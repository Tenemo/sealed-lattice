use super::*;

pub(super) struct ThresholdLimbCommitment {
    pub(super) rns_limb_index: usize,
    pub(super) rns_prime: u64,
    pub(super) threshold_share_commitment_root: String,
    pub(super) coefficient_commitment_roots: Vec<String>,
    pub(super) commitment: SetupCommitmentValue,
}

pub(super) fn threshold_share_commitment_set(
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    ring_degree: usize,
    ring_degree_status: &str,
    roster: &AcceptedRosterParameters,
    source_trustee_bindings: &BTreeMap<u64, SourceTrusteeCommitmentBinding>,
    coefficient_commitments: &BTreeMap<(u64, usize, u64), CoefficientCommitmentBinding>,
) -> CanonicalResult<Value> {
    let mut recipient_records = Vec::with_capacity(roster.participant_count as usize);
    for recipient_roster_position in 0..roster.participant_count {
        let recipient_identity = recipient_identity_from_source_bindings(
            source_trustee_bindings,
            recipient_roster_position,
        )?;
        let recipient_record = threshold_share_recipient_record(
            setup_context,
            public_matrix_seed_hash,
            &recipient_identity,
            recipient_roster_position,
            ring_degree,
            ring_degree_status,
            roster,
            source_trustee_bindings,
            coefficient_commitments,
        )?;
        recipient_records.push(recipient_record);
    }

    let mut commitment_set = json!({
        "objectType": THRESHOLD_SHARE_COMMITMENT_SET_OBJECT_TYPE,
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "commitmentProfileId": SETUP_COMMITMENT_PROFILE_ID,
        "derivationRule": THRESHOLD_SHARE_DERIVATION_RULE,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "participantCount": roster.participant_count,
        "thresholdDegree": roster.decryption_threshold,
        "rnsLimbCount": DATA_PRIMES.len(),
        "ringDegree": ring_degree,
        "ringDegreeStatus": ring_degree_status,
        "recipientRecords": recipient_records,
    });
    copy_context_fields(&mut commitment_set, setup_context)?;
    let commitment_set_root =
        derive_protocol_hash("ThresholdShareCommitmentRoot", &commitment_set)?;
    commitment_set["thresholdShareCommitmentRoot"] = json!(commitment_set_root);

    Ok(commitment_set)
}

pub(super) fn recipient_identity_from_source_bindings(
    source_trustee_bindings: &BTreeMap<u64, SourceTrusteeCommitmentBinding>,
    roster_position: u64,
) -> CanonicalResult<String> {
    source_trustee_bindings
        .get(&roster_position)
        .map(|binding| binding.source_trustee_identity.clone())
        .ok_or_else(|| {
            invalid_threshold_commitment_input(
                "threshold derivation is missing a source trustee identity for a roster position",
            )
        })
}

#[allow(clippy::too_many_arguments)]
fn threshold_share_recipient_record(
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    recipient_identity: &str,
    recipient_roster_position: u64,
    ring_degree: usize,
    ring_degree_status: &str,
    roster: &AcceptedRosterParameters,
    source_trustee_bindings: &BTreeMap<u64, SourceTrusteeCommitmentBinding>,
    coefficient_commitments: &BTreeMap<(u64, usize, u64), CoefficientCommitmentBinding>,
) -> CanonicalResult<Value> {
    let recipient_roster_position_usize =
        usize::try_from(recipient_roster_position).map_err(|_| {
            invalid_threshold_commitment_input("recipient roster position does not fit usize")
        })?;
    let mut limb_commitments = Vec::with_capacity(DATA_PRIMES.len());
    for (rns_limb_index, rns_prime) in DATA_PRIMES.iter().copied().enumerate() {
        let threshold_limb = derive_threshold_limb_commitment(
            setup_context,
            public_matrix_seed_hash,
            recipient_identity,
            recipient_roster_position,
            recipient_roster_position_usize,
            rns_limb_index,
            rns_prime,
            roster,
            source_trustee_bindings,
            coefficient_commitments,
        )?;
        limb_commitments.push(threshold_limb_commitment_value(
            setup_context,
            public_matrix_seed_hash,
            recipient_identity,
            recipient_roster_position,
            recipient_roster_position_usize,
            roster.decryption_threshold as usize,
            ring_degree_status,
            &threshold_limb,
        )?);
    }
    let trustee_point = canonical_trustee_point(recipient_roster_position_usize, DATA_PRIMES[0])?;
    let mut recipient_record = json!({
        "objectType": THRESHOLD_SHARE_RECIPIENT_COMMITMENT_OBJECT_TYPE,
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "commitmentProfileId": SETUP_COMMITMENT_PROFILE_ID,
        "derivationRule": THRESHOLD_SHARE_DERIVATION_RULE,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "recipientIdentity": recipient_identity,
        "recipientRosterPosition": recipient_roster_position,
        "trusteePoint": trustee_point,
        "ringDegree": ring_degree,
        "ringDegreeStatus": ring_degree_status,
        "limbCommitments": limb_commitments,
    });
    copy_context_fields(&mut recipient_record, setup_context)?;
    let recipient_commitment_root =
        derive_protocol_hash("ThresholdShareCommitmentRoot", &recipient_record)?;
    recipient_record["recipientCommitmentRoot"] = json!(recipient_commitment_root);

    Ok(recipient_record)
}

#[allow(clippy::too_many_arguments)]
fn derive_threshold_limb_commitment(
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    recipient_identity: &str,
    recipient_roster_position: u64,
    recipient_roster_position_usize: usize,
    rns_limb_index: usize,
    rns_prime: u64,
    roster: &AcceptedRosterParameters,
    source_trustee_bindings: &BTreeMap<u64, SourceTrusteeCommitmentBinding>,
    coefficient_commitments: &BTreeMap<(u64, usize, u64), CoefficientCommitmentBinding>,
) -> CanonicalResult<ThresholdLimbCommitment> {
    let decryption_threshold = roster.decryption_threshold as usize;
    let trustee_point = canonical_trustee_point(recipient_roster_position_usize, rns_prime)?;
    let scalars = shamir_coefficient_scalars(trustee_point, decryption_threshold)?;
    let mut coefficient_commitment_roots =
        Vec::with_capacity(roster.participant_count as usize * decryption_threshold);
    let mut combination_terms =
        Vec::with_capacity(roster.participant_count as usize * decryption_threshold);
    for source_trustee_roster_position in 0..roster.participant_count {
        let _source_trustee_binding = source_trustee_bindings
            .get(&source_trustee_roster_position)
            .ok_or_else(|| {
                invalid_threshold_commitment_input(
                    "threshold derivation is missing an accepted source trustee binding",
                )
            })?;
        for shamir_coefficient_index in 0..roster.decryption_threshold {
            let coefficient_binding = coefficient_commitments
                .get(&(
                    source_trustee_roster_position,
                    rns_limb_index,
                    shamir_coefficient_index,
                ))
                .ok_or_else(|| {
                    invalid_threshold_commitment_input(
                        "threshold derivation is missing coefficient commitment material",
                    )
                })?;
            let scalar = scalars[shamir_coefficient_index as usize];
            coefficient_commitment_roots.push(coefficient_binding.commitment_root.clone());
            combination_terms.push((&coefficient_binding.commitment, scalar));
        }
    }

    let commitment = linear_combination_setup_commitments(&combination_terms)?;
    let threshold_limb = ThresholdLimbCommitment {
        rns_limb_index,
        rns_prime,
        threshold_share_commitment_root: String::new(),
        coefficient_commitment_roots,
        commitment,
    };
    let threshold_share_commitment_root = derive_protocol_hash(
        "ThresholdShareCommitmentRoot",
        &threshold_limb_commitment_root_payload(
            setup_context,
            public_matrix_seed_hash,
            recipient_identity,
            recipient_roster_position,
            recipient_roster_position_usize,
            decryption_threshold,
            &threshold_limb,
        )?,
    )?;

    Ok(ThresholdLimbCommitment {
        threshold_share_commitment_root,
        ..threshold_limb
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn threshold_limb_commitment_value(
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    recipient_identity: &str,
    recipient_roster_position: u64,
    recipient_roster_position_usize: usize,
    decryption_threshold: usize,
    ring_degree_status: &str,
    threshold_limb: &ThresholdLimbCommitment,
) -> CanonicalResult<Value> {
    let mut value = threshold_limb_commitment_root_payload(
        setup_context,
        public_matrix_seed_hash,
        recipient_identity,
        recipient_roster_position,
        recipient_roster_position_usize,
        decryption_threshold,
        threshold_limb,
    )?;
    value["ringDegreeStatus"] = json!(ring_degree_status);
    value["thresholdShareCommitmentRoot"] = json!(threshold_limb.threshold_share_commitment_root);

    Ok(value)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn threshold_limb_commitment_root_payload(
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    recipient_identity: &str,
    recipient_roster_position: u64,
    recipient_roster_position_usize: usize,
    decryption_threshold: usize,
    threshold_limb: &ThresholdLimbCommitment,
) -> CanonicalResult<Value> {
    let trustee_point =
        canonical_trustee_point(recipient_roster_position_usize, threshold_limb.rns_prime)?;
    let mut payload = json!({
        "objectType": THRESHOLD_SHARE_LIMB_COMMITMENT_OBJECT_TYPE,
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "commitmentProfileId": SETUP_COMMITMENT_PROFILE_ID,
        "derivationRule": THRESHOLD_SHARE_DERIVATION_RULE,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "recipientIdentity": recipient_identity,
        "recipientRosterPosition": recipient_roster_position,
        "trusteePoint": trustee_point,
        "rnsLimbIndex": threshold_limb.rns_limb_index,
        "rnsPrime": threshold_limb.rns_prime,
        "ringDegree": threshold_limb.commitment.ring_degree,
        "ringDegreeStatus": if threshold_limb.commitment.ring_degree == POLYNOMIAL_DEGREE {
            "profile-ring"
        } else {
            "development-reduced-ring"
        },
        "shamirCoefficientScalarsDecimal": shamir_coefficient_scalars(
            trustee_point,
            decryption_threshold,
        )?
        .iter()
        .map(u128::to_string)
        .collect::<Vec<_>>(),
        "coefficientCommitmentRoots": threshold_limb.coefficient_commitment_roots,
        "commitmentLimbs": commitment_limb_hash_values(&threshold_limb.commitment),
    });
    copy_context_fields(&mut payload, setup_context)?;

    Ok(payload)
}

fn commitment_limb_hash_values(commitment: &SetupCommitmentValue) -> Vec<Value> {
    commitment
        .limbs
        .iter()
        .map(|limb| {
            json!({
                "commitmentModulusIndex": limb.commitment_modulus_index,
                "modulus": limb.modulus,
                "rowCoefficientHash512": limb.rows.iter().map(|row| {
                    coefficient_vector_hash512(
                        row,
                        "sealed-lattice-threshold-share-commitment/row-coefficients-v1",
                    )
                }).collect::<Vec<_>>(),
            })
        })
        .collect()
}

pub(super) fn shamir_coefficient_scalars(
    trustee_point: u64,
    coefficient_count: usize,
) -> CanonicalResult<Vec<u128>> {
    let mut scalars = Vec::with_capacity(coefficient_count);
    let mut scalar = 1_u128;
    let trustee_point_wide = u128::from(trustee_point);
    for coefficient_index in 0..coefficient_count {
        scalars.push(scalar);
        if coefficient_index + 1 < coefficient_count {
            scalar = scalar.checked_mul(trustee_point_wide).ok_or_else(|| {
                invalid_threshold_commitment_input("trustee point scalar power overflow")
            })?;
        }
    }

    Ok(scalars)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn transported_vss_material_set_value(
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    ring_degree: usize,
    ring_degree_status: &str,
    roster: &AcceptedRosterParameters,
    material_record_count: usize,
    vss_coefficient_commitment_root: &str,
    hashes: &SetupVssMaterialTransportHashes,
) -> CanonicalResult<Value> {
    validate_hash_string(
        vss_coefficient_commitment_root,
        "vssCoefficientCommitmentRoot",
    )?;
    let mut material_set = json!({
        "objectType": "VssCoefficientCommitmentMaterialSet",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "commitmentProfileId": SETUP_COMMITMENT_PROFILE_ID,
        "commitmentProfileHash": setup_commitment_profile_hash()?,
        "materialEncoding": "binary-chunked-full-public-setup-commitment-values",
        "binaryFormat": VSS_MATERIAL_BINARY_FORMAT,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "vssCoefficientCommitmentRoot": vss_coefficient_commitment_root,
        "participantCount": roster.participant_count,
        "thresholdDegree": roster.decryption_threshold,
        "rnsLimbCount": DATA_PRIMES.len(),
        "ringDegree": ring_degree,
        "ringDegreeStatus": ring_degree_status,
        "materialRecordCount": material_record_count,
        "transport": {
            "transportProfileId": SETUP_TRANSPORT_PROFILE_ID,
            "chunkSizeBytes": SETUP_TRANSPORT_CHUNK_SIZE_BYTES,
            "chunkCount": hashes.chunk_hashes.len(),
            "totalByteLength": hashes.total_byte_length,
            "fullObjectHash": hashes.full_object_hash,
            "chunkRoot": hashes.chunk_root,
        },
    });
    copy_context_fields(&mut material_set, setup_context)?;
    let material_root =
        derive_protocol_hash("VssCoefficientCommitmentMaterialRoot", &material_set)?;
    material_set["vssCoefficientCommitmentMaterialRoot"] = json!(material_root);

    Ok(material_set)
}
