use super::decoding::*;
use super::target_decryption_parsing::*;
use super::*;

// The same-secret bridge statement fields shared by the bridge-anchor family
// parser and the optional key-bearing anchor. Every commitment body is
// validated against its expected canonical root, and every parsed field enters
// the statement hash, so the anchor cannot be swapped after proving.
fn same_secret_bridge_fields_from_value(
    statement_value: &Value,
    ring_degree: usize,
) -> CanonicalResult<SameSecretBridgeStatement> {
    let source_trustee_identity =
        read_string(statement_value, "sourceTrusteeIdentity")?.to_string();
    let source_trustee_roster_position = read_u64(statement_value, "sourceTrusteeRosterPosition")?;
    let public_matrix_seed_hash = read_string(statement_value, "publicMatrixSeedHash")?.to_string();
    let target_basis_hash = read_string(statement_value, "targetBasisHash")?.to_string();
    let target_rns_primes = read_u64_array(statement_value, "targetRnsPrimes")?;
    let target_constant_commitment_roots =
        read_string_array(statement_value, "targetConstantCommitmentRoots")?;
    let target_constant_commitment_values = statement_value
        .get("targetConstantCommitments")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid_succinct_setup_proof(
                "sameSecretBridge.targetConstantCommitments must be an array",
            )
        })?;
    if target_constant_commitment_roots.len() != target_rns_primes.len()
        || target_constant_commitment_values.len() != target_rns_primes.len()
    {
        return Err(invalid_succinct_setup_proof(
            "sameSecretBridge target primes, roots, and commitments must be aligned",
        ));
    }
    let target_constant_commitments = target_constant_commitment_values
        .iter()
        .zip(target_constant_commitment_roots.iter())
        .zip(target_rns_primes.iter())
        .enumerate()
        .map(
            |(target_rns_limb_index, ((value, expected_commitment_root), target_rns_prime))| {
                vss_share_linkage_commitment_from_value(
                    value,
                    VssPublicCommandCommitmentExpectation {
                        field_name: format!("targetConstantCommitments.{target_rns_limb_index}"),
                        root: expected_commitment_root,
                        role: "coefficient",
                        public_matrix_seed_hash: &public_matrix_seed_hash,
                        rns_limb_index: target_rns_limb_index,
                        rns_prime: *target_rns_prime,
                        ring_degree,
                    },
                )
            },
        )
        .collect::<CanonicalResult<Vec<_>>>()?;
    Ok(SameSecretBridgeStatement {
        public_matrix_seed_hash,
        source_trustee_identity,
        source_trustee_roster_position,
        target_basis_hash,
        target_rns_primes,
        target_constant_commitment_roots,
        target_constant_commitments,
    })
}

// The optional same-secret bridge anchor on a key-bearing statement request:
// the anchor the atom schedule's linkage opens. Development statements may
// omit it; the schedule backend refuses to prove or verify without it.
fn optional_same_secret_bridge_from_statement_request(
    request: &Value,
    ring_degree: usize,
) -> CanonicalResult<Option<SameSecretBridgeStatement>> {
    match request.get("sameSecretBridge") {
        None | Some(Value::Null) => Ok(None),
        Some(statement_value) => Ok(Some(same_secret_bridge_fields_from_value(
            statement_value,
            ring_degree,
        )?)),
    }
}

pub(in crate::bgv::setup::trustee_evaluation_key_proof) fn statement_from_request(
    request: &Value,
) -> CanonicalResult<TrusteeEvaluationKeyStatement> {
    let context_value = request
        .get("context")
        .ok_or_else(|| invalid_succinct_setup_proof("context must be present"))?;
    let ring_degree = usize::try_from(read_u64(request, "ringDegree")?)
        .map_err(|_| invalid_succinct_setup_proof("ringDegree does not fit usize"))?;
    let key_values = request
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_succinct_setup_proof("keys must be an array"))?;
    let keys = key_values
        .iter()
        .map(key_descriptor_from_value)
        .collect::<CanonicalResult<Vec<_>>>()?;
    // The key kinds decide the family, and the family decides which labeled
    // binding roots the context must carry.
    let shape = SuccinctSetupProofFamilyShape::from_key_kinds(
        &keys.iter().map(|key| key.kind).collect::<Vec<_>>(),
    )?;
    let context = proof_context_from_value(context_value, shape)?;
    let same_secret_linkage = match request.get("sameSecretLinkage") {
        None | Some(Value::Null) => None,
        Some(linkage_value) => {
            let commitment_values = linkage_value
                .get("commitments")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    invalid_succinct_setup_proof("sameSecretLinkage.commitments must be an array")
                })?;
            let commitments = commitment_values
                .iter()
                .map(parse_setup_commitment_full_value)
                .collect::<CanonicalResult<Vec<_>>>()?;
            Some(SameSecretLinkageStatement {
                public_matrix_seed_hash: read_string(linkage_value, "publicMatrixSeedHash")?
                    .to_string(),
                commitments,
            })
        }
    };
    let same_secret_bridge =
        optional_same_secret_bridge_from_statement_request(request, ring_degree)?;
    let statement = TrusteeEvaluationKeyStatement {
        context,
        ring_degree,
        keys,
        same_secret_linkage,
        private_vss_share: None,
        vss_share_linkage: None,
        same_secret_bridge,
        target_decryption_share: None,
    };
    statement.validate_shape()?;

    Ok(statement)
}

pub(super) fn proof_context_from_value(
    context_value: &Value,
    shape: SuccinctSetupProofFamilyShape,
) -> CanonicalResult<SuccinctSetupProofContext> {
    Ok(SuccinctSetupProofContext {
        proof_family: shape.proof_family().to_string(),
        ceremony_id: read_string(context_value, "ceremonyId")?.to_string(),
        manifest_hash: read_string(context_value, "manifestHash")?.to_string(),
        roster_hash: read_string(context_value, "rosterHash")?.to_string(),
        trustee_identity: read_string(context_value, "trusteeIdentity")?.to_string(),
        trustee_roster_position: read_u64(context_value, "trusteeRosterPosition")?,
        setup_epoch: read_string(context_value, "setupEpoch")?.to_string(),
        binding_roots: shape
            .binding_labels()
            .iter()
            .map(|label| {
                Ok((
                    (*label).to_string(),
                    read_string(context_value, label)?.to_string(),
                ))
            })
            .collect::<CanonicalResult<Vec<_>>>()?,
    })
}

pub(super) fn vss_share_linkage_statement_from_request(
    request: &Value,
) -> CanonicalResult<TrusteeEvaluationKeyStatement> {
    let context_value = request
        .get("context")
        .ok_or_else(|| invalid_succinct_setup_proof("context must be present"))?;
    let ring_degree = usize::try_from(read_u64(request, "ringDegree")?)
        .map_err(|_| invalid_succinct_setup_proof("ringDegree does not fit usize"))?;
    let statement_value = request
        .get("vssShareLinkage")
        .ok_or_else(|| invalid_succinct_setup_proof("vssShareLinkage must be present"))?;
    let context = proof_context_from_value(
        context_value,
        SuccinctSetupProofFamilyShape::VssShareLinkage,
    )?;
    let share_linkage_statement_root = read_string(statement_value, "shareLinkageStatementRoot")?;
    if context.binding_roots[0].1 != share_linkage_statement_root {
        return Err(invalid_succinct_setup_proof(
            "share-linkage context root must match the share-linkage statement root",
        ));
    }
    let public_matrix_seed_hash = read_string(statement_value, "publicMatrixSeedHash")?.to_string();
    let primary_item = vss_share_linkage_item_from_value(
        statement_value,
        "vssShareLinkage",
        &public_matrix_seed_hash,
        ring_degree,
    )?;
    let additional_linkage_items = match statement_value.get("additionalLinkageItems") {
        None => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .enumerate()
            .map(|(item_index, item_value)| {
                vss_share_linkage_item_from_value(
                    item_value,
                    &format!("vssShareLinkage.additionalLinkageItems.{item_index}"),
                    &public_matrix_seed_hash,
                    ring_degree,
                )
            })
            .collect::<CanonicalResult<Vec<_>>>()?,
        Some(_) => {
            return Err(invalid_succinct_setup_proof(
                "vssShareLinkage.additionalLinkageItems must be an array",
            ));
        }
    };

    let statement = TrusteeEvaluationKeyStatement {
        context,
        ring_degree,
        keys: Vec::new(),
        same_secret_linkage: None,
        private_vss_share: None,
        vss_share_linkage: Some(VssShareLinkageStatement {
            public_matrix_seed_hash,
            source_trustee_identity: primary_item.source_trustee_identity,
            source_trustee_roster_position: primary_item.source_trustee_roster_position,
            recipient_identity: primary_item.recipient_identity,
            recipient_roster_position: primary_item.recipient_roster_position,
            source_coefficient_commitment_root: primary_item.source_coefficient_commitment_root,
            source_recipient_share_commitment_root: primary_item
                .source_recipient_share_commitment_root,
            source_rns_limb_index: primary_item.source_rns_limb_index,
            source_message_modulus: primary_item.source_message_modulus,
            coefficient_commitment_roots: primary_item.coefficient_commitment_roots,
            coefficient_opening_roots: primary_item.coefficient_opening_roots,
            coefficient_commitments: primary_item.coefficient_commitments,
            recipient_share_commitment_root: primary_item.recipient_share_commitment_root,
            recipient_share_opening_root: primary_item.recipient_share_opening_root,
            recipient_share_commitment: primary_item.recipient_share_commitment,
            additional_linkage_items,
        }),
        same_secret_bridge: None,
        target_decryption_share: None,
    };
    statement.validate_shape()?;

    Ok(statement)
}

pub(super) fn vss_share_linkage_witness_from_request(
    request: &Value,
) -> CanonicalResult<TrusteeEvaluationKeyWitness> {
    Ok(TrusteeEvaluationKeyWitness {
        secret_coefficients: Vec::new(),
        error_coefficients_by_key: Vec::new(),
        negative_indicator_coefficients: Vec::new(),
        opening_randomness_by_limb: Vec::new(),
        private_vss_coefficient_messages_by_shamir_index: Vec::new(),
        private_vss_opening_randomness_by_shamir_index: Vec::new(),
        private_vss_carry_witnesses: Vec::new(),
        vss_public_coefficient_messages_by_shamir_index: read_i64_matrix2(
            request,
            "coefficientMessagesByShamirIndex",
        )?,
        vss_public_recipient_share_messages: read_i64_array(request, "recipientShareMessages")?,
        vss_public_coefficient_opening_randomness_by_shamir_index: read_i64_matrix(
            request,
            "coefficientOpeningRandomnessByShamirIndex",
        )?,
        vss_public_recipient_share_opening_randomness: read_i64_matrix2(
            request,
            "recipientShareOpeningRandomness",
        )?,
        vss_public_carry_witnesses: read_i64_array(request, "carryWitnesses")?,
        vss_public_recipient_share_messages_by_item: read_optional_i64_matrix2(
            request,
            "recipientShareMessagesByItem",
        )?,
        vss_public_recipient_share_opening_randomness_by_item: read_optional_i64_matrix(
            request,
            "recipientShareOpeningRandomnessByItem",
        )?,
        vss_public_carry_witnesses_by_item: read_optional_i64_matrix2(
            request,
            "carryWitnessesByItem",
        )?,
        target_decryption_message_vectors: Vec::new(),
        target_decryption_opening_randomness_by_commitment: Vec::new(),
    })
}

pub(super) fn same_secret_bridge_statement_from_request(
    request: &Value,
) -> CanonicalResult<TrusteeEvaluationKeyStatement> {
    let context_value = request
        .get("context")
        .ok_or_else(|| invalid_succinct_setup_proof("context must be present"))?;
    let ring_degree = usize::try_from(read_u64(request, "ringDegree")?)
        .map_err(|_| invalid_succinct_setup_proof("ringDegree does not fit usize"))?;
    let statement_value = request
        .get("sameSecretBridge")
        .ok_or_else(|| invalid_succinct_setup_proof("sameSecretBridge must be present"))?;
    let context = proof_context_from_value(
        context_value,
        SuccinctSetupProofFamilyShape::SameSecretBridge,
    )?;
    let same_secret_bridge_statement_root =
        read_string(statement_value, "sameSecretBridgeStatementRoot")?;
    let same_secret_statement_root = read_string(statement_value, "sameSecretStatementRoot")?;
    let same_secret_proof_root = read_string(statement_value, "sameSecretProofRoot")?;
    let same_secret_proof_family_binding_root =
        read_string(statement_value, "sameSecretProofFamilyBindingRoot")?;
    if context.binding_roots[0].1 != same_secret_bridge_statement_root
        || context.binding_roots[1].1 != same_secret_statement_root
        || context.binding_roots[2].1 != same_secret_proof_root
        || context.binding_roots[3].1 != same_secret_proof_family_binding_root
    {
        return Err(invalid_succinct_setup_proof(
            "same-secret bridge context roots must match the statement roots",
        ));
    }
    let source_trustee_identity =
        read_string(statement_value, "sourceTrusteeIdentity")?.to_string();
    let source_trustee_roster_position = read_u64(statement_value, "sourceTrusteeRosterPosition")?;
    if context.trustee_identity != source_trustee_identity
        || context.trustee_roster_position != source_trustee_roster_position
    {
        return Err(invalid_succinct_setup_proof(
            "same-secret bridge context trustee must match the source trustee",
        ));
    }
    let bridge_fields = same_secret_bridge_fields_from_value(statement_value, ring_degree)?;

    let statement = TrusteeEvaluationKeyStatement {
        context,
        ring_degree,
        keys: Vec::new(),
        same_secret_linkage: None,
        private_vss_share: None,
        vss_share_linkage: None,
        same_secret_bridge: Some(bridge_fields),
        target_decryption_share: None,
    };
    statement.validate_shape()?;

    Ok(statement)
}

pub(super) fn same_secret_bridge_witness_from_request(
    request: &Value,
) -> CanonicalResult<TrusteeEvaluationKeyWitness> {
    Ok(TrusteeEvaluationKeyWitness {
        secret_coefficients: read_i64_array(request, "secretCoefficients")?,
        error_coefficients_by_key: Vec::new(),
        negative_indicator_coefficients: read_i64_array(request, "negativeIndicatorCoefficients")?,
        opening_randomness_by_limb: read_i64_matrix(request, "openingRandomnessByLimb")?,
        private_vss_coefficient_messages_by_shamir_index: Vec::new(),
        private_vss_opening_randomness_by_shamir_index: Vec::new(),
        private_vss_carry_witnesses: Vec::new(),
        vss_public_coefficient_messages_by_shamir_index: Vec::new(),
        vss_public_recipient_share_messages: Vec::new(),
        vss_public_coefficient_opening_randomness_by_shamir_index: Vec::new(),
        vss_public_recipient_share_opening_randomness: Vec::new(),
        vss_public_carry_witnesses: Vec::new(),
        vss_public_recipient_share_messages_by_item: Vec::new(),
        vss_public_recipient_share_opening_randomness_by_item: Vec::new(),
        vss_public_carry_witnesses_by_item: Vec::new(),
        target_decryption_message_vectors: Vec::new(),
        target_decryption_opening_randomness_by_commitment: Vec::new(),
    })
}

pub(super) fn vss_share_linkage_item_from_value(
    value: &Value,
    field_name: &str,
    public_matrix_seed_hash: &str,
    ring_degree: usize,
) -> CanonicalResult<VssShareLinkageItem> {
    if !value.is_object() {
        return Err(invalid_succinct_setup_proof(format!(
            "{field_name} must be an object"
        )));
    }
    let source_rns_limb_index =
        usize::try_from(read_u64(value, "sourceRnsLimbIndex")?).map_err(|_| {
            invalid_succinct_setup_proof(format!(
                "{field_name}.sourceRnsLimbIndex does not fit usize"
            ))
        })?;
    let source_message_modulus = read_u64(value, "sourceMessageModulus")?;
    let coefficient_commitment_roots = read_string_array(value, "coefficientCommitmentRoots")?;
    let coefficient_opening_roots = read_string_array(value, "coefficientOpeningRoots")?;
    let coefficient_commitment_values = value
        .get("coefficientCommitments")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid_succinct_setup_proof(format!(
                "{field_name}.coefficientCommitments must be an array"
            ))
        })?;
    if coefficient_commitment_values.len() != coefficient_commitment_roots.len() {
        return Err(invalid_succinct_setup_proof(format!(
            "{field_name} coefficient commitments and roots must be aligned"
        )));
    }
    if coefficient_commitment_values.len() != coefficient_opening_roots.len() {
        return Err(invalid_succinct_setup_proof(format!(
            "{field_name} coefficient commitments and opening roots must be aligned"
        )));
    }
    let coefficient_commitments = coefficient_commitment_values
        .iter()
        .zip(coefficient_commitment_roots.iter())
        .enumerate()
        .map(
            |(coefficient_index, (commitment_value, expected_commitment_root))| {
                vss_share_linkage_commitment_from_value(
                    commitment_value,
                    VssPublicCommandCommitmentExpectation {
                        field_name: format!(
                            "{field_name}.coefficientCommitments.{coefficient_index}"
                        ),
                        root: expected_commitment_root,
                        role: "coefficient",
                        public_matrix_seed_hash,
                        rns_limb_index: source_rns_limb_index,
                        rns_prime: source_message_modulus,
                        ring_degree,
                    },
                )
            },
        )
        .collect::<CanonicalResult<Vec<_>>>()?;
    let recipient_share_commitment_root =
        read_string(value, "recipientShareCommitmentRoot")?.to_string();
    let recipient_share_opening_root = read_string(value, "recipientShareOpeningRoot")?.to_string();
    let recipient_share_commitment = vss_share_linkage_commitment_from_value(
        value.get("recipientShareCommitment").ok_or_else(|| {
            invalid_succinct_setup_proof(format!(
                "{field_name}.recipientShareCommitment must be present"
            ))
        })?,
        VssPublicCommandCommitmentExpectation {
            field_name: format!("{field_name}.recipientShareCommitment"),
            root: &recipient_share_commitment_root,
            role: "recipient-share",
            public_matrix_seed_hash,
            rns_limb_index: source_rns_limb_index,
            rns_prime: source_message_modulus,
            ring_degree,
        },
    )?;

    Ok(VssShareLinkageItem {
        source_trustee_identity: read_string(value, "sourceTrusteeIdentity")?.to_string(),
        source_trustee_roster_position: read_u64(value, "sourceTrusteeRosterPosition")?,
        source_coefficient_commitment_root: read_string(value, "sourceCoefficientCommitmentRoot")?
            .to_string(),
        source_recipient_share_commitment_root: read_string(
            value,
            "sourceRecipientShareCommitmentRoot",
        )?
        .to_string(),
        recipient_identity: read_string(value, "recipientIdentity")?.to_string(),
        recipient_roster_position: read_u64(value, "recipientRosterPosition")?,
        source_rns_limb_index,
        source_message_modulus,
        coefficient_commitment_roots,
        coefficient_opening_roots,
        coefficient_commitments,
        recipient_share_commitment_root,
        recipient_share_opening_root,
        recipient_share_commitment,
    })
}
