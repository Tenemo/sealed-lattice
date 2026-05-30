use super::*;

pub(in crate::ballot_privacy::aggregate_derivation_proof) fn collect_aggregate_proof_input_refusals(
    proof_input: &Value,
    component: Option<&Value>,
    proof_bytes_required: bool,
) -> Vec<Value> {
    let object_hash = component
        .and_then(|component_value| {
            string_field(component_value, "aggregateDerivationComponentHash")
        })
        .or_else(|| string_field(proof_input, "statementHash"));
    let mut refused_objects = Vec::new();
    if string_field(proof_input, "componentId") != Some(AGGREGATE_DERIVATION_COMPONENT_ID) {
        refused_objects.push(structural_refusal(
            "Aggregate derivation proof input must use aggregate-derivation-component.",
            object_hash,
        ));
    }
    if string_field(proof_input, "proofStatementFormat")
        != Some(AGGREGATE_DERIVATION_PROOF_STATEMENT_FORMAT)
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation proof input must use sparse-polynomial-matrix-linear-proof-v1.",
            object_hash,
        ));
    }
    if proof_bytes_required {
        match string_field(proof_input, "proofBytesHex") {
            Some(proof_bytes_hex)
                if !proof_bytes_hex.is_empty()
                    && proof_bytes_hex.len().is_multiple_of(2)
                    && proof_bytes_hex
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) => {}
            _ => refused_objects.push(structural_refusal(
                "Aggregate derivation proof bytes must be non-empty lowercase hexadecimal bytes.",
                object_hash,
            )),
        }
    }
    let Some(proof_statement) = proof_input.get("proofStatement") else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation proof input must include proofStatement.",
            object_hash,
        ));

        return refused_objects;
    };
    let Some(parameter_set) = proof_input.get("proofParameterSet") else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation proof input must include proofParameterSet.",
            object_hash,
        ));

        return refused_objects;
    };
    let Some(proof_encoding) = proof_input.get("proofEncoding") else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation proof input must include proofEncoding.",
            object_hash,
        ));

        return refused_objects;
    };
    // Statement-shape index math. share_vector_width = statementRows - module rank. The *3 covers
    // the three witness blocks (integer share, reduced field, quotient); + opening dimension gives
    // the column count. The short response uses the 256/64 source-to-proof ring-embedding ratio, +1.
    let statement_rows = usize_object_field(proof_statement, "statementRows");
    let statement_columns = usize_object_field(proof_statement, "statementColumns");
    let share_vector_width =
        statement_rows.and_then(|rows| rows.checked_sub(SHARE_COMMITMENT_MODULE_RANK));
    let expected_columns = share_vector_width.and_then(|width| {
        width
            .checked_mul(3)?
            .checked_add(SHARE_COMMITMENT_OPENING_DIMENSION)
    });
    let expected_short_response_length = statement_columns.and_then(|columns| {
        columns
            .checked_mul(
                AGGREGATE_DERIVATION_SOURCE_RING_DEGREE / AGGREGATE_DERIVATION_PROOF_RING_DEGREE,
            )?
            .checked_add(1)
    });

    if string_field(proof_statement, "componentId") != Some(AGGREGATE_DERIVATION_COMPONENT_ID)
        || string_field(proof_statement, "parameterProfileId")
            != Some(AGGREGATE_DERIVATION_PARAMETER_PROFILE_ID)
        || string_field(proof_statement, "proofStatementFormat")
            != Some(AGGREGATE_DERIVATION_PROOF_STATEMENT_FORMAT)
        || string_field(proof_statement, "projectionCoverage")
            != Some("aggregate-derivation-full-encoded-layout")
        || string_field(proof_statement, "matrixCoefficientRepresentation")
            != Some("centeredSignedSourceModulus")
        || string_field(proof_statement, "targetCoefficientRepresentation")
            != Some("centeredSignedSourceModulus")
        || string_field(proof_statement, "coefficientModulus")
            != Some(&SHARE_COMMITMENT_MODULUS.to_string())
        || usize_object_field(proof_statement, "sourceRingDegree")
            != Some(AGGREGATE_DERIVATION_SOURCE_RING_DEGREE)
        || statement_rows.is_none()
        || statement_columns.is_none()
        || expected_columns != statement_columns
        || u64_object_field(proof_statement, "witnessL2BoundSquared")
            != Some(AGGREGATE_DERIVATION_WITNESS_L2_BOUND_SQUARED as u64)
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation sparse proof statement shape is invalid.",
            object_hash,
        ));
    }
    let Some(share_vector_width) = share_vector_width else {
        return refused_objects;
    };
    if share_vector_width == 0
        || share_vector_width % (BALLOT_PRIVACY_ENCODED_COORDINATES_PER_OPTION as usize) != 0
        || share_vector_width
            > usize::try_from(BALLOT_PRIVACY_MAXIMUM_OPTION_COUNT)
                .ok()
                .and_then(|maximum_option_count| {
                    maximum_option_count
                        .checked_mul(BALLOT_PRIVACY_ENCODED_COORDINATES_PER_OPTION as usize)
                })
                .unwrap_or(0)
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation must use the full scalar-plus-one-hot encoded layout.",
            object_hash,
        ));
    }
    if string_field(parameter_set, "profileId") != Some(AGGREGATE_DERIVATION_PARAMETER_PROFILE_ID)
        || string_field(parameter_set, "coefficientModulus")
            != Some(&SHARE_COMMITMENT_MODULUS.to_string())
        || usize_object_field(parameter_set, "ringDegree")
            != Some(AGGREGATE_DERIVATION_SOURCE_RING_DEGREE)
        || usize_object_field(parameter_set, "proofSystemRingDegree")
            != Some(AGGREGATE_DERIVATION_PROOF_RING_DEGREE)
        || usize_object_field(parameter_set, "statementRows") != statement_rows
        || usize_object_field(parameter_set, "statementColumns") != statement_columns
        || u64_object_field(parameter_set, "witnessL2BoundSquared")
            != Some(AGGREGATE_DERIVATION_WITNESS_L2_BOUND_SQUARED as u64)
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation parameter set is not bound to the proof statement.",
            object_hash,
        ));
    }
    if string_field(proof_encoding, "profileId")
        != Some(AGGREGATE_DERIVATION_PROOF_ENCODING_PROFILE_ID)
        || u64_object_field(proof_encoding, "coefficientModulus")
            != Some(AGGREGATE_DERIVATION_PROOF_MODULUS)
        || usize_object_field(proof_encoding, "ringDegree")
            != Some(AGGREGATE_DERIVATION_PROOF_RING_DEGREE)
        || usize_object_field(proof_encoding, "shortResponseVectorLength")
            != expected_short_response_length
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation proof encoding is not bound to the proof statement.",
            object_hash,
        ));
    }
    if let Some(statement_hash) = string_field(proof_statement, "statementHash") {
        let expected_statement_hash =
            derive_aggregate_sparse_linear_statement_hash(proof_statement);
        if expected_statement_hash.as_deref() != Some(statement_hash) {
            refused_objects.push(structural_refusal(
                "Aggregate derivation proof statement hash does not match its canonical payload.",
                Some(statement_hash),
            ));
        }
        if string_field(proof_input, "componentProofStatementHash") != Some(statement_hash) {
            refused_objects.push(structural_refusal(
                "Aggregate derivation proof input is not bound to the proof statement hash.",
                Some(statement_hash),
            ));
        }
    } else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation proof statement is missing statementHash.",
            object_hash,
        ));
    }
    // Public randomness must equal the first 32 bytes (64 hex chars) of the statement's
    // challengeDomainHash, binding Fiat-Shamir randomness to the statement so the prover cannot
    // choose its own randomness.
    if let Some(component_value) = component
        && let Some(statement) = component_value.get("statement")
        && let Some(challenge_domain_hash) = string_field(statement, "challengeDomainHash")
        && challenge_domain_hash.len() >= 64
        && string_field(proof_input, "publicRandomnessHex") != Some(&challenge_domain_hash[..64])
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation public randomness must be verifier-derived from the statement challenge domain.",
            object_hash,
        ));
    }

    refused_objects
}

fn derive_aggregate_sparse_linear_statement_hash(proof_statement: &Value) -> Option<String> {
    let statement_payload = value_without_field(proof_statement, "statementHash")?;
    derive_hash(
        "ChallengeDomainHash",
        &json!({
            "payload": statement_payload,
            "purpose": "aggregate-derivation-sparse-linear-proof-statement-v1"
        }),
    )
}
