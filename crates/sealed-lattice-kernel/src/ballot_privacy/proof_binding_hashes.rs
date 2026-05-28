use super::*;

pub(crate) fn derive_receiver_key_proof_encoding_profile_hash(
    proof_encoding: &Value,
) -> Option<String> {
    derive_hash(
        "ChallengeDomainHash",
        &json!({
            "proofEncoding": proof_encoding,
            "purpose": "receiver-key-linear-proof-encoding-profile-v1"
        }),
    )
}

pub(crate) fn derive_receiver_key_proof_parameter_set_hash(
    parameter_set: &Value,
) -> Option<String> {
    derive_hash(
        "ChallengeDomainHash",
        &json!({
            "parameterSet": parameter_set,
            "purpose": "receiver-key-linear-proof-parameter-set-v1"
        }),
    )
}

pub(crate) fn derive_receiver_key_public_randomness_hash(
    public_randomness_hex: &str,
) -> Option<String> {
    derive_hash(
        "ChallengeDomainHash",
        &json!({
            "publicRandomnessHex": public_randomness_hex,
            "purpose": "receiver-key-linear-proof-public-randomness-v1"
        }),
    )
}

pub(crate) fn derive_receiver_key_linear_statement_hash(
    linear_statement: &Value,
) -> Option<String> {
    let statement_payload = value_without_field(linear_statement, "statementHash")?;
    derive_hash(
        "ChallengeDomainHash",
        &json!({
            "payload": statement_payload,
            "purpose": "receiver-key-linear-proof-statement-v1"
        }),
    )
}

pub(crate) fn derive_ballot_proof_encoding_profile_hash(proof_encoding: &Value) -> Option<String> {
    derive_hash(
        "ChallengeDomainHash",
        &json!({
            "proofEncoding": proof_encoding,
            "purpose": "ballot-proof-linear-proof-encoding-profile-v1"
        }),
    )
}

pub(crate) fn derive_ballot_proof_parameter_set_hash(parameter_set: &Value) -> Option<String> {
    derive_hash(
        "ChallengeDomainHash",
        &json!({
            "parameterSet": parameter_set,
            "purpose": "ballot-proof-linear-proof-parameter-set-v1"
        }),
    )
}

pub(crate) fn derive_ballot_proof_public_randomness_hash(
    public_randomness_hex: &str,
) -> Option<String> {
    derive_hash(
        "ChallengeDomainHash",
        &json!({
            "publicRandomnessHex": public_randomness_hex,
            "purpose": "ballot-proof-linear-proof-public-randomness-v1"
        }),
    )
}

pub(crate) fn derive_ballot_proof_linear_statement_hash(
    linear_statement: &Value,
) -> Option<String> {
    let statement_payload = value_without_field(linear_statement, "statementHash")?;
    derive_hash(
        "ChallengeDomainHash",
        &json!({
            "payload": statement_payload,
            "purpose": "ballot-proof-linear-proof-statement-v1"
        }),
    )
}

pub(crate) fn derive_ballot_sparse_linear_statement_hash(
    sparse_statement: &Value,
) -> Option<String> {
    let statement_payload = value_without_field(sparse_statement, "statementHash")?;
    derive_hash(
        "ChallengeDomainHash",
        &json!({
            "payload": statement_payload,
            "purpose": "ballot-proof-sparse-linear-proof-statement-v1"
        }),
    )
}

pub(crate) fn derive_ballot_structured_receiver_encryption_statement_hash(
    structured_statement: &Value,
) -> Option<String> {
    let statement_payload = value_without_field(structured_statement, "statementHash")?;
    derive_hash(
        "ChallengeDomainHash",
        &json!({
            "payload": statement_payload,
            "purpose": "ballot-proof-structured-receiver-encryption-proof-statement-v1"
        }),
    )
}

pub(crate) fn derive_ballot_structured_share_commitment_statement_hash(
    structured_statement: &Value,
) -> Option<String> {
    let statement_payload = value_without_field(structured_statement, "statementHash")?;
    derive_hash(
        "ChallengeDomainHash",
        &json!({
            "payload": statement_payload,
            "purpose": "ballot-proof-structured-share-commitment-proof-statement-v1"
        }),
    )
}

pub(crate) fn derive_ballot_component_proof_statement_plan_hash(plan: &Value) -> Option<String> {
    let statement_payload = value_without_field(plan, "componentProofStatementHash")?;
    derive_hash(
        "ChallengeDomainHash",
        &json!({
            "payload": statement_payload,
            "purpose": "ballot-proof-component-proof-statement-plan-v1"
        }),
    )
}
