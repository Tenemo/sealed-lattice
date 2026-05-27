use super::backend_helpers::{
    is_protocol_digest as receiver_key_is_protocol_digest,
    value_without_field as receiver_key_value_without_field,
};
use super::public_matrix_derivation::{
    derive_receiver_public_matrix, identity_polynomial, validate_key_material_digest_from_target,
};
use super::*;
use serde_json::{Map, Value, json};

use crate::ballot_privacy::protocol_constants::{
    RECEIVER_ENCRYPTION_MODULE_DEGREE, RECEIVER_ENCRYPTION_MODULE_RANK, RECEIVER_ENCRYPTION_MODULUS,
};
use crate::hashing::derive_protocol_digest;

pub(super) const BACKEND_STATEMENT_FORMAT: &str = "SparseSignedIntegerBackendStatement-v1";
pub(super) const RECEIVER_KEY_STATEMENT_DIGEST_PURPOSE: &str = "receiver-key-backend-statement-v1";
pub(super) const RECEIVER_KEY_MATRIX_DIGEST_PURPOSE: &str = "receiver-key-backend-matrix-v1";
pub(super) const RECEIVER_KEY_TARGET_VECTOR_DIGEST_PURPOSE: &str =
    "receiver-key-backend-target-vector-v1";
pub(super) const RECEIVER_KEY_BOUNDS_DIGEST_PURPOSE: &str = "receiver-key-backend-bounds-v1";
pub(super) const RECEIVER_KEY_DIGEST_EXPANDED_MATRIX_DIGEST_PURPOSE: &str =
    "receiver-key-backend-digest-expanded-matrix-v1";
pub(super) const RECEIVER_KEY_DIGEST_EXPANDED_TARGET_VECTOR_DIGEST_PURPOSE: &str =
    "receiver-key-backend-digest-expanded-target-vector-v1";
pub(super) const RECEIVER_KEY_PUBLIC_CONTEXT_DIGEST_PURPOSE: &str =
    "receiver-key-backend-public-context-v1";
pub(super) const RECEIVER_KEY_LINEAR_STATEMENT_PROFILE_ID: &str =
    "receiver-key-linear-module-lwe-statement-v1";
pub(super) const RECEIVER_KEY_LINEAR_STATEMENT_DIGEST_PURPOSE: &str =
    "receiver-key-linear-proof-statement-v1";
pub(super) const RECEIVER_KEY_LINEAR_STATEMENT_MATRIX_DIGEST_PURPOSE: &str =
    "receiver-key-linear-proof-statement-matrix-v1";
pub(super) const RECEIVER_KEY_LINEAR_TARGET_VECTOR_DIGEST_PURPOSE: &str =
    "receiver-key-linear-proof-target-vector-v1";
pub(super) const RECEIVER_KEY_LINEAR_RELATION: &str = "A*w + t = 0";
pub(super) const RECEIVER_KEY_LINEAR_SOURCE_RING: &str = "Z_q[X]/(X^256 + 1)";
pub(super) const RECEIVER_KEY_LINEAR_PROOF_ROOT_KIND: &str =
    "ReceiverKeyRelationLinearStatementAndBackendStatement";
pub(super) const RECEIVER_KEY_EQUATION_COEFFICIENT_EXPANSION_DOMAIN: &str =
    "sealed.vote/internal/receiver-key-proof/receiver-key-equation/coefficient-expansion-v1";
pub(super) const RECEIVER_KEY_EQUATION_TARGET_EXPANSION_DOMAIN: &str =
    "sealed.vote/internal/receiver-key-proof/receiver-key-equation/target-expansion-v1";
pub(super) const RECEIVER_ENCRYPTION_SHORT_VECTOR_INFINITY_NORM_BOUND: u64 = 2;
pub(super) const RECEIVER_KEY_LINEAR_STATEMENT_ROW_COUNT: u64 = RECEIVER_ENCRYPTION_MODULE_RANK;
pub(super) const RECEIVER_KEY_LINEAR_STATEMENT_COLUMN_COUNT: u64 =
    RECEIVER_ENCRYPTION_MODULE_RANK * 2;
pub(super) const RECEIVER_KEY_LINEAR_WITNESS_L2_BOUND_SQUARED: u64 =
    RECEIVER_KEY_LINEAR_STATEMENT_COLUMN_COUNT
        * RECEIVER_ENCRYPTION_MODULE_DEGREE
        * RECEIVER_ENCRYPTION_SHORT_VECTOR_INFINITY_NORM_BOUND
        * RECEIVER_ENCRYPTION_SHORT_VECTOR_INFINITY_NORM_BOUND;
pub(super) const RECEIVER_KEY_EQUATION_ROW_COUNT: u64 =
    RECEIVER_ENCRYPTION_MODULE_RANK * RECEIVER_ENCRYPTION_MODULE_DEGREE;
pub(super) const RECEIVER_KEY_WITNESS_COLUMN_COUNT: u64 = RECEIVER_KEY_EQUATION_ROW_COUNT * 2;

pub fn verify_receiver_key_vector_case_value(vector_case: &Value) -> Value {
    let validation_result = validate_receiver_key_vector_case(vector_case);

    match validation_result {
        Ok(summary) => json!({
            "ok": true,
            "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
            "backendStatus": describe_proof_backend(),
            "caseName": summary.case_name,
            "vectorAvailable": true,
            "expectedOutcome": summary.expected_outcome,
            "statusLabels": summary.status_labels,
            "acceptedDigests": summary.accepted_digests,
            "refusedObjects": [],
            "unresolvedReason": Value::Null
        }),
        Err(message) => json!({
            "ok": false,
            "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
            "backendStatus": describe_proof_backend(),
            "statusLabels": [],
            "acceptedDigests": [],
            "refusedObjects": [
                {
                    "code": "InvalidFixture",
                    "message": message
                }
            ],
            "unresolvedReason": "InvalidFixture"
        }),
    }
}

pub(super) struct ReceiverKeyVectorSummary {
    accepted_digests: Vec<String>,
    case_name: String,
    expected_outcome: String,
    status_labels: Vec<&'static str>,
}

pub(super) struct ReceiverKeyAcceptedDigests {
    pub(super) backend_statement_digest: String,
    pub(super) linear_statement_digest: String,
}

pub(super) fn validate_receiver_key_vector_case(
    vector_case: &Value,
) -> Result<ReceiverKeyVectorSummary, String> {
    reject_forbidden_witness_keys(vector_case)?;
    let case_object = object_field(vector_case, "vectorCase")?;
    let case_name = string_property(case_object, "caseName")?;
    let expected_outcome = string_property(case_object, "expectedOutcome")?;
    let proof_construction_accepted = bool_property(case_object, "proofConstructionAccepted")?;

    if case_name.is_empty() {
        return Err("receiver-key vector caseName must not be empty".to_string());
    }
    if !matches!(expected_outcome.as_str(), "accept" | "reject") {
        return Err("receiver-key expectedOutcome must be accept or reject".to_string());
    }

    if proof_construction_accepted && expected_outcome == "accept" {
        let accepted_digests = validate_accepting_case(case_object)?;
        validate_digest_change_trace(case_object, &accepted_digests)?;

        Ok(ReceiverKeyVectorSummary {
            accepted_digests: vec![
                accepted_digests.backend_statement_digest,
                accepted_digests.linear_statement_digest,
            ],
            case_name,
            expected_outcome,
            status_labels: vec![
                "ReceiverKeyPublicShellParsed",
                "ReceiverKeyBackendStatementChecked",
                "ReceiverKeyLinearStatementChecked",
                "ReceiverKeyProofRootRecomputed",
            ],
        })
    } else if proof_construction_accepted {
        validate_preflight_rejecting_case(case_object)?;

        Ok(ReceiverKeyVectorSummary {
            accepted_digests: Vec::new(),
            case_name,
            expected_outcome,
            status_labels: vec![
                "ReceiverKeyConstructionAccepted",
                "ReceiverKeyRejectVectorChecked",
            ],
        })
    } else {
        validate_construction_rejecting_case(case_object, &expected_outcome)?;

        Ok(ReceiverKeyVectorSummary {
            accepted_digests: Vec::new(),
            case_name,
            expected_outcome,
            status_labels: vec![
                "ReceiverKeyConstructionRefusalRecorded",
                "ReceiverKeyRejectVectorChecked",
            ],
        })
    }
}

pub(super) fn validate_accepting_case(
    case_object: &Map<String, Value>,
) -> Result<ReceiverKeyAcceptedDigests, String> {
    let receiver_public_key = object_property(case_object, "receiverPublicKey")?;
    let receiver_key_proof = object_property(case_object, "receiverKeyProof")?;
    let backend_statement = object_property(case_object, "backendStatement")?;
    let linear_statement = object_property(case_object, "linearStatement")?;
    validate_receiver_public_key(receiver_public_key)?;
    let backend_statement_digest = validate_backend_statement(backend_statement)?;
    let linear_statement_digest =
        validate_linear_statement(receiver_public_key, backend_statement, linear_statement)?;
    validate_proof_shell(
        receiver_public_key,
        receiver_key_proof,
        backend_statement,
        linear_statement,
    )?;

    Ok(ReceiverKeyAcceptedDigests {
        backend_statement_digest,
        linear_statement_digest,
    })
}

pub(super) fn validate_preflight_rejecting_case(
    case_object: &Map<String, Value>,
) -> Result<(), String> {
    let trace = object_property(case_object, "trace")?;
    let rejection_layer = string_property(trace, "expectedLogicalRejectionLayer")?;
    if !matches!(
        rejection_layer.as_str(),
        "backend-statement-preflight" | "linear-statement-preflight" | "receiver-key-proof-shell"
    ) {
        return Err(
            "receiver-key proof-construction accepted reject vector must name a preflight layer"
                .to_string(),
        );
    }
    if let Ok(unexpected_digests) = validate_accepting_case(case_object) {
        return Err(format!(
            "receiver-key reject vector unexpectedly validated with digests {} and {}",
            unexpected_digests.backend_statement_digest, unexpected_digests.linear_statement_digest,
        ));
    }

    Ok(())
}

pub(super) fn validate_construction_rejecting_case(
    case_object: &Map<String, Value>,
    expected_outcome: &str,
) -> Result<(), String> {
    if expected_outcome != "reject" {
        return Err(
            "receiver-key construction-refusal vectors must declare expectedOutcome reject"
                .to_string(),
        );
    }
    if case_object.contains_key("backendStatement")
        || case_object.contains_key("linearStatement")
        || case_object.contains_key("receiverKeyProof")
        || case_object.contains_key("receiverPublicKey")
    {
        return Err(
            "receiver-key construction-refusal vectors must not include public proof objects"
                .to_string(),
        );
    }
    let refusal_messages = array_property(case_object, "refusalMessages")?;
    if refusal_messages.is_empty() || !refusal_messages.iter().all(Value::is_string) {
        return Err("receiver-key construction-refusal vectors must record messages".to_string());
    }
    let trace = object_property(case_object, "trace")?;
    if string_property(trace, "expectedLogicalRejectionLayer")? != "receiver-key-proof-construction"
    {
        return Err(
            "receiver-key construction-refusal vector must name the construction layer".to_string(),
        );
    }

    Ok(())
}

pub(super) fn validate_receiver_public_key(
    receiver_public_key: &Map<String, Value>,
) -> Result<(), String> {
    if string_property(receiver_public_key, "objectType")? != "ReceiverEncryptionPublicKey"
        || u64_property(receiver_public_key, "objectVersion")? != 1
        || string_property(receiver_public_key, "receiverIdentity")?.is_empty()
        || u64_property(receiver_public_key, "receiverRosterPosition")? == 0
        || !receiver_key_is_protocol_digest(&string_property(
            receiver_public_key,
            "manifestDigest",
        )?)
        || !receiver_key_is_protocol_digest(&string_property(receiver_public_key, "rosterDigest")?)
        || !receiver_key_is_protocol_digest(&string_property(
            receiver_public_key,
            "receiverEncryptionProfileDigest",
        )?)
        || !receiver_key_is_protocol_digest(&string_property(
            receiver_public_key,
            "keyMaterialDigest",
        )?)
    {
        return Err("receiver-key public key has an invalid canonical shape".to_string());
    }
    let public_key_payload = receiver_key_value_without_field(
        &Value::Object(receiver_public_key.clone()),
        "receiverPublicKeyDigest",
    )?;
    let expected_digest =
        derive_protocol_digest("PublicKeyDigest", &public_key_payload).map_err(|error| {
            format!("receiver-key public key digest could not be recomputed: {error}")
        })?;
    if string_property(receiver_public_key, "receiverPublicKeyDigest")? != expected_digest {
        return Err("receiver-key public key digest does not match its payload".to_string());
    }

    Ok(())
}

pub(super) fn validate_proof_shell(
    receiver_public_key: &Map<String, Value>,
    receiver_key_proof: &Map<String, Value>,
    backend_statement: &Map<String, Value>,
    linear_statement: &Map<String, Value>,
) -> Result<(), String> {
    if string_property(receiver_key_proof, "objectType")? != "ReceiverKeyProof"
        || u64_property(receiver_key_proof, "objectVersion")? != 1
        || string_property(receiver_key_proof, "proofBackend")? != "LocalLinearLatticeRelation"
        || !receiver_key_is_protocol_digest(&string_property(receiver_key_proof, "proofRoot")?)
    {
        return Err("receiver-key proof shell has an invalid canonical shape".to_string());
    }
    for field_name in [
        "ceremonyId",
        "manifestDigest",
        "rosterDigest",
        "receiverIdentity",
        "receiverEncryptionProfileDigest",
        "receiverPublicKeyDigest",
    ] {
        if string_property(receiver_key_proof, field_name)?
            != string_property(receiver_public_key, field_name)?
            || string_property(receiver_key_proof, field_name)?
                != string_property(backend_statement, field_name)?
            || string_property(receiver_key_proof, field_name)?
                != string_property(linear_statement, field_name)?
        {
            return Err(
                "receiver-key proof shell is not bound to the public key context".to_string(),
            );
        }
    }
    if u64_property(receiver_key_proof, "receiverRosterPosition")?
        != u64_property(receiver_public_key, "receiverRosterPosition")?
        || u64_property(receiver_key_proof, "receiverRosterPosition")?
            != u64_property(backend_statement, "receiverRosterPosition")?
        || u64_property(receiver_key_proof, "receiverRosterPosition")?
            != u64_property(linear_statement, "receiverRosterPosition")?
        || u64_property(receiver_key_proof, "recoveryEpoch")?
            != u64_property(receiver_public_key, "recoveryEpoch")?
        || u64_property(receiver_key_proof, "recoveryEpoch")?
            != u64_property(backend_statement, "recoveryEpoch")?
        || u64_property(receiver_key_proof, "recoveryEpoch")?
            != u64_property(linear_statement, "recoveryEpoch")?
    {
        return Err("receiver-key proof shell is not bound to the receiver index".to_string());
    }

    let expected_proof_root =
        expected_receiver_key_proof_root(backend_statement, linear_statement)?;
    if string_property(receiver_key_proof, "proofRoot")? != expected_proof_root {
        return Err("receiver-key proof root does not match the backend statement".to_string());
    }
    let proof_shell_payload = receiver_key_value_without_field(
        &Value::Object(receiver_key_proof.clone()),
        "receiverKeyProofRoot",
    )?;
    let expected_shell_root = derive_protocol_digest("ReceiverKeyProofRoot", &proof_shell_payload)
        .map_err(|error| {
            format!("receiver-key proof shell root could not be recomputed: {error}")
        })?;
    if string_property(receiver_key_proof, "receiverKeyProofRoot")? != expected_shell_root {
        return Err("receiver-key proof shell root does not match its payload".to_string());
    }

    Ok(())
}

pub(super) fn expected_receiver_key_proof_root(
    backend_statement: &Map<String, Value>,
    linear_statement: &Map<String, Value>,
) -> Result<String, String> {
    derive_protocol_digest(
        "ReceiverKeyProofRoot",
        &json!({
            "backendStatementDigest": string_property(backend_statement, "backendStatementDigest")?,
            "coefficientModulus": RECEIVER_ENCRYPTION_MODULUS,
            "errorInfinityNormBound": RECEIVER_ENCRYPTION_SHORT_VECTOR_INFINITY_NORM_BOUND,
            "keyMaterialDigest": string_property(backend_statement, "keyMaterialDigest")?,
            "linearStatementDigest": string_property(linear_statement, "statementDigest")?,
            "moduleDegree": RECEIVER_ENCRYPTION_MODULE_DEGREE,
            "moduleRank": RECEIVER_ENCRYPTION_MODULE_RANK,
            "proofRelation": "receiver_public_key_vector = public_matrix * secret_vector + error_vector mod q_receiver",
            "proofRootKind": RECEIVER_KEY_LINEAR_PROOF_ROOT_KIND,
            "publicMatrixSeedDigest": string_property(backend_statement, "publicMatrixSeedDigest")?,
            "receiverEncryptionProfileDigest": string_property(backend_statement, "receiverEncryptionProfileDigest")?,
            "receiverPublicKeyDigest": string_property(backend_statement, "receiverPublicKeyDigest")?,
            "secretInfinityNormBound": RECEIVER_ENCRYPTION_SHORT_VECTOR_INFINITY_NORM_BOUND,
        }),
    )
    .map_err(|error| format!("receiver-key proof root could not be recomputed: {error}"))
}

pub(super) fn validate_linear_statement(
    receiver_public_key: &Map<String, Value>,
    backend_statement: &Map<String, Value>,
    linear_statement: &Map<String, Value>,
) -> Result<String, String> {
    if string_property(linear_statement, "objectType")? != "ReceiverKeyLinearProofStatement"
        || u64_property(linear_statement, "objectVersion")? != 1
        || string_property(linear_statement, "statementProfileId")?
            != RECEIVER_KEY_LINEAR_STATEMENT_PROFILE_ID
        || string_property(linear_statement, "relation")? != RECEIVER_KEY_LINEAR_RELATION
        || string_property(linear_statement, "sourceRing")? != RECEIVER_KEY_LINEAR_SOURCE_RING
        || string_property(linear_statement, "coefficientModulus")?
            != RECEIVER_ENCRYPTION_MODULUS.to_string()
        || u64_property(linear_statement, "ringDegree")? != RECEIVER_ENCRYPTION_MODULE_DEGREE
        || u64_property(linear_statement, "statementRows")?
            != RECEIVER_KEY_LINEAR_STATEMENT_ROW_COUNT
        || u64_property(linear_statement, "statementColumns")?
            != RECEIVER_KEY_LINEAR_STATEMENT_COLUMN_COUNT
        || u64_property(linear_statement, "witnessInfinityNormBound")?
            != RECEIVER_ENCRYPTION_SHORT_VECTOR_INFINITY_NORM_BOUND
        || string_property(linear_statement, "witnessL2BoundSquared")?
            != RECEIVER_KEY_LINEAR_WITNESS_L2_BOUND_SQUARED.to_string()
    {
        return Err("receiver-key linear statement has an invalid canonical shape".to_string());
    }
    validate_decimal_string(&string_property(linear_statement, "coefficientModulus")?)?;
    validate_decimal_string(&string_property(linear_statement, "witnessL2BoundSquared")?)?;

    for field_name in [
        "ceremonyId",
        "manifestDigest",
        "rosterDigest",
        "receiverIdentity",
        "receiverEncryptionProfileDigest",
        "receiverPublicKeyDigest",
        "keyMaterialDigest",
    ] {
        if string_property(linear_statement, field_name)?
            != string_property(receiver_public_key, field_name)?
            || string_property(linear_statement, field_name)?
                != string_property(backend_statement, field_name)?
        {
            return Err(
                "receiver-key linear statement is not bound to the receiver key context"
                    .to_string(),
            );
        }
    }
    if string_property(linear_statement, "publicMatrixSeedDigest")?
        != string_property(backend_statement, "publicMatrixSeedDigest")?
    {
        return Err(
            "receiver-key linear statement is not bound to the backend matrix seed".to_string(),
        );
    }
    for digest_field_name in [
        "manifestDigest",
        "rosterDigest",
        "receiverEncryptionProfileDigest",
        "receiverPublicKeyDigest",
        "keyMaterialDigest",
        "publicMatrixSeedDigest",
        "statementMatrixDigest",
        "targetVectorDigest",
        "statementDigest",
    ] {
        if !receiver_key_is_protocol_digest(&string_property(linear_statement, digest_field_name)?)
        {
            return Err(format!(
                "receiver-key linear statement field {digest_field_name} is not a protocol digest"
            ));
        }
    }
    if u64_property(linear_statement, "receiverRosterPosition")?
        != u64_property(receiver_public_key, "receiverRosterPosition")?
        || u64_property(linear_statement, "receiverRosterPosition")?
            != u64_property(backend_statement, "receiverRosterPosition")?
        || u64_property(linear_statement, "recoveryEpoch")?
            != u64_property(receiver_public_key, "recoveryEpoch")?
        || u64_property(linear_statement, "recoveryEpoch")?
            != u64_property(backend_statement, "recoveryEpoch")?
    {
        return Err("receiver-key linear statement receiver index is not canonical".to_string());
    }

    validate_witness_vector_layout(linear_statement)?;
    let statement_matrix_values = array_property(linear_statement, "statementMatrixCoefficients")?;
    let statement_matrix = validate_statement_matrix(statement_matrix_values)?;
    let target_vector_values = array_property(linear_statement, "targetVectorCoefficients")?;
    let target_vector = validate_target_vector(target_vector_values)?;
    validate_canonical_linear_matrix(linear_statement, &statement_matrix)?;
    validate_key_material_digest_from_target(linear_statement, &target_vector)?;

    let statement_matrix_digest = derive_receiver_key_backend_digest(
        RECEIVER_KEY_LINEAR_STATEMENT_MATRIX_DIGEST_PURPOSE,
        &Value::Array(statement_matrix_values.clone()),
    )?;
    if string_property(linear_statement, "statementMatrixDigest")? != statement_matrix_digest {
        return Err("receiver-key linear matrix digest does not match coefficients".to_string());
    }
    let target_vector_digest = derive_receiver_key_backend_digest(
        RECEIVER_KEY_LINEAR_TARGET_VECTOR_DIGEST_PURPOSE,
        &Value::Array(target_vector_values.clone()),
    )?;
    if string_property(linear_statement, "targetVectorDigest")? != target_vector_digest {
        return Err("receiver-key linear target digest does not match coefficients".to_string());
    }

    let statement_payload = receiver_key_value_without_field(
        &Value::Object(linear_statement.clone()),
        "statementDigest",
    )?;
    let statement_digest = derive_receiver_key_backend_digest(
        RECEIVER_KEY_LINEAR_STATEMENT_DIGEST_PURPOSE,
        &statement_payload,
    )?;
    if string_property(linear_statement, "statementDigest")? != statement_digest {
        return Err(
            "receiver-key linear statement digest does not match its canonical payload".to_string(),
        );
    }

    Ok(statement_digest)
}

pub(super) fn validate_backend_statement(
    backend_statement: &Map<String, Value>,
) -> Result<String, String> {
    if string_property(backend_statement, "objectType")? != "ReceiverKeyProofBackendStatement"
        || u64_property(backend_statement, "objectVersion")? != 1
        || string_property(backend_statement, "backendStatementFormat")? != BACKEND_STATEMENT_FORMAT
        || string_property(backend_statement, "relationLabel")?
            != "ReceiverKeyWellFormednessRelation"
        || string_property(backend_statement, "coefficientModulus")?
            != RECEIVER_ENCRYPTION_MODULUS.to_string()
        || u64_property(backend_statement, "moduleRank")? != RECEIVER_ENCRYPTION_MODULE_RANK
        || u64_property(backend_statement, "moduleDegree")? != RECEIVER_ENCRYPTION_MODULE_DEGREE
        || u64_property(backend_statement, "columnCount")? != RECEIVER_KEY_WITNESS_COLUMN_COUNT
        || u64_property(backend_statement, "rowCount")? != RECEIVER_KEY_EQUATION_ROW_COUNT
        || u64_property(backend_statement, "digestExpandedRowCount")?
            != RECEIVER_KEY_EQUATION_ROW_COUNT
        || u64_property(backend_statement, "explicitRowCount")? != 0
    {
        return Err("receiver-key backend statement has an invalid canonical shape".to_string());
    }
    for digest_field_name in [
        "manifestDigest",
        "rosterDigest",
        "receiverEncryptionProfileDigest",
        "receiverPublicKeyDigest",
        "keyMaterialDigest",
        "publicMatrixSeedDigest",
        "receiverKeyContextDigest",
        "matrixDigest",
        "targetVectorDigest",
        "boundsDigest",
        "backendStatementDigest",
    ] {
        if !receiver_key_is_protocol_digest(&string_property(backend_statement, digest_field_name)?)
        {
            return Err(format!(
                "receiver-key backend statement field {digest_field_name} is not a protocol digest"
            ));
        }
    }

    validate_expected_public_matrix_seed(backend_statement)?;
    validate_receiver_key_context_digest(backend_statement)?;
    validate_variable_columns(backend_statement)?;
    validate_row_batch(backend_statement)?;
    validate_bounds(backend_statement)?;

    let row_batch = object_field(
        array_property(backend_statement, "rowBatches")?
            .first()
            .ok_or_else(|| "receiver-key backend statement has no row batch".to_string())?,
        "rowBatch",
    )?;
    let matrix_digest = derive_receiver_key_backend_digest(
        RECEIVER_KEY_MATRIX_DIGEST_PURPOSE,
        &json!({
            "rowBatches": [
                {
                    "batchKind": string_property(row_batch, "batchKind")?,
                    "batchName": string_property(row_batch, "batchName")?,
                    "matrixDigest": string_property(row_batch, "matrixDigest")?,
                    "rowCount": u64_property(row_batch, "rowCount")?,
                    "rowKind": string_property(row_batch, "rowKind")?,
                    "rowOffset": u64_property(row_batch, "rowOffset")?,
                }
            ]
        }),
    )?;
    if string_property(backend_statement, "matrixDigest")? != matrix_digest {
        return Err("receiver-key backend matrix digest does not match row batch".to_string());
    }
    let target_vector_digest = derive_receiver_key_backend_digest(
        RECEIVER_KEY_TARGET_VECTOR_DIGEST_PURPOSE,
        &json!({
            "rowBatches": [
                {
                    "batchKind": string_property(row_batch, "batchKind")?,
                    "batchName": string_property(row_batch, "batchName")?,
                    "rowCount": u64_property(row_batch, "rowCount")?,
                    "rowKind": string_property(row_batch, "rowKind")?,
                    "rowOffset": u64_property(row_batch, "rowOffset")?,
                    "targetVectorDigest": string_property(row_batch, "targetVectorDigest")?,
                }
            ]
        }),
    )?;
    if string_property(backend_statement, "targetVectorDigest")? != target_vector_digest {
        return Err(
            "receiver-key backend target-vector digest does not match row batch".to_string(),
        );
    }
    let bounds_digest = derive_receiver_key_backend_digest(
        RECEIVER_KEY_BOUNDS_DIGEST_PURPOSE,
        &json!({ "bounds": array_property(backend_statement, "bounds")? }),
    )?;
    if string_property(backend_statement, "boundsDigest")? != bounds_digest {
        return Err("receiver-key backend bounds digest does not match bounds".to_string());
    }
    let statement_payload = receiver_key_value_without_field(
        &Value::Object(backend_statement.clone()),
        "backendStatementDigest",
    )?;
    let backend_statement_digest = derive_receiver_key_backend_digest(
        RECEIVER_KEY_STATEMENT_DIGEST_PURPOSE,
        &statement_payload,
    )?;
    if string_property(backend_statement, "backendStatementDigest")? != backend_statement_digest {
        return Err(
            "receiver-key backend statement digest does not match its canonical payload"
                .to_string(),
        );
    }

    Ok(backend_statement_digest)
}

pub(super) fn validate_witness_vector_layout(
    linear_statement: &Map<String, Value>,
) -> Result<(), String> {
    let layout = array_property(linear_statement, "witnessVectorLayout")?;
    if layout.len() as u64 != RECEIVER_KEY_LINEAR_STATEMENT_COLUMN_COUNT {
        return Err("receiver-key linear witness layout has an invalid length".to_string());
    }
    for (layout_index, layout_value) in layout.iter().enumerate() {
        let expected_label = if (layout_index as u64) < RECEIVER_ENCRYPTION_MODULE_RANK {
            format!("receiver secret polynomial {layout_index}")
        } else {
            format!(
                "receiver error polynomial {}",
                layout_index as u64 - RECEIVER_ENCRYPTION_MODULE_RANK
            )
        };
        if layout_value.as_str() != Some(expected_label.as_str()) {
            return Err("receiver-key linear witness layout is not canonical".to_string());
        }
    }

    Ok(())
}

pub(super) fn validate_statement_matrix(
    statement_matrix_values: &[Value],
) -> Result<Vec<Vec<Vec<u64>>>, String> {
    if statement_matrix_values.len() as u64 != RECEIVER_KEY_LINEAR_STATEMENT_ROW_COUNT {
        return Err("receiver-key linear statement matrix row count is invalid".to_string());
    }

    let mut statement_matrix = Vec::with_capacity(statement_matrix_values.len());
    for (row_index, row_value) in statement_matrix_values.iter().enumerate() {
        let row_values = row_value
            .as_array()
            .ok_or_else(|| "receiver-key linear matrix row must be an array".to_string())?;
        if row_values.len() as u64 != RECEIVER_KEY_LINEAR_STATEMENT_COLUMN_COUNT {
            return Err("receiver-key linear statement matrix column count is invalid".to_string());
        }
        let mut matrix_row = Vec::with_capacity(row_values.len());
        for (column_index, polynomial_value) in row_values.iter().enumerate() {
            matrix_row.push(validate_modulus_polynomial(
                polynomial_value,
                &format!("receiver-key linear matrix polynomial {row_index}:{column_index}"),
            )?);
        }
        statement_matrix.push(matrix_row);
    }

    Ok(statement_matrix)
}

pub(super) fn validate_target_vector(
    target_vector_values: &[Value],
) -> Result<Vec<Vec<u64>>, String> {
    if target_vector_values.len() as u64 != RECEIVER_KEY_LINEAR_STATEMENT_ROW_COUNT {
        return Err("receiver-key linear target vector row count is invalid".to_string());
    }
    let mut target_vector = Vec::with_capacity(target_vector_values.len());
    for (row_index, polynomial_value) in target_vector_values.iter().enumerate() {
        target_vector.push(validate_modulus_polynomial(
            polynomial_value,
            &format!("receiver-key linear target polynomial {row_index}"),
        )?);
    }

    Ok(target_vector)
}

pub(super) fn validate_modulus_polynomial(
    polynomial_value: &Value,
    label: &str,
) -> Result<Vec<u64>, String> {
    let coefficients = polynomial_value
        .as_array()
        .ok_or_else(|| format!("{label} must be an array"))?;
    if coefficients.len() as u64 != RECEIVER_ENCRYPTION_MODULE_DEGREE {
        return Err(format!("{label} must use the frozen ring degree"));
    }

    let mut polynomial = Vec::with_capacity(coefficients.len());
    for coefficient_value in coefficients {
        let coefficient = coefficient_value
            .as_u64()
            .ok_or_else(|| format!("{label} contains a noncanonical coefficient"))?;
        if coefficient >= RECEIVER_ENCRYPTION_MODULUS {
            return Err(format!("{label} contains an out-of-range coefficient"));
        }
        polynomial.push(coefficient);
    }

    Ok(polynomial)
}

pub(super) fn validate_canonical_linear_matrix(
    linear_statement: &Map<String, Value>,
    statement_matrix: &[Vec<Vec<u64>>],
) -> Result<(), String> {
    let expected_public_matrix = derive_receiver_public_matrix(
        &string_property(linear_statement, "receiverEncryptionProfileDigest")?,
        &string_property(linear_statement, "publicMatrixSeedDigest")?,
    )?;

    for row_index in 0..RECEIVER_ENCRYPTION_MODULE_RANK as usize {
        for column_index in 0..RECEIVER_ENCRYPTION_MODULE_RANK as usize {
            if statement_matrix[row_index][column_index]
                != expected_public_matrix[row_index][column_index]
            {
                return Err(
                    "receiver-key linear statement public matrix coefficients are not canonical"
                        .to_string(),
                );
            }
        }
        for identity_column_index in 0..RECEIVER_ENCRYPTION_MODULE_RANK as usize {
            let column_index = identity_column_index + RECEIVER_ENCRYPTION_MODULE_RANK as usize;
            let expected_polynomial = identity_polynomial(row_index == identity_column_index);
            if statement_matrix[row_index][column_index] != expected_polynomial {
                return Err(
                    "receiver-key linear statement error-identity columns are not canonical"
                        .to_string(),
                );
            }
        }
    }

    Ok(())
}
