use serde_json::{Map, Value, json};

use crate::hashing::{canonical_json, derive_protocol_digest, hash512};

use super::{BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE, describe_proof_backend};

const BACKEND_STATEMENT_FORMAT: &str = "SparseSignedIntegerBackendStatement-v1";
const RECEIVER_KEY_STATEMENT_DIGEST_PURPOSE: &str = "receiver-key-backend-statement-v1";
const RECEIVER_KEY_MATRIX_DIGEST_PURPOSE: &str = "receiver-key-backend-matrix-v1";
const RECEIVER_KEY_TARGET_VECTOR_DIGEST_PURPOSE: &str = "receiver-key-backend-target-vector-v1";
const RECEIVER_KEY_BOUNDS_DIGEST_PURPOSE: &str = "receiver-key-backend-bounds-v1";
const RECEIVER_KEY_DIGEST_EXPANDED_MATRIX_DIGEST_PURPOSE: &str =
    "receiver-key-backend-digest-expanded-matrix-v1";
const RECEIVER_KEY_DIGEST_EXPANDED_TARGET_VECTOR_DIGEST_PURPOSE: &str =
    "receiver-key-backend-digest-expanded-target-vector-v1";
const RECEIVER_KEY_PUBLIC_CONTEXT_DIGEST_PURPOSE: &str = "receiver-key-backend-public-context-v1";
const RECEIVER_KEY_LINEAR_STATEMENT_PROFILE_ID: &str =
    "receiver-key-linear-module-lwe-statement-v1";
const RECEIVER_KEY_LINEAR_STATEMENT_DIGEST_PURPOSE: &str = "receiver-key-linear-proof-statement-v1";
const RECEIVER_KEY_LINEAR_STATEMENT_MATRIX_DIGEST_PURPOSE: &str =
    "receiver-key-linear-proof-statement-matrix-v1";
const RECEIVER_KEY_LINEAR_TARGET_VECTOR_DIGEST_PURPOSE: &str =
    "receiver-key-linear-proof-target-vector-v1";
const RECEIVER_KEY_LINEAR_RELATION: &str = "A*w + t = 0";
const RECEIVER_KEY_LINEAR_SOURCE_RING: &str = "Z_q[X]/(X^256 + 1)";
const RECEIVER_KEY_LINEAR_PROOF_ROOT_KIND: &str =
    "ReceiverKeyRelationLinearStatementAndBackendStatement";
const RECEIVER_KEY_EQUATION_COEFFICIENT_EXPANSION_DOMAIN: &str =
    "sealed.vote/internal/receiver-key-proof/receiver-key-equation/coefficient-expansion-v1";
const RECEIVER_KEY_EQUATION_TARGET_EXPANSION_DOMAIN: &str =
    "sealed.vote/internal/receiver-key-proof/receiver-key-equation/target-expansion-v1";
const RECEIVER_PUBLIC_MATRIX_EXPANSION_DOMAIN: &str =
    "sealed.vote/internal/receiver-encryption/public-matrix-v1";
const RECEIVER_ENCRYPTION_MODULUS: u64 = 12_289;
const RECEIVER_ENCRYPTION_MODULE_RANK: u64 = 4;
const RECEIVER_ENCRYPTION_MODULE_DEGREE: u64 = 256;
const RECEIVER_ENCRYPTION_SHORT_VECTOR_INFINITY_NORM_BOUND: u64 = 2;
const RECEIVER_KEY_LINEAR_STATEMENT_ROW_COUNT: u64 = RECEIVER_ENCRYPTION_MODULE_RANK;
const RECEIVER_KEY_LINEAR_STATEMENT_COLUMN_COUNT: u64 = RECEIVER_ENCRYPTION_MODULE_RANK * 2;
const RECEIVER_KEY_LINEAR_WITNESS_L2_BOUND_SQUARED: u64 = RECEIVER_KEY_LINEAR_STATEMENT_COLUMN_COUNT
    * RECEIVER_ENCRYPTION_MODULE_DEGREE
    * RECEIVER_ENCRYPTION_SHORT_VECTOR_INFINITY_NORM_BOUND
    * RECEIVER_ENCRYPTION_SHORT_VECTOR_INFINITY_NORM_BOUND;
const RECEIVER_KEY_EQUATION_ROW_COUNT: u64 =
    RECEIVER_ENCRYPTION_MODULE_RANK * RECEIVER_ENCRYPTION_MODULE_DEGREE;
const RECEIVER_KEY_WITNESS_COLUMN_COUNT: u64 = RECEIVER_KEY_EQUATION_ROW_COUNT * 2;

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

struct ReceiverKeyVectorSummary {
    accepted_digests: Vec<String>,
    case_name: String,
    expected_outcome: String,
    status_labels: Vec<&'static str>,
}

struct ReceiverKeyAcceptedDigests {
    backend_statement_digest: String,
    linear_statement_digest: String,
}

fn validate_receiver_key_vector_case(
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

fn validate_accepting_case(
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

fn validate_preflight_rejecting_case(case_object: &Map<String, Value>) -> Result<(), String> {
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

fn validate_construction_rejecting_case(
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

fn validate_receiver_public_key(receiver_public_key: &Map<String, Value>) -> Result<(), String> {
    if string_property(receiver_public_key, "objectType")? != "ReceiverEncryptionPublicKey"
        || u64_property(receiver_public_key, "objectVersion")? != 1
        || string_property(receiver_public_key, "receiverIdentity")?.is_empty()
        || u64_property(receiver_public_key, "receiverRosterPosition")? == 0
        || !is_protocol_digest(&string_property(receiver_public_key, "manifestDigest")?)
        || !is_protocol_digest(&string_property(receiver_public_key, "rosterDigest")?)
        || !is_protocol_digest(&string_property(
            receiver_public_key,
            "receiverEncryptionProfileDigest",
        )?)
        || !is_protocol_digest(&string_property(receiver_public_key, "keyMaterialDigest")?)
    {
        return Err("receiver-key public key has an invalid canonical shape".to_string());
    }
    let public_key_payload = value_without_field(
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

fn validate_proof_shell(
    receiver_public_key: &Map<String, Value>,
    receiver_key_proof: &Map<String, Value>,
    backend_statement: &Map<String, Value>,
    linear_statement: &Map<String, Value>,
) -> Result<(), String> {
    if string_property(receiver_key_proof, "objectType")? != "ReceiverKeyProof"
        || u64_property(receiver_key_proof, "objectVersion")? != 1
        || string_property(receiver_key_proof, "proofBackend")? != "LaZerStyleLocalLatticeRelation"
        || !is_protocol_digest(&string_property(receiver_key_proof, "proofRoot")?)
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
    let proof_shell_payload = value_without_field(
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

fn expected_receiver_key_proof_root(
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

fn validate_linear_statement(
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
        if !is_protocol_digest(&string_property(linear_statement, digest_field_name)?) {
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

    let statement_payload =
        value_without_field(&Value::Object(linear_statement.clone()), "statementDigest")?;
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

fn validate_backend_statement(backend_statement: &Map<String, Value>) -> Result<String, String> {
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
        if !is_protocol_digest(&string_property(backend_statement, digest_field_name)?) {
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
    let statement_payload = value_without_field(
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

fn validate_witness_vector_layout(linear_statement: &Map<String, Value>) -> Result<(), String> {
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

fn validate_statement_matrix(
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

fn validate_target_vector(target_vector_values: &[Value]) -> Result<Vec<Vec<u64>>, String> {
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

fn validate_modulus_polynomial(polynomial_value: &Value, label: &str) -> Result<Vec<u64>, String> {
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

fn validate_canonical_linear_matrix(
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

fn validate_key_material_digest_from_target(
    linear_statement: &Map<String, Value>,
    target_vector: &[Vec<u64>],
) -> Result<(), String> {
    let public_key_vector = Value::Array(
        target_vector
            .iter()
            .map(|polynomial| {
                Value::Array(
                    polynomial
                        .iter()
                        .map(|coefficient| {
                            Value::from(
                                (RECEIVER_ENCRYPTION_MODULUS - coefficient)
                                    % RECEIVER_ENCRYPTION_MODULUS,
                            )
                        })
                        .collect(),
                )
            })
            .collect(),
    );
    let expected_key_material_digest = derive_protocol_digest(
        "PublicKeyDigest",
        &json!({
            "publicKeyVector": public_key_vector,
            "publicMatrixSeedDigest": string_property(linear_statement, "publicMatrixSeedDigest")?,
            "receiverEncryptionProfileDigest": string_property(linear_statement, "receiverEncryptionProfileDigest")?,
        }),
    )
    .map_err(|error| {
        format!("receiver-key linear key material digest could not be recomputed: {error}")
    })?;
    if string_property(linear_statement, "keyMaterialDigest")? != expected_key_material_digest {
        return Err(
            "receiver-key linear target vector is not bound to the key material digest".to_string(),
        );
    }

    Ok(())
}

fn identity_polynomial(has_unit_coefficient: bool) -> Vec<u64> {
    let mut polynomial = vec![0; RECEIVER_ENCRYPTION_MODULE_DEGREE as usize];
    if has_unit_coefficient {
        polynomial[0] = 1;
    }

    polynomial
}

fn derive_receiver_public_matrix(
    receiver_encryption_profile_digest: &str,
    public_matrix_seed_digest: &str,
) -> Result<Vec<Vec<Vec<u64>>>, String> {
    let mut public_matrix = Vec::with_capacity(RECEIVER_ENCRYPTION_MODULE_RANK as usize);
    for row_index in 0..RECEIVER_ENCRYPTION_MODULE_RANK {
        let mut matrix_row = Vec::with_capacity(RECEIVER_ENCRYPTION_MODULE_RANK as usize);
        for column_index in 0..RECEIVER_ENCRYPTION_MODULE_RANK {
            matrix_row.push(derive_number_polynomial(
                RECEIVER_PUBLIC_MATRIX_EXPANSION_DOMAIN,
                &json!({
                    "columnIndex": column_index,
                    "publicMatrixSeedDigest": public_matrix_seed_digest,
                    "receiverEncryptionProfileDigest": receiver_encryption_profile_digest,
                    "rowIndex": row_index,
                }),
            )?);
        }
        public_matrix.push(matrix_row);
    }

    Ok(public_matrix)
}

fn derive_number_polynomial(domain: &str, payload: &Value) -> Result<Vec<u64>, String> {
    let mut polynomial = Vec::with_capacity(RECEIVER_ENCRYPTION_MODULE_DEGREE as usize);
    for coefficient_index in 0..RECEIVER_ENCRYPTION_MODULE_DEGREE {
        polynomial.push(derive_uniform_number(
            domain,
            &json!({
                "coefficientIndex": coefficient_index,
                "payload": payload,
            }),
            RECEIVER_ENCRYPTION_MODULUS,
        )?);
    }

    Ok(polynomial)
}

fn derive_uniform_number(domain: &str, payload: &Value, modulus: u64) -> Result<u64, String> {
    if modulus == 0 {
        return Err("receiver-key uniform derivation modulus must be nonzero".to_string());
    }
    let unsigned_word_modulus = 1u128 << 64;
    let rejection_limit = unsigned_word_modulus - (unsigned_word_modulus % u128::from(modulus));
    let mut block_counter = 0u64;

    loop {
        let block = derive_bytes(
            domain,
            &json!({
                "blockCounter": block_counter,
                "payload": payload,
            }),
            64,
        )?;
        for chunk in block.chunks_exact(8) {
            let candidate = u64::from_le_bytes(
                chunk
                    .try_into()
                    .map_err(|_| "receiver-key uniform chunk has invalid length".to_string())?,
            );
            if u128::from(candidate) < rejection_limit {
                return Ok((u128::from(candidate) % u128::from(modulus)) as u64);
            }
        }
        block_counter = block_counter
            .checked_add(1)
            .ok_or_else(|| "receiver-key uniform derivation counter overflowed".to_string())?;
    }
}

fn derive_bytes(domain: &str, payload: &Value, byte_length: usize) -> Result<Vec<u8>, String> {
    let mut output = vec![0; byte_length];
    let mut output_offset = 0usize;
    let mut block_counter = 0u64;
    while output_offset < byte_length {
        let block_payload = json!({
            "blockCounter": block_counter,
            "payload": payload,
        });
        let canonical = canonical_json(&block_payload)
            .map_err(|error| format!("receiver-key expansion payload is not canonical: {error}"))?;
        let block = hash512(domain, &[canonical.as_bytes()]);
        let bytes_to_copy = block.len().min(byte_length - output_offset);
        output[output_offset..output_offset + bytes_to_copy]
            .copy_from_slice(&block[..bytes_to_copy]);
        output_offset += bytes_to_copy;
        block_counter = block_counter
            .checked_add(1)
            .ok_or_else(|| "receiver-key byte derivation counter overflowed".to_string())?;
    }

    Ok(output)
}

fn validate_expected_public_matrix_seed(
    backend_statement: &Map<String, Value>,
) -> Result<(), String> {
    let expected_public_matrix_seed_digest = derive_protocol_digest(
        "ReceiverEncryptionProfileDigest",
        &json!({
            "ceremonyId": string_property(backend_statement, "ceremonyId")?,
            "manifestDigest": string_property(backend_statement, "manifestDigest")?,
            "purpose": "receiver-public-matrix-seed",
            "receiverEncryptionProfileDigest": string_property(backend_statement, "receiverEncryptionProfileDigest")?,
            "receiverIdentity": string_property(backend_statement, "receiverIdentity")?,
            "receiverRosterPosition": u64_property(backend_statement, "receiverRosterPosition")?,
            "recoveryEpoch": u64_property(backend_statement, "recoveryEpoch")?,
            "rosterDigest": string_property(backend_statement, "rosterDigest")?,
        }),
    )
    .map_err(|error| format!("receiver-key matrix seed could not be recomputed: {error}"))?;
    if string_property(backend_statement, "publicMatrixSeedDigest")?
        != expected_public_matrix_seed_digest
    {
        return Err(
            "receiver-key backend statement public matrix seed is not canonical".to_string(),
        );
    }

    Ok(())
}

fn validate_receiver_key_context_digest(
    backend_statement: &Map<String, Value>,
) -> Result<(), String> {
    let expected_context_digest = derive_receiver_key_backend_digest(
        RECEIVER_KEY_PUBLIC_CONTEXT_DIGEST_PURPOSE,
        &json!({
            "ceremonyId": string_property(backend_statement, "ceremonyId")?,
            "manifestDigest": string_property(backend_statement, "manifestDigest")?,
            "receiverEncryptionProfileDigest": string_property(backend_statement, "receiverEncryptionProfileDigest")?,
            "receiverIdentity": string_property(backend_statement, "receiverIdentity")?,
            "receiverPublicKeyDigest": string_property(backend_statement, "receiverPublicKeyDigest")?,
            "receiverRosterPosition": u64_property(backend_statement, "receiverRosterPosition")?,
            "recoveryEpoch": u64_property(backend_statement, "recoveryEpoch")?,
            "rosterDigest": string_property(backend_statement, "rosterDigest")?,
        }),
    )?;
    if string_property(backend_statement, "receiverKeyContextDigest")? != expected_context_digest {
        return Err("receiver-key backend context digest does not match public inputs".to_string());
    }

    Ok(())
}

fn validate_variable_columns(backend_statement: &Map<String, Value>) -> Result<(), String> {
    let variable_columns = array_property(backend_statement, "variableColumns")?;
    if variable_columns.len() as u64 != RECEIVER_KEY_WITNESS_COLUMN_COUNT {
        return Err("receiver-key backend variable column count is invalid".to_string());
    }
    for (column_index, variable_column) in variable_columns.iter().enumerate() {
        let column_object = object_field(variable_column, "variableColumn")?;
        if u64_property(column_object, "columnIndex")? != column_index as u64 {
            return Err("receiver-key backend variable columns are not canonical".to_string());
        }
        let expected_role = if (column_index as u64) < RECEIVER_KEY_EQUATION_ROW_COUNT {
            "ReceiverSecretCoefficient"
        } else {
            "ReceiverErrorCoefficient"
        };
        let role_offset = if expected_role == "ReceiverSecretCoefficient" {
            column_index as u64
        } else {
            column_index as u64 - RECEIVER_KEY_EQUATION_ROW_COUNT
        };
        let polynomial_index = role_offset / RECEIVER_ENCRYPTION_MODULE_DEGREE;
        let coefficient_index = role_offset % RECEIVER_ENCRYPTION_MODULE_DEGREE;
        let expected_variable_name = if expected_role == "ReceiverSecretCoefficient" {
            format!("receiver_secret_polynomial_{polynomial_index}_coefficient_{coefficient_index}")
        } else {
            format!("receiver_error_polynomial_{polynomial_index}_coefficient_{coefficient_index}")
        };

        if string_property(column_object, "variableRole")? != expected_role
            || u64_property(column_object, "polynomialIndex")? != polynomial_index
            || u64_property(column_object, "coefficientIndex")? != coefficient_index
            || string_property(column_object, "variableName")? != expected_variable_name
        {
            return Err("receiver-key backend variable column metadata is invalid".to_string());
        }
    }

    Ok(())
}

fn validate_row_batch(backend_statement: &Map<String, Value>) -> Result<(), String> {
    let row_batches = array_property(backend_statement, "rowBatches")?;
    if row_batches.len() != 1 {
        return Err("receiver-key backend statement must contain one row batch".to_string());
    }
    let row_batch = object_field(&row_batches[0], "rowBatch")?;
    if string_property(row_batch, "batchKind")? != "DigestExpandedRows"
        || string_property(row_batch, "batchName")? != "receiver_key_equation_rows"
        || string_property(row_batch, "coefficientExpansionDomain")?
            != RECEIVER_KEY_EQUATION_COEFFICIENT_EXPANSION_DOMAIN
        || string_property(row_batch, "modulus")? != RECEIVER_ENCRYPTION_MODULUS.to_string()
        || string_property(row_batch, "rowKind")? != "ReceiverKeyEquation"
        || u64_property(row_batch, "rowOffset")? != 0
        || u64_property(row_batch, "rowCount")? != RECEIVER_KEY_EQUATION_ROW_COUNT
        || string_property(row_batch, "sourceAlgebraicRowName")? != "receiver_key_well_formedness"
        || string_property(row_batch, "targetExpansionDomain")?
            != RECEIVER_KEY_EQUATION_TARGET_EXPANSION_DOMAIN
    {
        return Err("receiver-key backend row batch has an invalid canonical shape".to_string());
    }
    validate_decimal_string(&string_property(row_batch, "modulus")?)?;
    if string_property(row_batch, "receiverIdentity")?
        != string_property(backend_statement, "receiverIdentity")?
        || u64_property(row_batch, "receiverRosterPosition")?
            != u64_property(backend_statement, "receiverRosterPosition")?
        || string_property(row_batch, "targetDigest")?
            != string_property(backend_statement, "keyMaterialDigest")?
    {
        return Err("receiver-key backend row batch is not context-bound".to_string());
    }
    let public_input_digests = object_property(row_batch, "publicInputDigests")?;
    for (field_name, statement_field_name) in [
        ("keyMaterialDigest", "keyMaterialDigest"),
        ("publicMatrixSeedDigest", "publicMatrixSeedDigest"),
        (
            "receiverEncryptionProfileDigest",
            "receiverEncryptionProfileDigest",
        ),
        ("receiverKeyContextDigest", "receiverKeyContextDigest"),
        ("receiverPublicKeyDigest", "receiverPublicKeyDigest"),
    ] {
        if string_property(public_input_digests, field_name)?
            != string_property(backend_statement, statement_field_name)?
        {
            return Err(
                "receiver-key backend row batch public digest binding is invalid".to_string(),
            );
        }
    }
    validate_column_indices(
        array_property(row_batch, "variableColumnIndices")?,
        0,
        RECEIVER_KEY_WITNESS_COLUMN_COUNT,
    )?;

    let row_batch_payload = json!({
        "coefficientExpansionDomain": string_property(row_batch, "coefficientExpansionDomain")?,
        "modulus": string_property(row_batch, "modulus")?,
        "publicInputDigests": public_input_digests,
        "receiverIdentity": string_property(row_batch, "receiverIdentity")?,
        "receiverRosterPosition": u64_property(row_batch, "receiverRosterPosition")?,
        "rowCount": u64_property(row_batch, "rowCount")?,
        "rowKind": string_property(row_batch, "rowKind")?,
        "sourceAlgebraicRowName": string_property(row_batch, "sourceAlgebraicRowName")?,
        "targetDigest": string_property(row_batch, "targetDigest")?,
        "targetExpansionDomain": string_property(row_batch, "targetExpansionDomain")?,
        "variableColumnIndices": array_property(row_batch, "variableColumnIndices")?,
    });
    let matrix_digest = derive_receiver_key_backend_digest(
        RECEIVER_KEY_DIGEST_EXPANDED_MATRIX_DIGEST_PURPOSE,
        &row_batch_payload,
    )?;
    let target_vector_digest = derive_receiver_key_backend_digest(
        RECEIVER_KEY_DIGEST_EXPANDED_TARGET_VECTOR_DIGEST_PURPOSE,
        &row_batch_payload,
    )?;
    if string_property(row_batch, "matrixDigest")? != matrix_digest {
        return Err("receiver-key backend row-batch matrix digest is invalid".to_string());
    }
    if string_property(row_batch, "targetVectorDigest")? != target_vector_digest {
        return Err("receiver-key backend row-batch target digest is invalid".to_string());
    }

    Ok(())
}

fn validate_bounds(backend_statement: &Map<String, Value>) -> Result<(), String> {
    let bounds = array_property(backend_statement, "bounds")?;
    if bounds.len() != 2 {
        return Err(
            "receiver-key backend statement must contain two short-vector bounds".to_string(),
        );
    }
    validate_bound(&bounds[0], "receiver_secret_coefficients_eta_2", 0)?;
    validate_bound(
        &bounds[1],
        "receiver_error_coefficients_eta_2",
        RECEIVER_KEY_EQUATION_ROW_COUNT,
    )?;

    Ok(())
}

fn validate_bound(
    bound: &Value,
    expected_bound_name: &str,
    expected_column_offset: u64,
) -> Result<(), String> {
    let bound_object = object_field(bound, "bound")?;
    if string_property(bound_object, "absoluteMaximum")?
        != RECEIVER_ENCRYPTION_SHORT_VECTOR_INFINITY_NORM_BOUND.to_string()
        || string_property(bound_object, "boundKind")? != "SignedIntegerAbsoluteBound"
        || string_property(bound_object, "boundName")? != expected_bound_name
    {
        return Err("receiver-key backend bound has an invalid canonical shape".to_string());
    }
    validate_decimal_string(&string_property(bound_object, "absoluteMaximum")?)?;
    validate_column_indices(
        array_property(bound_object, "variableColumnIndices")?,
        expected_column_offset,
        RECEIVER_KEY_EQUATION_ROW_COUNT,
    )?;
    let variable_names = array_property(bound_object, "variableNames")?;
    if variable_names.len() as u64 != RECEIVER_KEY_EQUATION_ROW_COUNT {
        return Err("receiver-key backend bound variable names are invalid".to_string());
    }
    for (index, variable_name) in variable_names.iter().enumerate() {
        let linear_index = index as u64;
        let polynomial_index = linear_index / RECEIVER_ENCRYPTION_MODULE_DEGREE;
        let coefficient_index = linear_index % RECEIVER_ENCRYPTION_MODULE_DEGREE;
        let expected_variable_name = if expected_column_offset == 0 {
            format!("receiver_secret_polynomial_{polynomial_index}_coefficient_{coefficient_index}")
        } else {
            format!("receiver_error_polynomial_{polynomial_index}_coefficient_{coefficient_index}")
        };
        if variable_name.as_str() != Some(expected_variable_name.as_str()) {
            return Err("receiver-key backend bound variable names are not canonical".to_string());
        }
    }

    Ok(())
}

fn validate_digest_change_trace(
    case_object: &Map<String, Value>,
    accepted_digests: &ReceiverKeyAcceptedDigests,
) -> Result<(), String> {
    let trace = object_property(case_object, "trace")?;
    if let Ok(expected_digest_changed) = bool_property(trace, "expectedDigestChanged")
        && expected_digest_changed
    {
        if let Ok(baseline_backend_digest) =
            string_property(trace, "baselineBackendStatementDigest")
            && baseline_backend_digest == accepted_digests.backend_statement_digest
        {
            return Err(
                "receiver-key digest-change vector did not change backend digest".to_string(),
            );
        }
        if let Ok(baseline_linear_digest) = string_property(trace, "baselineLinearStatementDigest")
            && baseline_linear_digest == accepted_digests.linear_statement_digest
        {
            return Err(
                "receiver-key digest-change vector did not change linear digest".to_string(),
            );
        }
    }
    if let Ok(trace_digest) = string_property(trace, "backendStatementDigest")
        && trace_digest != accepted_digests.backend_statement_digest
    {
        return Err("receiver-key trace digest does not match backend statement".to_string());
    }
    if let Ok(trace_digest) = string_property(trace, "linearStatementDigest")
        && trace_digest != accepted_digests.linear_statement_digest
    {
        return Err("receiver-key trace digest does not match linear statement".to_string());
    }

    Ok(())
}

fn validate_column_indices(
    values: &[Value],
    expected_offset: u64,
    expected_count: u64,
) -> Result<(), String> {
    if values.len() as u64 != expected_count {
        return Err("receiver-key backend column index count is invalid".to_string());
    }
    for (index, value) in values.iter().enumerate() {
        if value.as_u64() != Some(expected_offset + index as u64) {
            return Err("receiver-key backend column indices are not canonical".to_string());
        }
    }

    Ok(())
}

fn derive_receiver_key_backend_digest(purpose: &str, payload: &Value) -> Result<String, String> {
    derive_protocol_digest(
        "ChallengeDomainDigest",
        &json!({
            "payload": payload,
            "purpose": purpose
        }),
    )
    .map_err(|error| format!("receiver-key backend digest could not be recomputed: {error}"))
}

fn reject_forbidden_witness_keys(value: &Value) -> Result<(), String> {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                if matches!(
                    key.as_str(),
                    "ciphertextChunks"
                        | "errorVector"
                        | "openingRandomness"
                        | "privateWitness"
                        | "proofRandomness"
                        | "publicKeyVector"
                        | "receiverShareVector"
                        | "secretState"
                        | "secretVector"
                        | "witness"
                ) {
                    return Err(format!(
                        "receiver-key vector exposes forbidden witness key {key}"
                    ));
                }
                reject_forbidden_witness_keys(child)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                reject_forbidden_witness_keys(item)?;
            }
        }
        _ => {}
    }

    Ok(())
}

fn is_protocol_digest(value: &str) -> bool {
    value.len() == 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_decimal_string(value: &str) -> Result<(), String> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err("receiver-key decimal string is not canonical".to_string());
    }

    Ok(())
}

fn object_field<'value>(
    value: &'value Value,
    field_name: &str,
) -> Result<&'value Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("{field_name} must be an object"))
}

fn object_property<'value>(
    object: &'value Map<String, Value>,
    field_name: &str,
) -> Result<&'value Map<String, Value>, String> {
    object
        .get(field_name)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{field_name} must be an object"))
}

fn string_property(object: &Map<String, Value>, field_name: &str) -> Result<String, String> {
    object
        .get(field_name)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("{field_name} must be a string"))
}

fn u64_property(object: &Map<String, Value>, field_name: &str) -> Result<u64, String> {
    object
        .get(field_name)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{field_name} must be an unsigned integer"))
}

fn array_property<'value>(
    object: &'value Map<String, Value>,
    field_name: &str,
) -> Result<&'value Vec<Value>, String> {
    object
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{field_name} must be an array"))
}

fn bool_property(object: &Map<String, Value>, field_name: &str) -> Result<bool, String> {
    object
        .get(field_name)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("{field_name} must be a boolean"))
}

fn value_without_field(value: &Value, field_name: &str) -> Result<Value, String> {
    let object = object_field(value, "object")?;
    let mut copied_object = object.clone();
    copied_object.remove(field_name);

    Ok(Value::Object(copied_object))
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::verify_receiver_key_vector_case_value;

    fn generated_case(case_name: &str) -> Value {
        let vectors: Value = serde_json::from_str(include_str!(
            "../../../../test-vectors/ballot-privacy/receiver-key-proof-vectors.json"
        ))
        .expect("receiver-key vector file should parse");

        vectors["cases"]
            .as_array()
            .expect("receiver-key vector file should contain cases")
            .iter()
            .find(|vector_case| vector_case["caseName"] == case_name)
            .unwrap_or_else(|| panic!("receiver-key vector case {case_name} should exist"))
            .clone()
    }

    #[test]
    fn verifies_valid_receiver_key_vector() {
        let verification = verify_receiver_key_vector_case_value(&generated_case(
            "valid-receiver-key-proof-backend-statement",
        ));

        assert_eq!(verification["ok"], true);
        assert_eq!(verification["backendAvailable"], false);
        assert_eq!(verification["expectedOutcome"], "accept");
        assert!({
            verification["statusLabels"]
                .as_array()
                .expect("status labels should be an array")
                .contains(&serde_json::json!("ReceiverKeyProofRootRecomputed"))
        });
        assert!({
            verification["statusLabels"]
                .as_array()
                .expect("status labels should be an array")
                .contains(&serde_json::json!("ReceiverKeyLinearStatementChecked"))
        });
    }

    #[test]
    fn verifies_recorded_receiver_key_construction_refusal() {
        let verification = verify_receiver_key_vector_case_value(&generated_case(
            "wrong-public-matrix-seed-rejects",
        ));

        assert_eq!(verification["ok"], true);
        assert_eq!(verification["expectedOutcome"], "reject");
        assert!({
            verification["statusLabels"]
                .as_array()
                .expect("status labels should be an array")
                .contains(&serde_json::json!("ReceiverKeyConstructionRefusalRecorded"))
        });
    }

    #[test]
    fn verifies_backend_preflight_reject_vector() {
        let verification = verify_receiver_key_vector_case_value(&generated_case(
            "noncanonical-backend-modulus-rejects",
        ));

        assert_eq!(verification["ok"], true);
        assert_eq!(verification["expectedOutcome"], "reject");
    }

    #[test]
    fn verifies_linear_statement_preflight_reject_vector() {
        let verification = verify_receiver_key_vector_case_value(&generated_case(
            "mutated-linear-statement-target-rejects",
        ));

        assert_eq!(verification["ok"], true);
        assert_eq!(verification["expectedOutcome"], "reject");
    }

    #[test]
    fn verifies_proof_shell_reject_vector() {
        let verification =
            verify_receiver_key_vector_case_value(&generated_case("mutated-proof-root-rejects"));

        assert_eq!(verification["ok"], true);
        assert_eq!(verification["expectedOutcome"], "reject");
    }
}
