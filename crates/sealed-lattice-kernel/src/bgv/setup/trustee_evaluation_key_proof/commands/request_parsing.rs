use super::super::invalid_succinct_setup_proof;
use super::super::relation::{
    SameSecretLinkageStatement, SetupProofStatement, SuccinctSetupProofContext,
    SuccinctSetupProofFamilyShape, TrusteeEvaluationKeyStatement,
};
use super::decoding::{read_string, read_u64};
use super::target_decryption_parsing::key_descriptor_from_value;
use crate::bgv::setup::commitment::parse_setup_commitment_full_value;
use crate::encoding::CanonicalResult;
use serde_json::Value;

fn same_secret_linkage_from_statement_request(
    request: &Value,
) -> CanonicalResult<SameSecretLinkageStatement> {
    let linkage_value = request
        .get("sameSecretLinkage")
        .ok_or_else(|| invalid_succinct_setup_proof("sameSecretLinkage must be present"))?;
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
    Ok(SameSecretLinkageStatement {
        public_matrix_seed_hash: read_string(linkage_value, "publicMatrixSeedHash")?.to_string(),
        commitments,
    })
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
        .map(|key_value| key_descriptor_from_value(key_value, request))
        .collect::<CanonicalResult<Vec<_>>>()?;
    // The key kinds decide the family, and the family decides which labeled
    // binding roots the context must carry.
    let shape = SuccinctSetupProofFamilyShape::from_key_kinds(
        &keys.iter().map(|key| key.kind).collect::<Vec<_>>(),
    )?;
    let context = proof_context_from_value(context_value, shape)?;
    if shape != SuccinctSetupProofFamilyShape::TrusteeEvaluationKey {
        return Err(invalid_succinct_setup_proof(
            "the trustee evaluation-key command requires diagonal-source key descriptors",
        ));
    }
    let proof = SetupProofStatement::TrusteeEvaluationKey {
        keys,
        same_secret_linkage: same_secret_linkage_from_statement_request(request)?,
    };
    let statement = TrusteeEvaluationKeyStatement {
        context,
        ring_degree,
        proof,
    };
    statement.validate_shape()?;

    Ok(statement)
}

fn proof_context_from_value(
    context_value: &Value,
    shape: SuccinctSetupProofFamilyShape,
) -> CanonicalResult<SuccinctSetupProofContext> {
    Ok(SuccinctSetupProofContext {
        setup_context_hash: read_string(context_value, "setupContextHash")?.to_string(),
        trustee_identity: read_string(context_value, "trusteeIdentity")?.to_string(),
        trustee_roster_position: read_u64(context_value, "trusteeRosterPosition")?,
        binding_roots: shape
            .binding_labels()
            .iter()
            .map(|label| Ok(read_string(context_value, label)?.to_string()))
            .collect::<CanonicalResult<Vec<_>>>()?,
    })
}
