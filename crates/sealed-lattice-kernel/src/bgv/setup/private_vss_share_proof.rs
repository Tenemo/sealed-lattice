use serde_json::{Value, json};

use crate::{
    bgv::parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE},
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::{derive_canonical_object_hash, to_hex},
    transcript_core::decode_hex,
};

use super::{
    accepted_setup::setup_parameters_hash,
    commitment::{SETUP_COMMITMENT_RANDOMNESS_WIDTH, SetupCommitmentValue, setup_commitment_root},
    setup_proof::{
        SETUP_PROOF_MATERIAL_ENCODING, SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        setup_proof_material_transport_hashes,
    },
    sharing::canonical_trustee_point,
    trustee_evaluation_key_proof::{
        PRIVATE_VSS_SHARE_PROOF_FAMILY, PrivateVssShareStatement, SuccinctSetupProofContext,
        TrusteeEvaluationKeyStatement, TrusteeEvaluationKeyWitness,
        decode_trustee_evaluation_key_proof, encode_trustee_evaluation_key_proof,
        private_vss_share_succinct_proof_bytes_hash, prove_evaluation_key_share,
        verify_evaluation_key_share,
    },
};

const PRIVATE_VSS_SHARE_EMBEDDED_PROOF_BYTES_ENCODING: &str = "embedded-binary-proof-bytes-hex";
const PRIVATE_VSS_SHARE_PROOF_TRANSPORT_SET_OBJECT_TYPE: &str =
    "SetupTransportedPrivateVssShareProofMaterialSet";
const PRIVATE_VSS_SHARE_PROOF_TRANSPORT_OBJECT_TYPE: &str =
    "SetupTransportedPrivateVssShareProofMaterial";

pub(super) struct PrivateVssShareSuccinctProofVerificationInput<'a> {
    pub(super) setup_context: &'a Value,
    pub(super) public_matrix_seed_hash: &'a str,
    pub(super) private_envelope_aad_hash: &'a str,
    pub(super) source_trustee_identity: &'a str,
    pub(super) source_trustee_roster_position: u64,
    pub(super) recipient_identity: &'a str,
    pub(super) recipient_roster_position: u64,
    pub(super) source_trustee_commitment_root: &'a str,
    pub(super) rns_limb_index: usize,
    pub(super) rns_prime: u64,
    pub(super) ring_degree: usize,
    pub(super) coefficient_commitment_roots: &'a [String],
    pub(super) share_values: &'a [u64],
    pub(super) share_values_hash: &'a str,
    pub(super) coefficient_commitments: &'a [SetupCommitmentValue],
    pub(super) proof_record: &'a Value,
    pub(super) transported_proof_material: Option<&'a Value>,
}

pub(super) struct PrivateVssShareSuccinctProofVerification {
    pub(super) proof_bytes_hash: String,
    pub(super) proof_statement_root: String,
    pub(super) proof_material_root: String,
    pub(super) statement_hash_hex: String,
}

pub(super) struct PrivateVssShareSuccinctProofWitness {
    pub(super) coefficient_messages_by_shamir_index: Vec<Vec<u64>>,
    pub(super) opening_randomness_by_shamir_index: Vec<Vec<Vec<i128>>>,
    pub(super) carry_witnesses: Vec<i128>,
}

#[derive(Clone, Copy)]
pub(super) struct PrivateVssShareSuccinctProofGenerationInput<'a> {
    pub(super) setup_context: &'a Value,
    pub(super) public_matrix_seed_hash: &'a str,
    pub(super) private_envelope_aad_hash: &'a str,
    pub(super) source_trustee_identity: &'a str,
    pub(super) source_trustee_roster_position: u64,
    pub(super) recipient_identity: &'a str,
    pub(super) recipient_roster_position: u64,
    pub(super) source_trustee_commitment_root: &'a str,
    pub(super) rns_limb_index: usize,
    pub(super) rns_prime: u64,
    pub(super) ring_degree: usize,
    pub(super) coefficient_commitment_roots: &'a [String],
    pub(super) share_values: &'a [u64],
    pub(super) share_values_hash: &'a str,
    pub(super) coefficient_commitments: &'a [SetupCommitmentValue],
    pub(super) witness: &'a PrivateVssShareSuccinctProofWitness,
    pub(super) proof_randomness_seed_hex: &'a str,
}

pub(super) fn verify_private_vss_share_succinct_relation_proof(
    input: PrivateVssShareSuccinctProofVerificationInput<'_>,
) -> CanonicalResult<PrivateVssShareSuccinctProofVerification> {
    validate_private_vss_share_statement_material(&input)?;
    validate_private_vss_share_proof_record(input.proof_record)?;

    let proof_bytes = private_vss_share_succinct_proof_bytes_from_record(&input)?;
    let proof_bytes_hash = private_vss_share_succinct_proof_bytes_hash(&proof_bytes);
    if value_string(input.proof_record, "proofBytesHash")? != proof_bytes_hash {
        return Err(invalid_private_vss_share_proof(
            "private VSS share proofBytesHash must match supplied proof bytes",
        ));
    }

    let statement = private_vss_share_succinct_statement(&input)?;
    let statement_value = private_vss_share_succinct_statement_value(&input, &statement)?;
    let proof_statement_root = derive_canonical_object_hash(&statement_value)?;
    let statement_hash_hex = to_hex(&statement.statement_hash());
    if value_string(input.proof_record, "proofStatementRoot")? != proof_statement_root {
        return Err(invalid_private_vss_share_proof(
            "private VSS share proofStatementRoot must match the canonical proof statement",
        ));
    }
    if value_string(input.proof_record, "statementHash")? != statement_hash_hex {
        return Err(invalid_private_vss_share_proof(
            "private VSS share statementHash must match the canonical proof statement",
        ));
    }

    let decoded_proof = decode_trustee_evaluation_key_proof(&statement, &proof_bytes)?;
    verify_evaluation_key_share(&statement, &decoded_proof)?;
    let proof_material_root =
        if private_vss_share_succinct_proof_uses_transport(input.proof_record)? {
            value_string(input.proof_record, "proofMaterialRoot")?.to_string()
        } else {
            private_vss_share_succinct_proof_material_root(&statement_hash_hex, &proof_bytes_hash)?
        };
    if value_string(input.proof_record, "proofMaterialRoot")? != proof_material_root {
        return Err(invalid_private_vss_share_proof(
            "private VSS share proofMaterialRoot must match the embedded proof material",
        ));
    }
    Ok(PrivateVssShareSuccinctProofVerification {
        proof_bytes_hash,
        proof_statement_root,
        proof_material_root,
        statement_hash_hex,
    })
}

fn validate_private_vss_share_statement_material(
    input: &PrivateVssShareSuccinctProofVerificationInput<'_>,
) -> CanonicalResult<()> {
    if DATA_PRIMES.get(input.rns_limb_index) != Some(&input.rns_prime) {
        return Err(invalid_private_vss_share_proof(
            "private VSS share proof RNS limb does not match Q_share",
        ));
    }
    if input.ring_degree == 0
        || input.ring_degree > POLYNOMIAL_DEGREE
        || input.share_values.len() != input.ring_degree
    {
        return Err(invalid_private_vss_share_proof(
            "private VSS share proof ring degree is outside the selected parameters",
        ));
    }
    if input
        .share_values
        .iter()
        .any(|value| *value >= input.rns_prime)
    {
        return Err(invalid_private_vss_share_proof(
            "private VSS share values must be canonical Q_share residues",
        ));
    }
    let roster = super::accepted_setup::accepted_roster_from_setup_context(input.setup_context);
    let expected_coefficient_count =
        usize::try_from(roster.decryption_threshold).map_err(|_| {
            invalid_private_vss_share_proof("setup decryption threshold does not fit usize")
        })?;
    if input.coefficient_commitment_roots.len() != input.coefficient_commitments.len()
        || input.coefficient_commitments.len() != expected_coefficient_count
    {
        return Err(invalid_private_vss_share_proof(
            "private VSS share proof requires every setup Shamir coefficient commitment",
        ));
    }
    for (coefficient_index, (commitment_root, commitment)) in input
        .coefficient_commitment_roots
        .iter()
        .zip(input.coefficient_commitments.iter())
        .enumerate()
    {
        if commitment.source_rns_limb_index != input.rns_limb_index
            || commitment.source_message_modulus != input.rns_prime
            || commitment.shamir_coefficient_index != coefficient_index as u64
            || commitment.ring_degree != input.ring_degree
            || setup_commitment_root(commitment)? != *commitment_root
        {
            return Err(invalid_private_vss_share_proof(
                "private VSS share coefficient commitments must follow the accepted limb and Shamir coefficient order",
            ));
        }
    }

    Ok(())
}

fn validate_private_vss_share_proof_record(proof_record: &Value) -> CanonicalResult<()> {
    expect_string_field(
        proof_record,
        "objectType",
        "PrivateVssShareProof",
        "private VSS share proof objectType must be PrivateVssShareProof",
    )?;
    if proof_record.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(invalid_private_vss_share_proof(
            "private VSS share proof objectVersion must be 1",
        ));
    }
    expect_string_field(
        proof_record,
        "proofFamily",
        PRIVATE_VSS_SHARE_PROOF_FAMILY,
        "private VSS share proofFamily does not match the VSS opening/carry family",
    )?;
    let proof_bytes_encoding = value_string(proof_record, "proofBytesEncoding")?;
    match proof_bytes_encoding {
        PRIVATE_VSS_SHARE_EMBEDDED_PROOF_BYTES_ENCODING => {
            if private_vss_share_succinct_proof_has_transport_reference(proof_record) {
                return Err(invalid_private_vss_share_proof(
                    "private VSS share proof must not mix embedded proofBytesHex with transported proof material",
                ));
            }
            if value_string(proof_record, "proofBytesHex")?.is_empty() {
                return Err(invalid_private_vss_share_proof(
                    "private VSS share proofBytesHex must be non-empty",
                ));
            }
        }
        SETUP_PROOF_MATERIAL_ENCODING => {
            if proof_record.get("proofBytesHex").is_some() {
                return Err(invalid_private_vss_share_proof(
                    "private VSS share proof must not mix embedded proofBytesHex with transported proof material",
                ));
            }
        }
        _ => {
            return Err(invalid_private_vss_share_proof(
                "private VSS share proofBytesEncoding must be embedded-binary-proof-bytes-hex or binary-chunked-proof-bytes",
            ));
        }
    }
    for field_name in [
        "proofStatementRoot",
        "statementHash",
        "proofBytesHash",
        "proofMaterialRoot",
    ] {
        validate_hash(value_string(proof_record, field_name)?, field_name)?;
    }

    Ok(())
}

fn private_vss_share_succinct_proof_uses_transport(proof_record: &Value) -> CanonicalResult<bool> {
    Ok(value_string(proof_record, "proofBytesEncoding")? == SETUP_PROOF_MATERIAL_ENCODING)
}

fn private_vss_share_succinct_proof_has_transport_reference(proof_record: &Value) -> bool {
    [
        "proofChunkSizeBytes",
        "proofChunkCount",
        "proofTotalByteLength",
        "proofFullObjectHash",
        "proofChunkRoot",
        "proofChunkHashes",
    ]
    .iter()
    .any(|field_name| proof_record.get(*field_name).is_some())
}

fn private_vss_share_succinct_proof_bytes_from_record(
    input: &PrivateVssShareSuccinctProofVerificationInput<'_>,
) -> CanonicalResult<Vec<u8>> {
    let proof_record = input.proof_record;
    match value_string(proof_record, "proofBytesEncoding")? {
        PRIVATE_VSS_SHARE_EMBEDDED_PROOF_BYTES_ENCODING => {
            decode_hex(value_string(proof_record, "proofBytesHex")?)
        }
        SETUP_PROOF_MATERIAL_ENCODING => {
            private_vss_share_succinct_transported_proof_bytes_from_record(input)
        }
        _ => Err(invalid_private_vss_share_proof(
            "private VSS share proofBytesEncoding must be embedded-binary-proof-bytes-hex or binary-chunked-proof-bytes",
        )),
    }
}

fn private_vss_share_succinct_transported_proof_bytes_from_record(
    input: &PrivateVssShareSuccinctProofVerificationInput<'_>,
) -> CanonicalResult<Vec<u8>> {
    let proof_record = input.proof_record;
    let Some(material_set) = input.transported_proof_material else {
        return Err(invalid_private_vss_share_proof(
            "transportedPrivateVssShareProofMaterial was required by transported private VSS proof records",
        ));
    };
    let proof_material_root = value_string(proof_record, "proofMaterialRoot")?;
    validate_hash(
        proof_material_root,
        "privateVssShareProof.proofMaterialRoot",
    )?;
    let chunks =
        transported_private_vss_share_proof_material_chunks(material_set, proof_material_root)?;
    let transport_hashes = setup_proof_material_transport_hashes(
        PRIVATE_VSS_SHARE_PROOF_FAMILY,
        &chunks,
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
    )?;
    verify_private_vss_share_succinct_proof_transport_reference(proof_record, &transport_hashes)?;
    let expected_material_root = private_vss_share_succinct_transported_proof_material_root(
        value_string(proof_record, "statementHash")?,
        value_string(proof_record, "proofBytesHash")?,
        &transport_hashes,
    )?;
    if proof_material_root != expected_material_root {
        return Err(invalid_private_vss_share_proof(
            "private VSS share proofMaterialRoot must match the canonical transported proof material reference",
        ));
    }

    let mut proof_bytes = Vec::with_capacity(
        usize::try_from(transport_hashes.total_byte_length).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "private VSS transported proof material length does not fit usize",
            )
        })?,
    );
    for chunk in chunks {
        proof_bytes.extend_from_slice(&chunk);
    }

    Ok(proof_bytes)
}

fn verify_private_vss_share_succinct_proof_transport_reference(
    proof_record: &Value,
    transport_hashes: &super::setup_proof::SetupProofMaterialTransportHashes,
) -> CanonicalResult<()> {
    if value_u64(proof_record, "proofChunkSizeBytes")? != SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES {
        return Err(invalid_private_vss_share_proof(
            "private VSS share proofChunkSizeBytes must match the setup proof transport parameters",
        ));
    }
    let expected_chunk_count =
        u64::try_from(transport_hashes.chunk_hashes.len()).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "private VSS proof material chunk count does not fit u64",
            )
        })?;
    if value_u64(proof_record, "proofChunkCount")? != expected_chunk_count {
        return Err(invalid_private_vss_share_proof(
            "private VSS share proofChunkCount must match transported proof chunks",
        ));
    }
    if value_u64(proof_record, "proofTotalByteLength")? != transport_hashes.total_byte_length {
        return Err(invalid_private_vss_share_proof(
            "private VSS share proofTotalByteLength must match transported proof chunks",
        ));
    }
    if value_string(proof_record, "proofFullObjectHash")?
        != transport_hashes.full_object_hash.as_str()
    {
        return Err(invalid_private_vss_share_proof(
            "private VSS share proofFullObjectHash must match transported proof chunks",
        ));
    }
    if value_string(proof_record, "proofChunkRoot")? != transport_hashes.chunk_root.as_str() {
        return Err(invalid_private_vss_share_proof(
            "private VSS share proofChunkRoot must match the canonical proof chunk manifest",
        ));
    }
    let Some(chunk_hash_values) = proof_record
        .get("proofChunkHashes")
        .and_then(Value::as_array)
    else {
        return Err(invalid_private_vss_share_proof(
            "private VSS share proofChunkHashes must list every transported proof chunk",
        ));
    };
    if chunk_hash_values.len() != transport_hashes.chunk_hashes.len() {
        return Err(invalid_private_vss_share_proof(
            "private VSS share proofChunkHashes length must match transported proof chunks",
        ));
    }
    for (chunk_index, (chunk_hash_value, expected_chunk_hash)) in chunk_hash_values
        .iter()
        .zip(transport_hashes.chunk_hashes.iter())
        .enumerate()
    {
        let Some(chunk_hash) = chunk_hash_value.as_str() else {
            return Err(invalid_private_vss_share_proof(format!(
                "private VSS share proofChunkHashes[{chunk_index}] must be a hash string"
            )));
        };
        validate_hash(
            chunk_hash,
            &format!("privateVssShareProof.proofChunkHashes[{chunk_index}]"),
        )?;
        if chunk_hash != expected_chunk_hash {
            return Err(invalid_private_vss_share_proof(
                "private VSS share proofChunkHashes must match transported proof chunks",
            ));
        }
    }

    Ok(())
}

fn transported_private_vss_share_proof_material_chunks(
    material_set: &Value,
    expected_proof_material_root: &str,
) -> CanonicalResult<Vec<Vec<u8>>> {
    verify_transported_private_vss_share_proof_material_set_header(material_set)?;
    let Some(proof_materials) = material_set.get("proofMaterials").and_then(Value::as_array) else {
        return Err(invalid_private_vss_share_proof(
            "transportedPrivateVssShareProofMaterial.proofMaterials must list transported proof material objects",
        ));
    };
    let mut matching_chunks = None;
    for proof_material in proof_materials {
        verify_transported_private_vss_share_proof_material_header(proof_material)?;
        let proof_material_root = value_string(proof_material, "proofMaterialRoot")?;
        if proof_material_root != expected_proof_material_root {
            continue;
        }
        if matching_chunks.is_some() {
            return Err(invalid_private_vss_share_proof(
                "transportedPrivateVssShareProofMaterial contains duplicate proofMaterialRoot entries",
            ));
        }
        let chunks = transported_private_vss_share_proof_chunks(proof_material)?;
        let transport_hashes = setup_proof_material_transport_hashes(
            PRIVATE_VSS_SHARE_PROOF_FAMILY,
            &chunks,
            SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        )?;
        verify_transported_private_vss_share_proof_material_hashes(
            proof_material,
            &transport_hashes,
        )?;
        matching_chunks = Some(chunks);
    }

    matching_chunks.ok_or_else(|| {
        invalid_private_vss_share_proof(
            "transportedPrivateVssShareProofMaterial is missing the requested proofMaterialRoot",
        )
    })
}

fn verify_transported_private_vss_share_proof_material_set_header(
    value: &Value,
) -> CanonicalResult<()> {
    for (field_name, expected_value) in [
        (
            "objectType",
            PRIVATE_VSS_SHARE_PROOF_TRANSPORT_SET_OBJECT_TYPE,
        ),
        ("proofFamily", PRIVATE_VSS_SHARE_PROOF_FAMILY),
    ] {
        if value.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Err(invalid_private_vss_share_proof(format!(
                "transportedPrivateVssShareProofMaterial.{field_name} must be {expected_value}"
            )));
        }
    }
    if value.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(invalid_private_vss_share_proof(
            "transportedPrivateVssShareProofMaterial.objectVersion must be 1",
        ));
    }

    Ok(())
}

fn verify_transported_private_vss_share_proof_material_header(
    value: &Value,
) -> CanonicalResult<()> {
    for (field_name, expected_value) in [
        ("objectType", PRIVATE_VSS_SHARE_PROOF_TRANSPORT_OBJECT_TYPE),
        ("proofFamily", PRIVATE_VSS_SHARE_PROOF_FAMILY),
    ] {
        if value.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Err(invalid_private_vss_share_proof(format!(
                "transported private VSS share proof material {field_name} must be {expected_value}"
            )));
        }
    }
    if value.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(invalid_private_vss_share_proof(
            "transported private VSS share proof material objectVersion must be 1",
        ));
    }
    validate_hash(
        value_string(value, "proofMaterialRoot")?,
        "transportedPrivateVssShareProofMaterial.proofMaterialRoot",
    )?;

    Ok(())
}

fn transported_private_vss_share_proof_chunks(value: &Value) -> CanonicalResult<Vec<Vec<u8>>> {
    if value_u64(value, "chunkSizeBytes")? != SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES {
        return Err(invalid_private_vss_share_proof(
            "transported private VSS share proof material chunkSizeBytes must match the setup proof transport parameters",
        ));
    }
    let expected_chunk_count = usize::try_from(value_u64(value, "chunkCount")?).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "transported private VSS share proof material chunkCount does not fit usize",
        )
    })?;
    let Some(chunk_values) = value.get("chunks").and_then(Value::as_array) else {
        return Err(invalid_private_vss_share_proof(
            "transported private VSS share proof material chunks are required",
        ));
    };
    if chunk_values.len() != expected_chunk_count {
        return Err(invalid_private_vss_share_proof(
            "transported private VSS share proof material chunks length must match chunkCount",
        ));
    }
    let mut chunks = Vec::with_capacity(expected_chunk_count);
    for (expected_chunk_index, chunk_value) in chunk_values.iter().enumerate() {
        let observed_chunk_index = value_u64(chunk_value, "chunkIndex")?;
        if observed_chunk_index != expected_chunk_index as u64 {
            return Err(invalid_private_vss_share_proof(
                "transported private VSS share proof chunks must be supplied in ascending chunk-index order",
            ));
        }
        chunks.push(decode_hex(value_string(chunk_value, "bytesHex")?)?);
    }

    Ok(chunks)
}

fn verify_transported_private_vss_share_proof_material_hashes(
    value: &Value,
    transport_hashes: &super::setup_proof::SetupProofMaterialTransportHashes,
) -> CanonicalResult<()> {
    if value_u64(value, "totalByteLength")? != transport_hashes.total_byte_length {
        return Err(invalid_private_vss_share_proof(
            "transported private VSS share proof totalByteLength must match supplied chunks",
        ));
    }
    if value_string(value, "fullObjectHash")? != transport_hashes.full_object_hash.as_str() {
        return Err(invalid_private_vss_share_proof(
            "transported private VSS share proof fullObjectHash must match supplied chunks",
        ));
    }
    if value_string(value, "chunkRoot")? != transport_hashes.chunk_root.as_str() {
        return Err(invalid_private_vss_share_proof(
            "transported private VSS share proof chunkRoot must match supplied chunks",
        ));
    }
    let Some(chunk_hash_values) = value.get("chunkHashes").and_then(Value::as_array) else {
        return Err(invalid_private_vss_share_proof(
            "transported private VSS share proof chunkHashes are required",
        ));
    };
    if chunk_hash_values.len() != transport_hashes.chunk_hashes.len() {
        return Err(invalid_private_vss_share_proof(
            "transported private VSS share proof chunkHashes length must match supplied chunks",
        ));
    }
    for (chunk_hash_value, expected_chunk_hash) in chunk_hash_values
        .iter()
        .zip(transport_hashes.chunk_hashes.iter())
    {
        if chunk_hash_value.as_str() != Some(expected_chunk_hash.as_str()) {
            return Err(invalid_private_vss_share_proof(
                "transported private VSS share proof chunkHashes must match supplied chunks",
            ));
        }
    }

    Ok(())
}

fn private_vss_share_succinct_statement(
    input: &PrivateVssShareSuccinctProofVerificationInput<'_>,
) -> CanonicalResult<TrusteeEvaluationKeyStatement> {
    let context = SuccinctSetupProofContext {
        proof_family: PRIVATE_VSS_SHARE_PROOF_FAMILY.to_string(),
        ceremony_id: value_string(input.setup_context, "ceremonyId")?.to_string(),
        manifest_hash: value_string(input.setup_context, "manifestHash")?.to_string(),
        roster_hash: value_string(input.setup_context, "rosterHash")?.to_string(),
        trustee_identity: input.source_trustee_identity.to_string(),
        trustee_roster_position: input.source_trustee_roster_position,
        setup_epoch: value_string(input.setup_context, "setupEpoch")?.to_string(),
        binding_roots: vec![
            (
                "sourceTrusteeCommitmentRoot".to_string(),
                input.source_trustee_commitment_root.to_string(),
            ),
            (
                "privateEnvelopeAadHash".to_string(),
                input.private_envelope_aad_hash.to_string(),
            ),
            (
                "shareValuesHash".to_string(),
                input.share_values_hash.to_string(),
            ),
        ],
    };
    let statement = TrusteeEvaluationKeyStatement {
        context,
        ring_degree: input.ring_degree,
        keys: Vec::new(),
        same_secret_linkage: None,
        private_vss_share: Some(PrivateVssShareStatement {
            public_matrix_seed_hash: input.public_matrix_seed_hash.to_string(),
            private_envelope_aad_hash: input.private_envelope_aad_hash.to_string(),
            source_trustee_identity: input.source_trustee_identity.to_string(),
            source_trustee_roster_position: input.source_trustee_roster_position,
            recipient_identity: input.recipient_identity.to_string(),
            recipient_roster_position: input.recipient_roster_position,
            source_trustee_commitment_root: input.source_trustee_commitment_root.to_string(),
            source_rns_limb_index: input.rns_limb_index,
            source_message_modulus: input.rns_prime,
            share_values_hash: input.share_values_hash.to_string(),
            share_values: input.share_values.to_vec(),
            coefficient_commitment_roots: input.coefficient_commitment_roots.to_vec(),
            coefficient_commitments: input.coefficient_commitments.to_vec(),
        }),
    };
    statement.validate_shape()?;

    Ok(statement)
}

fn private_vss_share_succinct_statement_value(
    input: &PrivateVssShareSuccinctProofVerificationInput<'_>,
    statement: &TrusteeEvaluationKeyStatement,
) -> CanonicalResult<Value> {
    let coefficient_commitment_roots = input
        .coefficient_commitment_roots
        .iter()
        .enumerate()
        .map(|(coefficient_index, commitment_root)| {
            json!({
                "rnsLimbIndex": input.rns_limb_index,
                "rnsPrime": input.rns_prime,
                "shamirCoefficientIndex": coefficient_index,
                "commitmentRoot": commitment_root,
            })
        })
        .collect::<Vec<_>>();
    let setup_proof_binding =
        super::setup_proof::setup_proof_record_binding_value(&setup_parameters_hash()?)?;
    let carry_bound = private_vss_share_lifted_carry_bound(
        input.recipient_roster_position,
        input.coefficient_commitments.len(),
    )?;

    Ok(json!({
        "objectType": "PrivateVssShareSuccinctProofStatement",
        "objectVersion": 1,
        "setupProofBinding": setup_proof_binding,
        "proofFamily": PRIVATE_VSS_SHARE_PROOF_FAMILY,
        "setupContext": input.setup_context,
        "publicMatrixSeedHash": input.public_matrix_seed_hash,
        "privateEnvelopeAadHash": input.private_envelope_aad_hash,
        "sourceTrusteeIdentity": input.source_trustee_identity,
        "sourceTrusteeRosterPosition": input.source_trustee_roster_position,
        "recipientIdentity": input.recipient_identity,
        "recipientRosterPosition": input.recipient_roster_position,
        "sourceTrusteeCommitmentRoot": input.source_trustee_commitment_root,
        "rnsLimbIndex": input.rns_limb_index,
        "rnsPrime": input.rns_prime,
        "ringDegree": input.ring_degree,
        "shareValuesHash": input.share_values_hash,
        "coefficientCommitmentRoots": coefficient_commitment_roots,
        "recipientTrusteePoint": canonical_trustee_point(
            usize::try_from(input.recipient_roster_position).map_err(|_| {
                invalid_private_vss_share_proof("private VSS recipient roster position does not fit usize")
            })?,
            input.rns_prime,
        )?,
        "succinctStatementHash": to_hex(&statement.statement_hash()),
        "relation": "for hidden Shamir coefficient polynomials F_k and hidden carry v, sum_k alpha^k F_k = sigma + q_l*v over lifted integers while every F_k opens the published setup commitment",
        "carryBound": carry_bound,
    }))
}

pub(super) fn private_vss_share_succinct_proof_material_root(
    statement_hash_hex: &str,
    proof_bytes_hash: &str,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "PrivateVssShareSuccinctProofMaterial",
        "objectVersion": 1,
        "proofFamily": PRIVATE_VSS_SHARE_PROOF_FAMILY,
        "proofBytesEncoding": "embedded-binary-proof-bytes-hex",
        "statementHash": statement_hash_hex,
        "proofBytesHash": proof_bytes_hash,
    }))
}

fn private_vss_share_succinct_transported_proof_material_root(
    statement_hash_hex: &str,
    proof_bytes_hash: &str,
    transport_hashes: &super::setup_proof::SetupProofMaterialTransportHashes,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "PrivateVssShareTransportedSuccinctProofMaterial",
        "objectVersion": 1,
        "proofFamily": PRIVATE_VSS_SHARE_PROOF_FAMILY,
        "proofBytesEncoding": SETUP_PROOF_MATERIAL_ENCODING,
        "statementHash": statement_hash_hex,
        "proofBytesHash": proof_bytes_hash,
        "proofChunkSizeBytes": SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        "proofChunkCount": transport_hashes.chunk_hashes.len(),
        "proofTotalByteLength": transport_hashes.total_byte_length,
        "proofFullObjectHash": transport_hashes.full_object_hash.as_str(),
        "proofChunkRoot": transport_hashes.chunk_root.as_str(),
        "proofChunkHashes": transport_hashes
            .chunk_hashes
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    }))
}

fn private_vss_share_lifted_carry_bound(
    recipient_roster_position: u64,
    coefficient_count: usize,
) -> CanonicalResult<i128> {
    let trustee_point = recipient_roster_position
        .checked_add(1)
        .ok_or_else(|| invalid_private_vss_share_proof("private VSS trustee point overflowed"))?;
    trustee_point_powers_i128(trustee_point, coefficient_count)?
        .into_iter()
        .try_fold(0_i128, |accumulator, power| {
            accumulator.checked_add(power).ok_or_else(|| {
                invalid_private_vss_share_proof("private VSS carry bound overflowed")
            })
        })
}

fn trustee_point_powers_i128(
    trustee_point: u64,
    coefficient_count: usize,
) -> CanonicalResult<Vec<i128>> {
    let mut powers = Vec::with_capacity(coefficient_count);
    let mut power = 1_i128;
    for _ in 0..coefficient_count {
        powers.push(power);
        power = power
            .checked_mul(i128::from(trustee_point))
            .ok_or_else(|| {
                invalid_private_vss_share_proof("private VSS trustee point power overflowed")
            })?;
    }

    Ok(powers)
}

fn checked_i128_sum_with_extra(values: &[i128], extra: i128) -> CanonicalResult<i128> {
    values.iter().try_fold(extra, |accumulator, value| {
        accumulator.checked_add(*value).ok_or_else(|| {
            invalid_private_vss_share_proof("private VSS lifted relation sum overflowed")
        })
    })
}

fn value_string<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a str> {
    value
        .get(field_name)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_private_vss_share_proof(format!("{field_name} must be a string")))
}

fn value_u64(value: &Value, field_name: &str) -> CanonicalResult<u64> {
    value
        .get(field_name)
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid_private_vss_share_proof(format!("{field_name} must be a u64")))
}

fn expect_string_field(
    value: &Value,
    field_name: &str,
    expected: &str,
    message: &'static str,
) -> CanonicalResult<()> {
    if value.get(field_name).and_then(Value::as_str) != Some(expected) {
        return Err(invalid_private_vss_share_proof(message));
    }

    Ok(())
}

fn validate_hash(hash: &str, field_name: &str) -> CanonicalResult<()> {
    if hash.len() == 128
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }

    Err(invalid_private_vss_share_proof(format!(
        "{field_name} must be a lowercase 512-bit hex protocol hash"
    )))
}

fn invalid_private_vss_share_proof(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

pub(super) fn private_vss_share_succinct_proof_record(
    input: PrivateVssShareSuccinctProofGenerationInput<'_>,
) -> CanonicalResult<Value> {
    let empty_proof_record = Value::Null;
    let verification_input = PrivateVssShareSuccinctProofVerificationInput {
        setup_context: input.setup_context,
        public_matrix_seed_hash: input.public_matrix_seed_hash,
        private_envelope_aad_hash: input.private_envelope_aad_hash,
        source_trustee_identity: input.source_trustee_identity,
        source_trustee_roster_position: input.source_trustee_roster_position,
        recipient_identity: input.recipient_identity,
        recipient_roster_position: input.recipient_roster_position,
        source_trustee_commitment_root: input.source_trustee_commitment_root,
        rns_limb_index: input.rns_limb_index,
        rns_prime: input.rns_prime,
        ring_degree: input.ring_degree,
        coefficient_commitment_roots: input.coefficient_commitment_roots,
        share_values: input.share_values,
        share_values_hash: input.share_values_hash,
        coefficient_commitments: input.coefficient_commitments,
        proof_record: &empty_proof_record,
        transported_proof_material: None,
    };
    validate_private_vss_share_statement_material(&verification_input)?;
    validate_private_vss_share_witness(&input)?;
    validate_private_vss_share_proof_randomness_seed(input.proof_randomness_seed_hex)?;
    let statement = private_vss_share_succinct_statement(&verification_input)?;
    let statement_value =
        private_vss_share_succinct_statement_value(&verification_input, &statement)?;
    let proof_statement_root = derive_canonical_object_hash(&statement_value)?;
    let statement_hash_hex = to_hex(&statement.statement_hash());
    let witness = TrusteeEvaluationKeyWitness {
        secret_coefficients: Vec::new(),
        error_coefficients_by_key: Vec::new(),
        negative_indicator_coefficients: Vec::new(),
        opening_randomness_by_limb: Vec::new(),
        private_vss_coefficient_messages_by_shamir_index: input
            .witness
            .coefficient_messages_by_shamir_index
            .iter()
            .map(|messages| {
                messages
                    .iter()
                    .map(|value| {
                        i64::try_from(*value).map_err(|_| {
                            invalid_private_vss_share_proof(
                                "private VSS coefficient message does not fit i64",
                            )
                        })
                    })
                    .collect()
            })
            .collect::<CanonicalResult<Vec<Vec<i64>>>>()?,
        private_vss_opening_randomness_by_shamir_index: input
            .witness
            .opening_randomness_by_shamir_index
            .iter()
            .map(|columns| {
                columns
                    .iter()
                    .map(|column| {
                        column
                            .iter()
                            .map(|value| {
                                i64::try_from(*value).map_err(|_| {
                                    invalid_private_vss_share_proof(
                                        "private VSS opening randomness does not fit i64",
                                    )
                                })
                            })
                            .collect()
                    })
                    .collect()
            })
            .collect::<CanonicalResult<Vec<Vec<Vec<i64>>>>>()?,
        private_vss_carry_witnesses: input
            .witness
            .carry_witnesses
            .iter()
            .map(|value| {
                i64::try_from(*value).map_err(|_| {
                    invalid_private_vss_share_proof("private VSS carry witness does not fit i64")
                })
            })
            .collect::<CanonicalResult<Vec<i64>>>()?,
    };
    let proof = prove_evaluation_key_share(&statement, &witness, input.proof_randomness_seed_hex)?;
    let proof_bytes = encode_trustee_evaluation_key_proof(&proof);
    let proof_bytes_hash = private_vss_share_succinct_proof_bytes_hash(&proof_bytes);
    let proof_material_root =
        private_vss_share_succinct_proof_material_root(&statement_hash_hex, &proof_bytes_hash)?;
    Ok(json!({
        "objectType": "PrivateVssShareProof",
        "objectVersion": 1,
        "proofFamily": PRIVATE_VSS_SHARE_PROOF_FAMILY,
        "proofBytesEncoding": "embedded-binary-proof-bytes-hex",
        "proofStatementRoot": proof_statement_root,
        "statementHash": statement_hash_hex,
        "proofBytesHash": proof_bytes_hash,
        "proofMaterialRoot": proof_material_root,
        "proofBytesHex": to_hex(&proof_bytes),
    }))
}

fn validate_private_vss_share_witness(
    input: &PrivateVssShareSuccinctProofGenerationInput<'_>,
) -> CanonicalResult<()> {
    if input.witness.coefficient_messages_by_shamir_index.len()
        != input.coefficient_commitments.len()
        || input.witness.opening_randomness_by_shamir_index.len()
            != input.coefficient_commitments.len()
        || input.witness.carry_witnesses.len() != input.ring_degree
    {
        return Err(invalid_private_vss_share_proof(
            "private VSS proof witness shape does not match statement material",
        ));
    }
    for (coefficient_index, (coefficient_messages, opening_randomness)) in input
        .witness
        .coefficient_messages_by_shamir_index
        .iter()
        .zip(input.witness.opening_randomness_by_shamir_index.iter())
        .enumerate()
    {
        if coefficient_messages.len() != input.ring_degree
            || coefficient_messages
                .iter()
                .any(|coefficient| *coefficient >= input.rns_prime)
            || opening_randomness.len() != SETUP_COMMITMENT_RANDOMNESS_WIDTH
            || opening_randomness
                .iter()
                .any(|column| column.len() != input.ring_degree)
        {
            return Err(invalid_private_vss_share_proof(format!(
                "private VSS proof witness for Shamir coefficient {coefficient_index} has the wrong shape"
            )));
        }
    }
    verify_private_vss_share_witness_relation(
        input.rns_prime,
        input.recipient_roster_position,
        input.share_values,
        &input.witness.coefficient_messages_by_shamir_index,
        &input.witness.carry_witnesses,
    )
}

fn validate_private_vss_share_proof_randomness_seed(seed_hex: &str) -> CanonicalResult<()> {
    if seed_hex.len() != 128
        || !seed_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid_private_vss_share_proof(
            "private VSS proofRandomnessSeedHex must be lowercase 512-bit hex CSPRNG seed material",
        ));
    }

    Ok(())
}

fn verify_private_vss_share_witness_relation(
    rns_prime: u64,
    recipient_roster_position: u64,
    share_values: &[u64],
    coefficient_messages_by_shamir_index: &[Vec<u64>],
    carry_witnesses: &[i128],
) -> CanonicalResult<()> {
    let trustee_point = canonical_trustee_point(
        usize::try_from(recipient_roster_position).map_err(|_| {
            invalid_private_vss_share_proof(
                "private VSS recipient roster position does not fit usize",
            )
        })?,
        rns_prime,
    )?;
    let trustee_point_powers =
        trustee_point_powers_i128(trustee_point, coefficient_messages_by_shamir_index.len())?;
    for coefficient_index in 0..share_values.len() {
        let weighted_messages = coefficient_messages_by_shamir_index
            .iter()
            .zip(trustee_point_powers.iter())
            .map(|(coefficient_messages, trustee_point_power)| {
                trustee_point_power
                    .checked_mul(i128::from(coefficient_messages[coefficient_index]))
                    .ok_or_else(|| {
                        invalid_private_vss_share_proof(
                            "private VSS witness message relation overflowed",
                        )
                    })
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        // Integer-lift relation: the q_l * carry term vanishes in the source field (q_l == 0 there) but is bound by the other commitment-modulus fields, which forces the unique integer lift; the recipient point reuses roster_position + 1.
        let carry_term = i128::from(rns_prime)
            .checked_mul(carry_witnesses[coefficient_index])
            .and_then(i128::checked_neg)
            .ok_or_else(|| {
                invalid_private_vss_share_proof("private VSS witness carry overflowed")
            })?;
        if checked_i128_sum_with_extra(&weighted_messages, carry_term)?
            != i128::from(share_values[coefficient_index])
        {
            return Err(invalid_private_vss_share_proof(format!(
                "private VSS witness relation failed at coefficient {coefficient_index}"
            )));
        }
    }

    Ok(())
}
