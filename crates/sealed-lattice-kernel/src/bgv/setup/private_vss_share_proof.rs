use serde_json::{Value, json};

use crate::{
    bgv::profile::{DATA_PRIMES, POLYNOMIAL_DEGREE},
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::{canonical_json, derive_protocol_hash, hash512, hash512_hex, to_hex},
    transcript_core::decode_hex,
};

use super::{
    accepted_setup::{COLLECTIVE_BGV_SETUP_PROFILE_ID, setup_proof_profile_hash},
    commitment::{
        SETUP_COMMITMENT_PROFILE_ID, SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND,
        SETUP_COMMITMENT_RANDOMNESS_WIDTH, SetupCommitmentLimb, SetupCommitmentValue,
        linear_combination_setup_commitments, setup_commitment_modulus_product,
        setup_commitment_root, verify_setup_lifted_commitment_opening,
    },
    setup_proof::SETUP_PROOF_PROFILE_ID,
    setup_proof::{
        SETUP_PROOF_MATERIAL_ENCODING, SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        SetupProofMaterialReferenceInput, setup_proof_material_reference_root,
        setup_proof_material_transport_hashes,
    },
    sharing::canonical_trustee_point,
};

const PRIVATE_VSS_SHARE_LNP_PROOF_MAGIC: &[u8; 8] = b"SLVSLNP1";
const PRIVATE_VSS_SHARE_LNP_SCALAR_CHALLENGE_DOMAIN: &str =
    "sealed-lattice/setup/private-vss-share/lnp-scalar-challenge-v1";
const PRIVATE_VSS_SHARE_LNP_COMMITMENT_HASH_DOMAIN: &str =
    "sealed-lattice/setup/private-vss-share/lnp-relation-commitment-v1";
const PRIVATE_VSS_SHARE_LNP_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice/setup/private-vss-share/lnp-proof-bytes-v1";
const PRIVATE_VSS_SHARE_MESSAGE_MASK_BITS: usize = 32;
const PRIVATE_VSS_SHARE_CARRY_MASK_BITS: usize = 64;
const PRIVATE_VSS_SHARE_RANDOMNESS_MASK_BITS: usize = 80;
const PRIVATE_VSS_SHARE_SCALAR_CHALLENGE_BITS: usize = 32;
const PRIVATE_VSS_SHARE_EMBEDDED_PROOF_BYTES_ENCODING: &str = "embedded-binary-proof-bytes-hex";
const PRIVATE_VSS_SHARE_PROOF_TRANSPORT_SET_OBJECT_TYPE: &str =
    "SetupTransportedPrivateVssShareProofMaterialSet";
const PRIVATE_VSS_SHARE_PROOF_TRANSPORT_OBJECT_TYPE: &str =
    "SetupTransportedPrivateVssShareProofMaterial";

pub(super) const PRIVATE_VSS_SHARE_PROOF_PROFILE_ID: &str =
    "sealed-lattice-private-vss-share-proof-lnp-v1";
pub(super) const PRIVATE_VSS_SHARE_PROOF_FAMILY: &str = "vss-opening-carry";
pub(super) const PRIVATE_VSS_SHARE_LNP_PROOF_VERIFICATION_STATUS: &str =
    "lnp-private-vss-share-relation-verified-review-gated";
pub(super) const PRIVATE_VSS_SHARE_LNP_PROOF_MODEL_STATUS: &str = "pinned LNP tbox proof bytes, setup-proof challenge domain, binary proof-material schema, hidden coefficient opening responses, hidden carry responses, carry-aware VSS share algebra, and fixed response bounds verified; external AB-DLOP/LNP soundness and zero-knowledge review remain required before claim-bearing VSS acceptance";

pub(super) struct PrivateVssShareLnpProofVerificationInput<'a> {
    pub(super) setup_context: &'a Value,
    pub(super) public_matrix_seed_hash: &'a str,
    pub(super) private_envelope_aad_hash: &'a str,
    pub(super) dealer_identity: &'a str,
    pub(super) dealer_roster_position: u64,
    pub(super) recipient_identity: &'a str,
    pub(super) recipient_roster_position: u64,
    pub(super) dealer_commitment_root: &'a str,
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

pub(super) struct PrivateVssShareLnpProofVerification {
    pub(super) proof_size_bytes: usize,
    pub(super) proof_bytes_hash: String,
    pub(super) proof_statement_root: String,
    pub(super) proof_material_root: String,
    pub(super) statement_hash_hex: String,
    pub(super) relation_commitment_hash_hex: String,
    pub(super) tbox_commitment_prefix_hash: String,
    pub(super) challenge: u64,
}

pub(super) struct PrivateVssShareLnpProofWitness {
    pub(super) coefficient_messages_by_shamir_index: Vec<Vec<u64>>,
    pub(super) opening_randomness_by_shamir_index: Vec<Vec<Vec<i128>>>,
    pub(super) carry_witnesses: Vec<i128>,
}

#[derive(Clone, Copy)]
pub(super) struct PrivateVssShareLnpProofGenerationInput<'a> {
    pub(super) setup_context: &'a Value,
    pub(super) public_matrix_seed_hash: &'a str,
    pub(super) private_envelope_aad_hash: &'a str,
    pub(super) dealer_identity: &'a str,
    pub(super) dealer_roster_position: u64,
    pub(super) recipient_identity: &'a str,
    pub(super) recipient_roster_position: u64,
    pub(super) dealer_commitment_root: &'a str,
    pub(super) rns_limb_index: usize,
    pub(super) rns_prime: u64,
    pub(super) ring_degree: usize,
    pub(super) coefficient_commitment_roots: &'a [String],
    pub(super) share_values: &'a [u64],
    pub(super) share_values_hash: &'a str,
    pub(super) coefficient_commitments: &'a [SetupCommitmentValue],
    pub(super) witness: &'a PrivateVssShareLnpProofWitness,
    pub(super) proof_randomness_seed_hex: &'a str,
}

struct ParsedPrivateVssShareLnpProof {
    challenge: u64,
    carry_relation_commitments: Vec<i128>,
    coefficient_relation_commitments: Vec<SetupCommitmentValue>,
    message_responses_by_coefficient: Vec<Vec<i128>>,
    randomness_responses_by_coefficient: Vec<Vec<Vec<i128>>>,
    carry_responses: Vec<i128>,
    tbox_proof_bytes: Vec<u8>,
    tbox_commitment_prefix_hash: String,
    parameter_profile_hash_hex: String,
}

pub(super) fn private_vss_share_lnp_relation_proof_bytes_hash(proof_bytes: &[u8]) -> String {
    hash512_hex(
        PRIVATE_VSS_SHARE_LNP_PROOF_BYTES_HASH_DOMAIN,
        &[proof_bytes],
    )
}

pub(super) fn verify_private_vss_share_lnp_relation_proof(
    input: PrivateVssShareLnpProofVerificationInput<'_>,
) -> CanonicalResult<PrivateVssShareLnpProofVerification> {
    validate_private_vss_share_statement_material(&input)?;
    validate_private_vss_share_proof_record(input.proof_record)?;

    let proof_bytes = private_vss_share_lnp_proof_bytes_from_record(&input)?;
    let proof_size_bytes = proof_bytes.len();
    if input
        .proof_record
        .get("proofSizeBytes")
        .and_then(Value::as_u64)
        != Some(u64::try_from(proof_size_bytes).map_err(|_| {
            invalid_private_vss_share_proof("private VSS share proof byte length does not fit u64")
        })?)
    {
        return Err(invalid_private_vss_share_proof(
            "private VSS share proofSizeBytes must match supplied proof bytes",
        ));
    }
    let proof_bytes_hash = private_vss_share_lnp_relation_proof_bytes_hash(&proof_bytes);
    if value_string(input.proof_record, "proofBytesHash")? != proof_bytes_hash {
        return Err(invalid_private_vss_share_proof(
            "private VSS share proofBytesHash must match supplied proof bytes",
        ));
    }

    let statement_value = private_vss_share_lnp_statement_value(&input)?;
    let proof_statement_root =
        derive_protocol_hash("PrivateVssShareProofStatementRoot", &statement_value)?;
    let statement_hash = private_vss_share_lnp_statement_hash(&statement_value)?;
    let statement_hash_hex = to_hex(&statement_hash);
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

    let parsed_proof = parse_private_vss_share_lnp_relation_proof(
        &proof_bytes,
        &statement_hash,
        input.coefficient_commitments,
    )?;
    let expected_parameter_profile_hash =
        super::setup_proof::private_vss_share_lnp_tbox_parameter_profile_hash()?;
    if parsed_proof.parameter_profile_hash_hex != expected_parameter_profile_hash {
        return Err(invalid_private_vss_share_proof(
            "private VSS share LNP proof is not bound to the accepted tbox parameter profile",
        ));
    }
    let encoded_commitments = encode_private_vss_share_relation_commitments(
        &parsed_proof.carry_relation_commitments,
        &parsed_proof.coefficient_relation_commitments,
    )?;
    let relation_commitment_hash_hex = private_vss_share_lnp_relation_commitment_hash(
        &statement_hash_hex,
        &expected_parameter_profile_hash,
        &parsed_proof.tbox_commitment_prefix_hash,
        &encoded_commitments,
    );
    let recomputed_challenge = private_vss_share_lnp_relation_challenge(
        &statement_hash_hex,
        &relation_commitment_hash_hex,
    )?;
    if parsed_proof.challenge != recomputed_challenge {
        return Err(invalid_private_vss_share_proof(
            "private VSS share LNP scalar challenge does not match its relation transcript",
        ));
    }
    let layout = super::setup_proof::private_vss_share_lnp_tbox_layout();
    super::setup_proof::verify_setup_proof_lnp_tbox_proof_bytes(
        &layout,
        &statement_hash_hex,
        &relation_commitment_hash_hex,
        &parsed_proof.tbox_proof_bytes,
    )?;

    verify_private_vss_share_response_bounds(
        parsed_proof.challenge,
        input.rns_prime,
        input.recipient_roster_position,
        input.coefficient_commitments.len(),
        &parsed_proof.message_responses_by_coefficient,
        &parsed_proof.randomness_responses_by_coefficient,
        &parsed_proof.carry_responses,
    )?;
    verify_private_vss_share_coefficient_opening_responses(
        input.public_matrix_seed_hash,
        input.coefficient_commitments,
        parsed_proof.challenge,
        &parsed_proof.coefficient_relation_commitments,
        &parsed_proof.message_responses_by_coefficient,
        &parsed_proof.randomness_responses_by_coefficient,
    )?;
    verify_private_vss_share_lifted_relation_response(
        input.rns_prime,
        input.recipient_roster_position,
        input.share_values,
        parsed_proof.challenge,
        &parsed_proof.carry_relation_commitments,
        &parsed_proof.message_responses_by_coefficient,
        &parsed_proof.carry_responses,
    )?;

    let proof_material_root = if private_vss_share_lnp_proof_uses_transport(input.proof_record)? {
        value_string(input.proof_record, "proofMaterialRoot")?.to_string()
    } else {
        private_vss_share_lnp_proof_material_root(
            &statement_hash_hex,
            &relation_commitment_hash_hex,
            &parsed_proof.tbox_commitment_prefix_hash,
            proof_size_bytes,
            &proof_bytes_hash,
        )?
    };
    if value_string(input.proof_record, "proofMaterialRoot")? != proof_material_root {
        return Err(invalid_private_vss_share_proof(
            "private VSS share proofMaterialRoot must match the embedded proof material",
        ));
    }
    if value_string(input.proof_record, "relationCommitmentHash")? != relation_commitment_hash_hex
        || value_string(input.proof_record, "tboxCommitmentPrefixHash")?
            != parsed_proof.tbox_commitment_prefix_hash
        || input.proof_record.get("challenge").and_then(Value::as_u64)
            != Some(parsed_proof.challenge)
    {
        return Err(invalid_private_vss_share_proof(
            "private VSS share proof transcript metadata must match verified proof bytes",
        ));
    }

    Ok(PrivateVssShareLnpProofVerification {
        proof_size_bytes,
        proof_bytes_hash,
        proof_statement_root,
        proof_material_root,
        statement_hash_hex,
        relation_commitment_hash_hex,
        tbox_commitment_prefix_hash: parsed_proof.tbox_commitment_prefix_hash,
        challenge: parsed_proof.challenge,
    })
}

fn validate_private_vss_share_statement_material(
    input: &PrivateVssShareLnpProofVerificationInput<'_>,
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
            "private VSS share proof ring degree is outside the selected profile",
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
    if input.coefficient_commitment_roots.len() != input.coefficient_commitments.len()
        || input.coefficient_commitments.len() != 4
    {
        return Err(invalid_private_vss_share_proof(
            "private VSS share proof requires the four first-profile Shamir coefficient commitments",
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
    reject_unexpected_fields(
        proof_record,
        &[
            "objectType",
            "objectVersion",
            "proofProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofBytesEncoding",
            "privateVssShareTboxParameterProfileHash",
            "proofVerificationStatus",
            "proofModelStatus",
            "proofStatementRoot",
            "statementHash",
            "relationCommitmentHash",
            "tboxCommitmentPrefixHash",
            "challenge",
            "proofSizeBytes",
            "proofBytesHash",
            "proofMaterialRoot",
            "proofChunkSizeBytes",
            "proofChunkCount",
            "proofTotalByteLength",
            "proofFullObjectHash",
            "proofChunkRoot",
            "proofChunkHashes",
            "proofBytesHex",
        ],
        "private VSS share proof",
    )?;
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
        "proofProfileId",
        PRIVATE_VSS_SHARE_PROOF_PROFILE_ID,
        "private VSS share proofProfileId does not match the accepted private proof profile",
    )?;
    expect_string_field(
        proof_record,
        "setupProofProfileId",
        SETUP_PROOF_PROFILE_ID,
        "private VSS share setupProofProfileId does not match the accepted setup-proof profile",
    )?;
    expect_string_field(
        proof_record,
        "proofFamily",
        PRIVATE_VSS_SHARE_PROOF_FAMILY,
        "private VSS share proofFamily does not match the VSS opening/carry family",
    )?;
    let proof_bytes_encoding = value_string(proof_record, "proofBytesEncoding")?;
    match proof_bytes_encoding {
        PRIVATE_VSS_SHARE_EMBEDDED_PROOF_BYTES_ENCODING => {
            if private_vss_share_lnp_proof_has_transport_reference(proof_record) {
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
    expect_string_field(
        proof_record,
        "privateVssShareTboxParameterProfileHash",
        &super::setup_proof::private_vss_share_lnp_tbox_parameter_profile_hash()?,
        "private VSS share proof tbox parameter profile hash does not match the accepted profile",
    )?;
    expect_string_field(
        proof_record,
        "proofVerificationStatus",
        PRIVATE_VSS_SHARE_LNP_PROOF_VERIFICATION_STATUS,
        "private VSS share proofVerificationStatus does not match the accepted verifier status",
    )?;
    expect_string_field(
        proof_record,
        "proofModelStatus",
        PRIVATE_VSS_SHARE_LNP_PROOF_MODEL_STATUS,
        "private VSS share proofModelStatus does not match the accepted verifier model status",
    )?;
    for field_name in [
        "proofStatementRoot",
        "statementHash",
        "relationCommitmentHash",
        "tboxCommitmentPrefixHash",
        "proofBytesHash",
        "proofMaterialRoot",
    ] {
        validate_hash(value_string(proof_record, field_name)?, field_name)?;
    }
    if proof_record
        .get("challenge")
        .and_then(Value::as_u64)
        .is_none()
    {
        return Err(invalid_private_vss_share_proof(
            "private VSS share proof challenge must be a non-negative integer",
        ));
    }
    if proof_record
        .get("proofSizeBytes")
        .and_then(Value::as_u64)
        .is_none()
    {
        return Err(invalid_private_vss_share_proof(
            "private VSS share proofSizeBytes must be a non-negative integer",
        ));
    }

    Ok(())
}

fn private_vss_share_lnp_proof_uses_transport(proof_record: &Value) -> CanonicalResult<bool> {
    Ok(value_string(proof_record, "proofBytesEncoding")? == SETUP_PROOF_MATERIAL_ENCODING)
}

fn private_vss_share_lnp_proof_has_transport_reference(proof_record: &Value) -> bool {
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

fn private_vss_share_lnp_proof_bytes_from_record(
    input: &PrivateVssShareLnpProofVerificationInput<'_>,
) -> CanonicalResult<Vec<u8>> {
    let proof_record = input.proof_record;
    match value_string(proof_record, "proofBytesEncoding")? {
        PRIVATE_VSS_SHARE_EMBEDDED_PROOF_BYTES_ENCODING => {
            decode_hex(value_string(proof_record, "proofBytesHex")?)
        }
        SETUP_PROOF_MATERIAL_ENCODING => {
            private_vss_share_lnp_transported_proof_bytes_from_record(input)
        }
        _ => Err(invalid_private_vss_share_proof(
            "private VSS share proofBytesEncoding must be embedded-binary-proof-bytes-hex or binary-chunked-proof-bytes",
        )),
    }
}

fn private_vss_share_lnp_transported_proof_bytes_from_record(
    input: &PrivateVssShareLnpProofVerificationInput<'_>,
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
    verify_private_vss_share_lnp_proof_transport_reference(proof_record, &transport_hashes)?;
    let expected_material_root =
        setup_proof_material_reference_root(SetupProofMaterialReferenceInput {
            setup_profile_id: COLLECTIVE_BGV_SETUP_PROFILE_ID,
            proof_family: PRIVATE_VSS_SHARE_PROOF_FAMILY,
            trustee_identity: input.dealer_identity,
            trustee_roster_position: input.dealer_roster_position,
            statement_hash_hex: value_string(proof_record, "statementHash")?,
            relation_commitment_hash_hex: value_string(proof_record, "relationCommitmentHash")?,
            tbox_commitment_prefix_hash: value_string(proof_record, "tboxCommitmentPrefixHash")?,
            proof_size_bytes: value_u64(proof_record, "proofSizeBytes")?,
            proof_bytes_hash: value_string(proof_record, "proofBytesHash")?,
            transport_hashes: &transport_hashes,
        })?;
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

fn verify_private_vss_share_lnp_proof_transport_reference(
    proof_record: &Value,
    transport_hashes: &super::setup_proof::SetupProofMaterialTransportHashes,
) -> CanonicalResult<()> {
    if value_u64(proof_record, "proofChunkSizeBytes")? != SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES {
        return Err(invalid_private_vss_share_proof(
            "private VSS share proofChunkSizeBytes must match the setup proof transport profile",
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
    if value_u64(proof_record, "proofSizeBytes")? != transport_hashes.total_byte_length {
        return Err(invalid_private_vss_share_proof(
            "private VSS share proofSizeBytes must match transported proof byte length",
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
    reject_unexpected_fields(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofMaterials",
        ],
        "transportedPrivateVssShareProofMaterial",
    )?;
    for (field_name, expected_value) in [
        (
            "objectType",
            PRIVATE_VSS_SHARE_PROOF_TRANSPORT_SET_OBJECT_TYPE,
        ),
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
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
    reject_unexpected_fields(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofMaterialRoot",
            "chunkSizeBytes",
            "chunkCount",
            "totalByteLength",
            "fullObjectHash",
            "chunkHashes",
            "chunkRoot",
            "chunks",
        ],
        "transported private VSS share proof material",
    )?;
    for (field_name, expected_value) in [
        ("objectType", PRIVATE_VSS_SHARE_PROOF_TRANSPORT_OBJECT_TYPE),
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
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
            "transported private VSS share proof material chunkSizeBytes must match the setup proof transport profile",
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
        reject_unexpected_fields(
            chunk_value,
            &["chunkIndex", "bytesHex"],
            "transported private VSS share proof chunk",
        )?;
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

fn private_vss_share_lnp_statement_value(
    input: &PrivateVssShareLnpProofVerificationInput<'_>,
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
    let setup_proof_binding = super::setup_proof::setup_proof_record_binding_value(
        COLLECTIVE_BGV_SETUP_PROFILE_ID,
        &setup_proof_profile_hash()?,
    )?;
    let carry_bound = private_vss_share_lifted_carry_bound(
        input.recipient_roster_position,
        input.coefficient_commitments.len(),
    )?;

    Ok(json!({
        "objectType": "PrivateVssShareLnpRelationProofStatement",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "setupProofBinding": setup_proof_binding,
        "commitmentProfileId": SETUP_COMMITMENT_PROFILE_ID,
        "proofProfileId": PRIVATE_VSS_SHARE_PROOF_PROFILE_ID,
        "proofFamily": PRIVATE_VSS_SHARE_PROOF_FAMILY,
        "proofVerificationStatus": PRIVATE_VSS_SHARE_LNP_PROOF_VERIFICATION_STATUS,
        "proofModelStatus": PRIVATE_VSS_SHARE_LNP_PROOF_MODEL_STATUS,
        "privateVssShareTboxParameterProfileHash": super::setup_proof::private_vss_share_lnp_tbox_parameter_profile_hash()?,
        "setupContext": input.setup_context,
        "publicMatrixSeedHash": input.public_matrix_seed_hash,
        "privateEnvelopeAadHash": input.private_envelope_aad_hash,
        "dealerIdentity": input.dealer_identity,
        "dealerRosterPosition": input.dealer_roster_position,
        "recipientIdentity": input.recipient_identity,
        "recipientRosterPosition": input.recipient_roster_position,
        "dealerCommitmentRoot": input.dealer_commitment_root,
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
        "relation": "for hidden Shamir coefficient polynomials F_k and hidden carry v, sum_k alpha^k F_k = sigma + q_l*v over lifted integers while every F_k opens the published setup commitment",
        "carryBound": carry_bound,
        "nonClosure": "external AB-DLOP/LNP soundness and zero-knowledge review plus production proof generation and transported private proof material remain pending",
    }))
}

fn private_vss_share_lnp_statement_hash(statement_value: &Value) -> CanonicalResult<[u8; 64]> {
    let statement_json = canonical_json(statement_value)?;
    Ok(hash512(
        "sealed-lattice/setup/private-vss-share/lnp-relation-statement-v1",
        &[statement_json.as_bytes()],
    ))
}

fn parse_private_vss_share_lnp_relation_proof(
    proof_bytes: &[u8],
    expected_statement_hash: &[u8; 64],
    expected_commitments: &[SetupCommitmentValue],
) -> CanonicalResult<ParsedPrivateVssShareLnpProof> {
    let mut cursor = 0_usize;
    let magic = read_fixed::<8>(proof_bytes, &mut cursor)?;
    if &magic != PRIVATE_VSS_SHARE_LNP_PROOF_MAGIC {
        return Err(invalid_private_vss_share_proof(
            "private VSS share LNP proof has the wrong format marker",
        ));
    }
    let statement_hash = read_fixed::<64>(proof_bytes, &mut cursor)?;
    if &statement_hash != expected_statement_hash {
        return Err(invalid_private_vss_share_proof(
            "private VSS share LNP proof is not bound to this statement",
        ));
    }
    let parameter_profile_hash = read_fixed::<64>(proof_bytes, &mut cursor)?;
    let parameter_profile_hash_hex = to_hex(&parameter_profile_hash);
    let challenge = read_u64(proof_bytes, &mut cursor)?;
    if challenge == 0 || challenge > private_vss_share_scalar_challenge_maximum()? {
        return Err(invalid_private_vss_share_proof(
            "private VSS share LNP scalar challenge is outside the expected range",
        ));
    }
    let tbox_proof_byte_count =
        usize::try_from(read_u64(proof_bytes, &mut cursor)?).map_err(|_| {
            invalid_private_vss_share_proof(
                "private VSS share LNP tbox proof byte count does not fit usize",
            )
        })?;
    if tbox_proof_byte_count == 0 {
        return Err(invalid_private_vss_share_proof(
            "private VSS share LNP proof must include tbox proof bytes",
        ));
    }
    let tbox_proof_bytes = read_bytes(proof_bytes, &mut cursor, tbox_proof_byte_count)?;
    let layout = super::setup_proof::private_vss_share_lnp_tbox_layout();
    let tbox_commitment_prefix_hash =
        super::setup_proof::setup_proof_lnp_tbox_commitment_prefix_hash(
            &layout,
            &tbox_proof_bytes,
        )?;
    let ring_degree = expected_commitments
        .first()
        .map(|commitment| commitment.ring_degree)
        .ok_or_else(|| {
            invalid_private_vss_share_proof("private VSS share proof requires commitments")
        })?;
    let carry_relation_commitments = read_i128_vector(proof_bytes, &mut cursor, ring_degree)?;
    let coefficient_relation_commitments = expected_commitments
        .iter()
        .map(|expected_commitment| {
            read_private_vss_share_relation_commitment(
                proof_bytes,
                &mut cursor,
                expected_commitment,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let message_responses_by_coefficient = expected_commitments
        .iter()
        .map(|_| read_i128_vector(proof_bytes, &mut cursor, ring_degree))
        .collect::<CanonicalResult<Vec<_>>>()?;
    let randomness_responses_by_coefficient = expected_commitments
        .iter()
        .map(|expected_commitment| {
            (0..SETUP_COMMITMENT_RANDOMNESS_WIDTH)
                .map(|_| {
                    read_i128_vector(proof_bytes, &mut cursor, expected_commitment.ring_degree)
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let carry_responses = read_i128_vector(proof_bytes, &mut cursor, ring_degree)?;
    if cursor != proof_bytes.len() {
        return Err(invalid_private_vss_share_proof(
            "private VSS share LNP proof has trailing bytes",
        ));
    }

    Ok(ParsedPrivateVssShareLnpProof {
        challenge,
        carry_relation_commitments,
        coefficient_relation_commitments,
        message_responses_by_coefficient,
        randomness_responses_by_coefficient,
        carry_responses,
        tbox_proof_bytes,
        tbox_commitment_prefix_hash,
        parameter_profile_hash_hex,
    })
}

fn read_private_vss_share_relation_commitment(
    proof_bytes: &[u8],
    cursor: &mut usize,
    expected_commitment: &SetupCommitmentValue,
) -> CanonicalResult<SetupCommitmentValue> {
    let mut limbs = Vec::with_capacity(expected_commitment.limbs.len());
    for expected_limb in &expected_commitment.limbs {
        let mut rows = Vec::with_capacity(expected_limb.rows.len());
        for expected_row in &expected_limb.rows {
            let mut row = Vec::with_capacity(expected_row.len());
            for _ in expected_row {
                let coefficient = read_u64(proof_bytes, cursor)?;
                if coefficient >= expected_limb.modulus {
                    return Err(invalid_private_vss_share_proof(
                        "private VSS share relation commitment coefficient is not canonical",
                    ));
                }
                row.push(coefficient);
            }
            rows.push(row);
        }
        limbs.push(SetupCommitmentLimb {
            commitment_modulus_index: expected_limb.commitment_modulus_index,
            modulus: expected_limb.modulus,
            rows,
        });
    }

    Ok(SetupCommitmentValue {
        source_rns_limb_index: expected_commitment.source_rns_limb_index,
        source_message_modulus: expected_commitment.source_message_modulus,
        shamir_coefficient_index: expected_commitment.shamir_coefficient_index,
        ring_degree: expected_commitment.ring_degree,
        limbs,
    })
}

fn verify_private_vss_share_response_bounds(
    challenge: u64,
    rns_prime: u64,
    recipient_roster_position: u64,
    coefficient_count: usize,
    message_responses_by_coefficient: &[Vec<i128>],
    randomness_responses_by_coefficient: &[Vec<Vec<i128>>],
    carry_responses: &[i128],
) -> CanonicalResult<()> {
    let message_response_bound = private_vss_share_message_response_bound(challenge, rns_prime)?;
    for message_responses in message_responses_by_coefficient {
        for message_response in message_responses {
            if *message_response < 0 || *message_response > message_response_bound {
                return Err(invalid_private_vss_share_proof(
                    "private VSS share message response exceeds the accepted no-wrap bound",
                ));
            }
        }
    }
    let randomness_response_bound = private_vss_share_randomness_response_bound(challenge)?;
    for randomness_responses in randomness_responses_by_coefficient {
        for column in randomness_responses {
            verify_i128_vector_bound(
                column,
                randomness_response_bound,
                "private VSS share opening-randomness response",
            )?;
        }
    }
    let carry_response_bound = private_vss_share_lifted_carry_response_bound(
        challenge,
        recipient_roster_position,
        coefficient_count,
    )?;
    verify_i128_vector_bound(
        carry_responses,
        carry_response_bound,
        "private VSS share carry response",
    )
}

fn verify_private_vss_share_coefficient_opening_responses(
    public_matrix_seed_hash: &str,
    coefficient_commitments: &[SetupCommitmentValue],
    challenge: u64,
    relation_commitments: &[SetupCommitmentValue],
    message_responses_by_coefficient: &[Vec<i128>],
    randomness_responses_by_coefficient: &[Vec<Vec<i128>>],
) -> CanonicalResult<()> {
    if relation_commitments.len() != coefficient_commitments.len()
        || message_responses_by_coefficient.len() != coefficient_commitments.len()
        || randomness_responses_by_coefficient.len() != coefficient_commitments.len()
    {
        return Err(invalid_private_vss_share_proof(
            "private VSS share proof coefficient response count does not match the statement",
        ));
    }
    for (
        coefficient_index,
        (((commitment, relation_commitment), message_response), randomness_response),
    ) in coefficient_commitments
        .iter()
        .zip(relation_commitments.iter())
        .zip(message_responses_by_coefficient.iter())
        .zip(randomness_responses_by_coefficient.iter())
        .enumerate()
    {
        let expected_response_commitment = linear_combination_setup_commitments(&[
            (relation_commitment, 1),
            (commitment, u128::from(challenge)),
        ])?;
        let response_message_coefficients = message_response
            .iter()
            .map(|response| {
                u128::try_from(*response).map_err(|_| {
                    invalid_private_vss_share_proof(
                        "private VSS share message response became negative",
                    )
                })
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        if response_message_coefficients
            .iter()
            .any(|coefficient| *coefficient >= setup_commitment_modulus_product())
        {
            return Err(invalid_private_vss_share_proof(
                "private VSS share message response wraps in the setup commitment modulus product",
            ));
        }
        let response_randomness_bound = private_vss_share_randomness_response_bound(challenge)?;
        verify_setup_lifted_commitment_opening(
            public_matrix_seed_hash,
            &expected_response_commitment,
            &response_message_coefficients,
            randomness_response,
            response_randomness_bound,
        )
        .map_err(|_| {
            invalid_private_vss_share_proof(format!(
                "private VSS share proof commitment response failed for Shamir coefficient {coefficient_index}"
            ))
        })?;
    }

    Ok(())
}

fn verify_private_vss_share_lifted_relation_response(
    rns_prime: u64,
    recipient_roster_position: u64,
    share_values: &[u64],
    challenge: u64,
    carry_relation_commitments: &[i128],
    message_responses_by_coefficient: &[Vec<i128>],
    carry_responses: &[i128],
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
        trustee_point_powers_i128(trustee_point, message_responses_by_coefficient.len())?;
    let ring_degree = share_values.len();
    if carry_relation_commitments.len() != ring_degree
        || carry_responses.len() != ring_degree
        || message_responses_by_coefficient
            .iter()
            .any(|responses| responses.len() != ring_degree)
    {
        return Err(invalid_private_vss_share_proof(
            "private VSS share lifted relation response width does not match the proof ring degree",
        ));
    }
    for coefficient_index in 0..ring_degree {
        let weighted_messages = message_responses_by_coefficient
            .iter()
            .zip(trustee_point_powers.iter())
            .map(|(message_responses, trustee_point_power)| {
                trustee_point_power
                    .checked_mul(message_responses[coefficient_index])
                    .ok_or_else(|| {
                        invalid_private_vss_share_proof(
                            "private VSS share lifted message response overflowed",
                        )
                    })
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        let carry_term = i128::from(rns_prime)
            .checked_mul(carry_responses[coefficient_index])
            .and_then(i128::checked_neg)
            .ok_or_else(|| {
                invalid_private_vss_share_proof(
                    "private VSS share lifted carry response overflowed",
                )
            })?;
        let left_side = checked_i128_sum_with_extra(&weighted_messages, carry_term)?;
        let right_side = carry_relation_commitments[coefficient_index]
            .checked_add(
                i128::from(challenge)
                    .checked_mul(i128::from(share_values[coefficient_index]))
                    .ok_or_else(|| {
                        invalid_private_vss_share_proof(
                            "private VSS share lifted public target overflowed",
                        )
                    })?,
            )
            .ok_or_else(|| {
                invalid_private_vss_share_proof("private VSS share lifted relation overflowed")
            })?;
        if left_side != right_side {
            return Err(invalid_private_vss_share_proof(format!(
                "private VSS share lifted relation failed at coefficient {coefficient_index}"
            )));
        }
    }

    Ok(())
}

fn encode_private_vss_share_relation_commitments(
    carry_relation_commitments: &[i128],
    coefficient_relation_commitments: &[SetupCommitmentValue],
) -> CanonicalResult<Vec<u8>> {
    let carry_byte_count = carry_relation_commitments
        .len()
        .checked_mul(16)
        .ok_or_else(|| {
            invalid_private_vss_share_proof("private VSS carry commitment size overflowed")
        })?;
    let commitment_byte_count =
        coefficient_relation_commitments
            .iter()
            .try_fold(0_usize, |accumulator, commitment| {
                accumulator
                    .checked_add(setup_commitment_value_byte_count(commitment)?)
                    .ok_or_else(|| {
                        invalid_private_vss_share_proof(
                            "private VSS coefficient commitment size overflowed",
                        )
                    })
            })?;
    let mut encoded = Vec::with_capacity(
        carry_byte_count
            .checked_add(commitment_byte_count)
            .ok_or_else(|| {
                invalid_private_vss_share_proof("private VSS commitment size overflowed")
            })?,
    );
    for commitment in carry_relation_commitments {
        encoded.extend_from_slice(&commitment.to_le_bytes());
    }
    for commitment in coefficient_relation_commitments {
        for limb in &commitment.limbs {
            for row in &limb.rows {
                for coefficient in row {
                    encoded.extend_from_slice(&coefficient.to_le_bytes());
                }
            }
        }
    }

    Ok(encoded)
}

fn private_vss_share_lnp_relation_commitment_hash(
    statement_hash_hex: &str,
    parameter_profile_hash_hex: &str,
    tbox_commitment_prefix_hash: &str,
    encoded_commitments: &[u8],
) -> String {
    hash512_hex(
        PRIVATE_VSS_SHARE_LNP_COMMITMENT_HASH_DOMAIN,
        &[
            statement_hash_hex.as_bytes(),
            parameter_profile_hash_hex.as_bytes(),
            tbox_commitment_prefix_hash.as_bytes(),
            encoded_commitments,
        ],
    )
}

fn private_vss_share_lnp_relation_challenge(
    statement_hash_hex: &str,
    relation_commitment_hash_hex: &str,
) -> CanonicalResult<u64> {
    let challenge_coefficients = super::setup_proof::derive_setup_proof_challenge_coefficients(
        PRIVATE_VSS_SHARE_PROOF_FAMILY,
        statement_hash_hex,
        relation_commitment_hash_hex,
        super::setup_proof::SETUP_PROOF_LNP_PROOF_RING_DEGREE,
    )?;
    let mut encoded_challenge = Vec::with_capacity(challenge_coefficients.len() * 8);
    for coefficient in challenge_coefficients {
        encoded_challenge.extend_from_slice(&coefficient.to_le_bytes());
    }
    let mut block_index = 0_u64;
    loop {
        let block_index_bytes = block_index.to_le_bytes();
        let block = hash512(
            PRIVATE_VSS_SHARE_LNP_SCALAR_CHALLENGE_DOMAIN,
            &[
                statement_hash_hex.as_bytes(),
                relation_commitment_hash_hex.as_bytes(),
                &encoded_challenge,
                &block_index_bytes,
            ],
        );
        let mut challenge_bytes = [0_u8; 8];
        challenge_bytes[..4].copy_from_slice(&block[..4]);
        let challenge = u64::from_le_bytes(challenge_bytes);
        if challenge != 0 {
            return Ok(challenge);
        }
        block_index = block_index.checked_add(1).ok_or_else(|| {
            invalid_private_vss_share_proof(
                "private VSS share LNP challenge block index overflowed",
            )
        })?;
    }
}

pub(super) fn private_vss_share_lnp_proof_material_root(
    statement_hash_hex: &str,
    relation_commitment_hash_hex: &str,
    tbox_commitment_prefix_hash: &str,
    proof_size_bytes: usize,
    proof_bytes_hash: &str,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "PrivateVssShareProofMaterialRoot",
        &json!({
            "objectType": "PrivateVssShareEmbeddedProofMaterial",
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
            "proofProfileId": PRIVATE_VSS_SHARE_PROOF_PROFILE_ID,
            "proofFamily": PRIVATE_VSS_SHARE_PROOF_FAMILY,
            "proofBytesEncoding": "embedded-binary-proof-bytes-hex",
            "statementHash": statement_hash_hex,
            "relationCommitmentHash": relation_commitment_hash_hex,
            "tboxCommitmentPrefixHash": tbox_commitment_prefix_hash,
            "proofSizeBytes": proof_size_bytes,
            "proofBytesHash": proof_bytes_hash,
        }),
    )
}

fn private_vss_share_scalar_challenge_maximum() -> CanonicalResult<u64> {
    let challenge_bits = u32::try_from(PRIVATE_VSS_SHARE_SCALAR_CHALLENGE_BITS).map_err(|_| {
        invalid_private_vss_share_proof("private VSS challenge bit count does not fit u32")
    })?;
    1_u64
        .checked_shl(challenge_bits)
        .and_then(|bound| bound.checked_sub(1))
        .ok_or_else(|| invalid_private_vss_share_proof("private VSS challenge bound overflowed"))
}

fn private_vss_share_message_response_bound(
    challenge: u64,
    rns_prime: u64,
) -> CanonicalResult<i128> {
    let mask_bound = mask_magnitude_bound(
        PRIVATE_VSS_SHARE_MESSAGE_MASK_BITS,
        "private VSS share message response",
    )?;
    let witness_bound = i128::from(rns_prime)
        .checked_sub(1)
        .ok_or_else(|| invalid_private_vss_share_proof("private VSS RNS prime underflowed"))?;
    let challenge_term = i128::from(challenge)
        .checked_mul(witness_bound)
        .ok_or_else(|| {
            invalid_private_vss_share_proof("private VSS message response bound overflowed")
        })?;
    let bound = mask_bound.checked_add(challenge_term).ok_or_else(|| {
        invalid_private_vss_share_proof("private VSS message response bound overflowed")
    })?;
    if u128::try_from(bound).map_err(|_| {
        invalid_private_vss_share_proof("private VSS message response bound became negative")
    })? >= setup_commitment_modulus_product()
    {
        return Err(invalid_private_vss_share_proof(
            "private VSS message response bound wraps in the setup commitment modulus product",
        ));
    }

    Ok(bound)
}

fn private_vss_share_randomness_response_bound(challenge: u64) -> CanonicalResult<i128> {
    let mask_bound = mask_magnitude_bound(
        PRIVATE_VSS_SHARE_RANDOMNESS_MASK_BITS,
        "private VSS share opening-randomness response",
    )?;
    let challenge_term = i128::from(challenge)
        .checked_mul(SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND)
        .ok_or_else(|| {
            invalid_private_vss_share_proof("private VSS randomness response bound overflowed")
        })?;
    mask_bound.checked_add(challenge_term).ok_or_else(|| {
        invalid_private_vss_share_proof("private VSS randomness response bound overflowed")
    })
}

fn private_vss_share_lifted_carry_response_bound(
    challenge: u64,
    recipient_roster_position: u64,
    coefficient_count: usize,
) -> CanonicalResult<i128> {
    let mask_bound = mask_magnitude_bound(
        PRIVATE_VSS_SHARE_CARRY_MASK_BITS,
        "private VSS share carry response",
    )?;
    let witness_bound =
        private_vss_share_lifted_carry_bound(recipient_roster_position, coefficient_count)?;
    let challenge_term = i128::from(challenge)
        .checked_mul(witness_bound)
        .ok_or_else(|| {
            invalid_private_vss_share_proof("private VSS carry response bound overflowed")
        })?;
    mask_bound.checked_add(challenge_term).ok_or_else(|| {
        invalid_private_vss_share_proof("private VSS carry response bound overflowed")
    })
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

fn mask_magnitude_bound(mask_bits: usize, label: &str) -> CanonicalResult<i128> {
    let mask_bits = u32::try_from(mask_bits).map_err(|_| {
        invalid_private_vss_share_proof(format!("{label} mask bit count overflowed"))
    })?;
    1_i128
        .checked_shl(mask_bits)
        .and_then(|bound| bound.checked_sub(1))
        .ok_or_else(|| invalid_private_vss_share_proof(format!("{label} mask bound overflowed")))
}

fn setup_commitment_value_byte_count(commitment: &SetupCommitmentValue) -> CanonicalResult<usize> {
    commitment
        .limbs
        .iter()
        .try_fold(0_usize, |accumulator, limb| {
            let limb_count = limb.rows.iter().try_fold(0_usize, |row_accumulator, row| {
                row_accumulator.checked_add(row.len()).ok_or_else(|| {
                    invalid_private_vss_share_proof("private VSS commitment row size overflowed")
                })
            })?;
            accumulator
                .checked_add(limb_count.checked_mul(8).ok_or_else(|| {
                    invalid_private_vss_share_proof("private VSS commitment limb size overflowed")
                })?)
                .ok_or_else(|| {
                    invalid_private_vss_share_proof("private VSS commitment size overflowed")
                })
        })
}

fn verify_i128_vector_bound(
    values: &[i128],
    inclusive_bound: i128,
    label: &str,
) -> CanonicalResult<()> {
    for value in values {
        let absolute_value = value.checked_abs().ok_or_else(|| {
            invalid_private_vss_share_proof(format!("{label} absolute value overflowed"))
        })?;
        if absolute_value > inclusive_bound {
            return Err(invalid_private_vss_share_proof(format!(
                "{label} exceeds the accepted response bound"
            )));
        }
    }

    Ok(())
}

fn checked_i128_sum_with_extra(values: &[i128], extra: i128) -> CanonicalResult<i128> {
    values.iter().try_fold(extra, |accumulator, value| {
        accumulator.checked_add(*value).ok_or_else(|| {
            invalid_private_vss_share_proof("private VSS lifted relation sum overflowed")
        })
    })
}

fn read_i128_vector(
    proof_bytes: &[u8],
    cursor: &mut usize,
    count: usize,
) -> CanonicalResult<Vec<i128>> {
    (0..count)
        .map(|_| {
            let bytes = read_fixed::<16>(proof_bytes, cursor)?;
            Ok(i128::from_le_bytes(bytes))
        })
        .collect()
}

fn read_u64(proof_bytes: &[u8], cursor: &mut usize) -> CanonicalResult<u64> {
    let bytes = read_fixed::<8>(proof_bytes, cursor)?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_fixed<const LENGTH: usize>(
    proof_bytes: &[u8],
    cursor: &mut usize,
) -> CanonicalResult<[u8; LENGTH]> {
    let end = cursor
        .checked_add(LENGTH)
        .ok_or_else(|| invalid_private_vss_share_proof("private VSS proof cursor overflowed"))?;
    let bytes = proof_bytes
        .get(*cursor..end)
        .ok_or_else(|| invalid_private_vss_share_proof("private VSS proof ended early"))?;
    let mut output = [0_u8; LENGTH];
    output.copy_from_slice(bytes);
    *cursor = end;
    Ok(output)
}

fn read_bytes(proof_bytes: &[u8], cursor: &mut usize, length: usize) -> CanonicalResult<Vec<u8>> {
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| invalid_private_vss_share_proof("private VSS proof cursor overflowed"))?;
    let bytes = proof_bytes
        .get(*cursor..end)
        .ok_or_else(|| invalid_private_vss_share_proof("private VSS proof ended early"))?;
    *cursor = end;

    Ok(bytes.to_vec())
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

fn reject_unexpected_fields(
    value: &Value,
    allowed_fields: &[&str],
    label: &str,
) -> CanonicalResult<()> {
    let Some(fields) = value.as_object() else {
        return Err(invalid_private_vss_share_proof(format!(
            "{label} must be a JSON object"
        )));
    };
    if let Some(unexpected_field) = fields
        .keys()
        .find(|field_name| !allowed_fields.contains(&field_name.as_str()))
    {
        return Err(invalid_private_vss_share_proof(format!(
            "{label} contains unexpected field {unexpected_field}"
        )));
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

pub(super) fn generate_private_vss_share_lnp_relation_proof(
    input: PrivateVssShareLnpProofGenerationInput<'_>,
) -> CanonicalResult<Vec<u8>> {
    use super::commitment::compute_setup_commitment;

    let empty_proof_record = Value::Null;
    let verification_input = PrivateVssShareLnpProofVerificationInput {
        setup_context: input.setup_context,
        public_matrix_seed_hash: input.public_matrix_seed_hash,
        private_envelope_aad_hash: input.private_envelope_aad_hash,
        dealer_identity: input.dealer_identity,
        dealer_roster_position: input.dealer_roster_position,
        recipient_identity: input.recipient_identity,
        recipient_roster_position: input.recipient_roster_position,
        dealer_commitment_root: input.dealer_commitment_root,
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

    let statement_value = private_vss_share_lnp_statement_value(&verification_input)?;
    let statement_hash = private_vss_share_lnp_statement_hash(&statement_value)?;
    let statement_hash_hex = to_hex(&statement_hash);
    let parameter_profile_hash =
        super::setup_proof::private_vss_share_lnp_tbox_parameter_profile_hash()?;
    let parameter_profile_hash_bytes = hash_hex_to_fixed_bytes(&parameter_profile_hash)?;
    let layout = super::setup_proof::private_vss_share_lnp_tbox_layout();
    let tbox_prefix =
        encode_private_vss_share_lnp_tbox_prefix(&layout, input.proof_randomness_seed_hex)?;
    let tbox_commitment_prefix_hash =
        super::setup_proof::setup_proof_lnp_tbox_commitment_prefix_hash(&layout, &tbox_prefix)?;

    let message_masks_by_coefficient = input
        .coefficient_commitments
        .iter()
        .enumerate()
        .map(|(coefficient_index, commitment)| {
            (0..commitment.ring_degree)
                .map(|coefficient_position| {
                    sample_private_vss_share_message_mask_i128(
                        &statement_hash,
                        input.proof_randomness_seed_hex,
                        coefficient_index,
                        coefficient_position,
                    )
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let randomness_masks_by_coefficient = input
        .coefficient_commitments
        .iter()
        .enumerate()
        .map(|(coefficient_index, commitment)| {
            (0..SETUP_COMMITMENT_RANDOMNESS_WIDTH)
                .map(|randomness_column_index| {
                    (0..commitment.ring_degree)
                        .map(|coefficient_position| {
                            sample_private_vss_share_mask_i128(
                                &statement_hash,
                                input.proof_randomness_seed_hex,
                                1,
                                coefficient_index,
                                randomness_column_index,
                                coefficient_position,
                            )
                        })
                        .collect::<CanonicalResult<Vec<_>>>()
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let carry_masks = (0..input.ring_degree)
        .map(|coefficient_position| {
            sample_private_vss_share_carry_mask_i128(
                &statement_hash,
                input.proof_randomness_seed_hex,
                coefficient_position,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let trustee_point = canonical_trustee_point(
        usize::try_from(input.recipient_roster_position).map_err(|_| {
            invalid_private_vss_share_proof(
                "private VSS recipient roster position does not fit usize",
            )
        })?,
        input.rns_prime,
    )?;
    let trustee_point_powers =
        trustee_point_powers_i128(trustee_point, input.coefficient_commitments.len())?;
    let carry_relation_commitments = (0..input.ring_degree)
        .map(|coefficient_position| {
            let weighted_masks = message_masks_by_coefficient
                .iter()
                .zip(trustee_point_powers.iter())
                .map(|(message_masks, trustee_point_power)| {
                    trustee_point_power
                        .checked_mul(message_masks[coefficient_position])
                        .ok_or_else(|| {
                            invalid_private_vss_share_proof(
                                "private VSS share lifted mask overflowed",
                            )
                        })
                })
                .collect::<CanonicalResult<Vec<_>>>()?;
            let carry_term = i128::from(input.rns_prime)
                .checked_mul(carry_masks[coefficient_position])
                .and_then(i128::checked_neg)
                .ok_or_else(|| {
                    invalid_private_vss_share_proof("private VSS carry mask overflowed")
                })?;
            checked_i128_sum_with_extra(&weighted_masks, carry_term)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let coefficient_relation_commitments = input
        .coefficient_commitments
        .iter()
        .enumerate()
        .map(|(coefficient_index, commitment)| {
            let mask_message_coefficients = message_masks_by_coefficient[coefficient_index]
                .iter()
                .map(|message_mask| {
                    if *message_mask < 0 {
                        return Err(invalid_private_vss_share_proof(
                            "private VSS message mask became negative",
                        ));
                    }
                    u128::try_from(*message_mask).map_err(|_| {
                        invalid_private_vss_share_proof(
                            "private VSS message mask does not fit u128",
                        )
                    })
                })
                .collect::<CanonicalResult<Vec<_>>>()?;
            compute_setup_commitment(
                input.public_matrix_seed_hash,
                commitment.source_rns_limb_index,
                commitment.source_message_modulus,
                commitment.shamir_coefficient_index,
                &mask_message_coefficients,
                &randomness_masks_by_coefficient[coefficient_index],
                commitment.ring_degree,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let encoded_commitments = encode_private_vss_share_relation_commitments(
        &carry_relation_commitments,
        &coefficient_relation_commitments,
    )?;
    let relation_commitment_hash = private_vss_share_lnp_relation_commitment_hash(
        &statement_hash_hex,
        &parameter_profile_hash,
        &tbox_commitment_prefix_hash,
        &encoded_commitments,
    );
    let challenge =
        private_vss_share_lnp_relation_challenge(&statement_hash_hex, &relation_commitment_hash)?;
    let challenge_coefficients = super::setup_proof::derive_setup_proof_challenge_coefficients(
        PRIVATE_VSS_SHARE_PROOF_FAMILY,
        &statement_hash_hex,
        &relation_commitment_hash,
        layout.proof_ring_degree,
    )?;
    let mut tbox_proof_bytes = tbox_prefix;
    encode_private_vss_share_lnp_tbox_suffix(
        &mut tbox_proof_bytes,
        &layout,
        &challenge_coefficients,
    )?;

    let message_responses_by_coefficient = message_masks_by_coefficient
        .iter()
        .zip(input.witness.coefficient_messages_by_shamir_index.iter())
        .map(|(message_masks, coefficient_messages)| {
            message_masks
                .iter()
                .zip(coefficient_messages.iter())
                .map(|(message_mask, coefficient_message)| {
                    message_mask
                        .checked_add(
                            i128::from(challenge)
                                .checked_mul(i128::from(*coefficient_message))
                                .ok_or_else(|| {
                                    invalid_private_vss_share_proof(
                                        "private VSS message response overflowed",
                                    )
                                })?,
                        )
                        .ok_or_else(|| {
                            invalid_private_vss_share_proof(
                                "private VSS message response overflowed",
                            )
                        })
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let randomness_responses_by_coefficient = randomness_masks_by_coefficient
        .iter()
        .zip(input.witness.opening_randomness_by_shamir_index.iter())
        .map(|(randomness_masks, opening_randomness)| {
            randomness_masks
                .iter()
                .zip(opening_randomness.iter())
                .map(|(mask_column, witness_column)| {
                    mask_column
                        .iter()
                        .zip(witness_column.iter())
                        .map(|(mask, witness_value)| {
                            mask.checked_add(
                                i128::from(challenge)
                                    .checked_mul(*witness_value)
                                    .ok_or_else(|| {
                                        invalid_private_vss_share_proof(
                                            "private VSS randomness response overflowed",
                                        )
                                    })?,
                            )
                            .ok_or_else(|| {
                                invalid_private_vss_share_proof(
                                    "private VSS randomness response overflowed",
                                )
                            })
                        })
                        .collect::<CanonicalResult<Vec<_>>>()
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let carry_responses = carry_masks
        .iter()
        .zip(input.witness.carry_witnesses.iter())
        .map(|(carry_mask, carry_witness)| {
            carry_mask
                .checked_add(
                    i128::from(challenge)
                        .checked_mul(*carry_witness)
                        .ok_or_else(|| {
                            invalid_private_vss_share_proof("private VSS carry response overflowed")
                        })?,
                )
                .ok_or_else(|| {
                    invalid_private_vss_share_proof("private VSS carry response overflowed")
                })
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    let mut proof_bytes = Vec::new();
    proof_bytes.extend_from_slice(PRIVATE_VSS_SHARE_LNP_PROOF_MAGIC);
    proof_bytes.extend_from_slice(&statement_hash);
    proof_bytes.extend_from_slice(&parameter_profile_hash_bytes);
    proof_bytes.extend_from_slice(&challenge.to_le_bytes());
    proof_bytes.extend_from_slice(
        &u64::try_from(tbox_proof_bytes.len())
            .map_err(|_| {
                invalid_private_vss_share_proof(
                    "private VSS LNP tbox proof byte count does not fit u64",
                )
            })?
            .to_le_bytes(),
    );
    proof_bytes.extend_from_slice(&tbox_proof_bytes);
    write_i128_vector(&mut proof_bytes, &carry_relation_commitments);
    for commitment in &coefficient_relation_commitments {
        for limb in &commitment.limbs {
            for row in &limb.rows {
                for coefficient in row {
                    proof_bytes.extend_from_slice(&coefficient.to_le_bytes());
                }
            }
        }
    }
    for message_response in &message_responses_by_coefficient {
        write_i128_vector(&mut proof_bytes, message_response);
    }
    for randomness_response in &randomness_responses_by_coefficient {
        for column in randomness_response {
            write_i128_vector(&mut proof_bytes, column);
        }
    }
    write_i128_vector(&mut proof_bytes, &carry_responses);

    Ok(proof_bytes)
}

pub(super) fn private_vss_share_lnp_proof_record(
    input: PrivateVssShareLnpProofGenerationInput<'_>,
) -> CanonicalResult<Value> {
    let proof_bytes = generate_private_vss_share_lnp_relation_proof(input)?;
    let empty_proof_record = Value::Null;
    let verification_input = PrivateVssShareLnpProofVerificationInput {
        setup_context: input.setup_context,
        public_matrix_seed_hash: input.public_matrix_seed_hash,
        private_envelope_aad_hash: input.private_envelope_aad_hash,
        dealer_identity: input.dealer_identity,
        dealer_roster_position: input.dealer_roster_position,
        recipient_identity: input.recipient_identity,
        recipient_roster_position: input.recipient_roster_position,
        dealer_commitment_root: input.dealer_commitment_root,
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
    let statement_value = private_vss_share_lnp_statement_value(&verification_input)?;
    let proof_statement_root =
        derive_protocol_hash("PrivateVssShareProofStatementRoot", &statement_value)?;
    let statement_hash = private_vss_share_lnp_statement_hash(&statement_value)?;
    let statement_hash_hex = to_hex(&statement_hash);
    let parsed_proof = parse_private_vss_share_lnp_relation_proof(
        &proof_bytes,
        &statement_hash,
        input.coefficient_commitments,
    )?;
    let parameter_profile_hash =
        super::setup_proof::private_vss_share_lnp_tbox_parameter_profile_hash()?;
    let encoded_commitments = encode_private_vss_share_relation_commitments(
        &parsed_proof.carry_relation_commitments,
        &parsed_proof.coefficient_relation_commitments,
    )?;
    let relation_commitment_hash = private_vss_share_lnp_relation_commitment_hash(
        &statement_hash_hex,
        &parameter_profile_hash,
        &parsed_proof.tbox_commitment_prefix_hash,
        &encoded_commitments,
    );
    let proof_bytes_hash = private_vss_share_lnp_relation_proof_bytes_hash(&proof_bytes);
    let proof_material_root = private_vss_share_lnp_proof_material_root(
        &statement_hash_hex,
        &relation_commitment_hash,
        &parsed_proof.tbox_commitment_prefix_hash,
        proof_bytes.len(),
        &proof_bytes_hash,
    )?;

    Ok(json!({
        "objectType": "PrivateVssShareProof",
        "objectVersion": 1,
        "proofProfileId": PRIVATE_VSS_SHARE_PROOF_PROFILE_ID,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "proofFamily": PRIVATE_VSS_SHARE_PROOF_FAMILY,
        "proofBytesEncoding": "embedded-binary-proof-bytes-hex",
        "privateVssShareTboxParameterProfileHash": parameter_profile_hash,
        "proofVerificationStatus": PRIVATE_VSS_SHARE_LNP_PROOF_VERIFICATION_STATUS,
        "proofModelStatus": PRIVATE_VSS_SHARE_LNP_PROOF_MODEL_STATUS,
        "proofStatementRoot": proof_statement_root,
        "statementHash": statement_hash_hex,
        "relationCommitmentHash": relation_commitment_hash,
        "tboxCommitmentPrefixHash": parsed_proof.tbox_commitment_prefix_hash,
        "challenge": parsed_proof.challenge,
        "proofSizeBytes": proof_bytes.len(),
        "proofBytesHash": proof_bytes_hash,
        "proofMaterialRoot": proof_material_root,
        "proofBytesHex": to_hex(&proof_bytes),
    }))
}

fn validate_private_vss_share_witness(
    input: &PrivateVssShareLnpProofGenerationInput<'_>,
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

fn hash_hex_to_fixed_bytes(hash_hex: &str) -> CanonicalResult<[u8; 64]> {
    if hash_hex.len() != 128 {
        return Err(invalid_private_vss_share_proof(
            "private VSS hash must be 64 bytes",
        ));
    }
    let mut output = [0_u8; 64];
    for (byte_index, chunk) in hash_hex.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        output[byte_index] = (high << 4) | low;
    }

    Ok(output)
}

fn hex_nibble(value: u8) -> CanonicalResult<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(invalid_private_vss_share_proof(
            "private VSS hash contains a non-hex character",
        )),
    }
}

fn encode_private_vss_share_lnp_tbox_prefix(
    layout: &super::setup_proof::SetupProofLnpTboxLayout,
    proof_randomness_seed_hex: &str,
) -> CanonicalResult<Vec<u8>> {
    let mut writer = PrivateVssShareLnpBitWriter::new();
    encode_private_vss_share_lnp_uniform_polyvec(
        &mut writer,
        layout.t_b_polynomial_count,
        layout.proof_ring_degree,
        layout.proof_modulus_bit_count,
        proof_randomness_seed_hex,
        0,
    )?;
    encode_private_vss_share_lnp_uniform_polyvec(
        &mut writer,
        layout.h_polynomial_count,
        layout.proof_ring_degree,
        layout.proof_modulus_bit_count,
        proof_randomness_seed_hex,
        1,
    )?;
    encode_private_vss_share_lnp_uniform_polyvec(
        &mut writer,
        layout.t_a1_polynomial_count,
        layout.proof_ring_degree,
        layout
            .proof_modulus_bit_count
            .checked_sub(layout.compression_dropped_bits)
            .ok_or_else(|| {
                invalid_private_vss_share_proof("private VSS LNP compression underflowed")
            })?,
        proof_randomness_seed_hex,
        2,
    )?;

    Ok(writer.into_bytes())
}

fn encode_private_vss_share_lnp_tbox_suffix(
    prefix_bytes: &mut Vec<u8>,
    layout: &super::setup_proof::SetupProofLnpTboxLayout,
    challenge_coefficients: &[i64],
) -> CanonicalResult<()> {
    let mut writer = PrivateVssShareLnpBitWriter::from_bytes(prefix_bytes);
    for coefficient in challenge_coefficients {
        let shifted = coefficient
            .checked_add(
                i64::try_from(super::setup_proof::SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND)
                    .expect("fixed challenge coefficient bound fits i64"),
            )
            .ok_or_else(|| {
                invalid_private_vss_share_proof("private VSS LNP challenge shift overflowed")
            })?;
        let shifted = u64::try_from(shifted).map_err(|_| {
            invalid_private_vss_share_proof("private VSS LNP challenge coefficient is negative")
        })?;
        writer.write_u64_le_bits(
            shifted,
            super::setup_proof::SETUP_PROOF_LNP_CHALLENGE_LOG2_RANGE,
        )?;
    }
    encode_private_vss_share_lnp_zero_hint_polyvec(
        &mut writer,
        layout.hint_polynomial_count,
        layout.proof_ring_degree,
    )?;
    encode_private_vss_share_lnp_zero_gaussian_polyvec(
        &mut writer,
        layout.z1_polynomial_count,
        layout.proof_ring_degree,
        layout.z1_log2_standard_deviation,
    )?;
    encode_private_vss_share_lnp_zero_gaussian_polyvec(
        &mut writer,
        layout.z21_polynomial_count,
        layout.proof_ring_degree,
        layout.z21_log2_standard_deviation,
    )?;
    encode_private_vss_share_lnp_zero_gaussian_polyvec(
        &mut writer,
        layout.z3_polynomial_count,
        layout.proof_ring_degree,
        layout.z3_log2_standard_deviation,
    )?;
    encode_private_vss_share_lnp_zero_gaussian_polyvec(
        &mut writer,
        layout.z4_polynomial_count,
        layout.proof_ring_degree,
        layout.z4_log2_standard_deviation,
    )?;
    writer.finish_with_lazer_padding();

    Ok(())
}

fn encode_private_vss_share_lnp_uniform_polyvec(
    writer: &mut PrivateVssShareLnpBitWriter<'_>,
    polynomial_count: usize,
    proof_ring_degree: usize,
    bit_count: usize,
    proof_randomness_seed_hex: &str,
    field_index: u64,
) -> CanonicalResult<()> {
    let coefficient_count = polynomial_count
        .checked_mul(proof_ring_degree)
        .ok_or_else(|| {
            invalid_private_vss_share_proof("private VSS LNP tbox coefficient count overflowed")
        })?;
    for coefficient_index in 0..coefficient_count {
        let coefficient_index_bytes = u64::try_from(coefficient_index)
            .map_err(|_| {
                invalid_private_vss_share_proof("private VSS LNP coefficient index overflowed")
            })?
            .to_le_bytes();
        let field_index_bytes = field_index.to_le_bytes();
        let block = hash512(
            "sealed-lattice/setup/private-vss-share/lnp-tbox-uniform-v1",
            &[
                proof_randomness_seed_hex.as_bytes(),
                &field_index_bytes,
                &coefficient_index_bytes,
            ],
        );
        let mut word = [0_u8; 8];
        word.copy_from_slice(&block[..8]);
        let value = u64::from_le_bytes(word) & ((1_u64 << bit_count.min(32)) - 1);
        writer.write_u64_le_bits(value, bit_count)?;
    }

    Ok(())
}

fn encode_private_vss_share_lnp_zero_hint_polyvec(
    writer: &mut PrivateVssShareLnpBitWriter<'_>,
    polynomial_count: usize,
    proof_ring_degree: usize,
) -> CanonicalResult<()> {
    let coefficient_count = polynomial_count
        .checked_mul(proof_ring_degree)
        .ok_or_else(|| invalid_private_vss_share_proof("private VSS LNP hint count overflowed"))?;
    for _ in 0..coefficient_count {
        writer.write_bit(false);
        writer.write_bit(false);
    }

    Ok(())
}

fn encode_private_vss_share_lnp_zero_gaussian_polyvec(
    writer: &mut PrivateVssShareLnpBitWriter<'_>,
    polynomial_count: usize,
    proof_ring_degree: usize,
    log2_standard_deviation: usize,
) -> CanonicalResult<()> {
    let coefficient_count = polynomial_count
        .checked_mul(proof_ring_degree)
        .ok_or_else(|| {
            invalid_private_vss_share_proof("private VSS LNP Gaussian count overflowed")
        })?;
    let low_bit_count = log2_standard_deviation.checked_add(1).ok_or_else(|| {
        invalid_private_vss_share_proof("private VSS LNP Gaussian low-bit count overflowed")
    })?;
    for _ in 0..coefficient_count {
        writer.write_bit(false);
        writer.write_u64_le_bits(0, low_bit_count)?;
    }

    Ok(())
}

enum PrivateVssShareLnpBitWriterStorage<'a> {
    Owned(Vec<u8>),
    Borrowed(&'a mut Vec<u8>),
}

struct PrivateVssShareLnpBitWriter<'a> {
    storage: PrivateVssShareLnpBitWriterStorage<'a>,
    bit_offset: usize,
}

impl<'a> PrivateVssShareLnpBitWriter<'a> {
    fn new() -> Self {
        Self {
            storage: PrivateVssShareLnpBitWriterStorage::Owned(Vec::new()),
            bit_offset: 0,
        }
    }

    fn from_bytes(bytes: &'a mut Vec<u8>) -> Self {
        let bit_offset = bytes.len() * 8;
        Self {
            storage: PrivateVssShareLnpBitWriterStorage::Borrowed(bytes),
            bit_offset,
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        match self.storage {
            PrivateVssShareLnpBitWriterStorage::Owned(bytes) => bytes,
            PrivateVssShareLnpBitWriterStorage::Borrowed(_) => {
                unreachable!("borrowed private VSS LNP bit writer is not consumed by value")
            }
        }
    }

    fn write_u64_le_bits(&mut self, value: u64, bit_count: usize) -> CanonicalResult<()> {
        for bit_index in 0..bit_count {
            let bit = if bit_index < u64::BITS as usize {
                ((value >> bit_index) & 1) == 1
            } else {
                false
            };
            self.write_bit(bit);
        }

        Ok(())
    }

    fn write_bit(&mut self, bit: bool) {
        let byte_index = self.bit_offset / 8;
        let bit_index = self.bit_offset % 8;
        let bytes = self.bytes_mut();
        if byte_index == bytes.len() {
            bytes.push(0);
        }
        if bit {
            bytes[byte_index] |= 1_u8 << bit_index;
        }
        self.bit_offset += 1;
    }

    fn finish_with_lazer_padding(&mut self) {
        self.write_bit(true);
        while !self.bit_offset.is_multiple_of(8) {
            self.write_bit(false);
        }
    }

    fn bytes_mut(&mut self) -> &mut Vec<u8> {
        match &mut self.storage {
            PrivateVssShareLnpBitWriterStorage::Owned(bytes) => bytes,
            PrivateVssShareLnpBitWriterStorage::Borrowed(bytes) => bytes,
        }
    }
}

fn sample_private_vss_share_message_mask_i128(
    statement_hash: &[u8; 64],
    proof_randomness_seed_hex: &str,
    coefficient_index: usize,
    coefficient_position: usize,
) -> CanonicalResult<i128> {
    let mask = sample_private_vss_share_mask_i128(
        statement_hash,
        proof_randomness_seed_hex,
        0,
        coefficient_index,
        0,
        coefficient_position,
    )?;
    let bound = 1_i128
        .checked_shl(PRIVATE_VSS_SHARE_MESSAGE_MASK_BITS as u32)
        .ok_or_else(|| {
            invalid_private_vss_share_proof("private VSS message mask bound overflowed")
        })?;
    Ok(mask.rem_euclid(bound))
}

fn sample_private_vss_share_carry_mask_i128(
    statement_hash: &[u8; 64],
    proof_randomness_seed_hex: &str,
    coefficient_position: usize,
) -> CanonicalResult<i128> {
    let mask = sample_private_vss_share_mask_i128(
        statement_hash,
        proof_randomness_seed_hex,
        2,
        0,
        0,
        coefficient_position,
    )?;
    let bound = 1_i128
        .checked_shl(PRIVATE_VSS_SHARE_CARRY_MASK_BITS as u32)
        .ok_or_else(|| {
            invalid_private_vss_share_proof("private VSS carry mask bound overflowed")
        })?;
    Ok(mask % bound)
}

fn sample_private_vss_share_mask_i128(
    statement_hash: &[u8; 64],
    proof_randomness_seed_hex: &str,
    domain_index: usize,
    coefficient_index: usize,
    column_index: usize,
    coefficient_position: usize,
) -> CanonicalResult<i128> {
    let domain_bytes = (domain_index as u64).to_le_bytes();
    let coefficient_index_bytes = (coefficient_index as u64).to_le_bytes();
    let column_bytes = (column_index as u64).to_le_bytes();
    let position_bytes = (coefficient_position as u64).to_le_bytes();
    let block = hash512(
        "sealed-lattice/setup/private-vss-share/lnp-proof-mask-v1",
        &[
            statement_hash,
            proof_randomness_seed_hex.as_bytes(),
            &domain_bytes,
            &coefficient_index_bytes,
            &column_bytes,
            &position_bytes,
        ],
    );
    let mut mask_bytes = [0_u8; 16];
    mask_bytes[..10].copy_from_slice(&block[..10]);
    let value = i128::from_le_bytes(mask_bytes);
    let sign = if block[10] & 1 == 0 { 1_i128 } else { -1_i128 };
    let bound = 1_i128
        .checked_shl(PRIVATE_VSS_SHARE_RANDOMNESS_MASK_BITS as u32)
        .ok_or_else(|| {
            invalid_private_vss_share_proof("private VSS proof mask bound overflowed")
        })?;
    Ok(sign * (value % bound))
}

fn write_i128_vector(output: &mut Vec<u8>, values: &[i128]) {
    for value in values {
        output.extend_from_slice(&value.to_le_bytes());
    }
}
