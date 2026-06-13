use super::*;

#[derive(Debug, Clone)]
pub(crate) struct SetupProofMaterialTransportHashes {
    pub(crate) full_object_hash: String,
    pub(crate) chunk_hashes: Vec<String>,
    pub(crate) chunk_root: String,
    pub(crate) total_byte_length: u64,
}

pub(crate) struct SetupProofMaterialReferenceInput<'a> {
    pub(crate) setup_profile_id: &'a str,
    pub(crate) proof_family: &'a str,
    pub(crate) trustee_identity: &'a str,
    pub(crate) trustee_roster_position: u64,
    pub(crate) statement_hash_hex: &'a str,
    pub(crate) relation_commitment_hash_hex: &'a str,
    pub(crate) tbox_commitment_prefix_hash: &'a str,
    pub(crate) proof_size_bytes: u64,
    pub(crate) proof_bytes_hash: &'a str,
    pub(crate) transport_hashes: &'a SetupProofMaterialTransportHashes,
}

pub(in crate::bgv::setup) fn setup_proof_record_binding_value(
    setup_profile_id: &str,
    setup_proof_profile_hash: &str,
) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "SetupProofRecordBinding",
        "objectVersion": 1,
        "setupProfileId": setup_profile_id,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "setupProofProfileHash": setup_proof_profile_hash,
        "proofSystem": "fixed-lnp-linear-relation-subset",
        "challengeDomain": SETUP_PROOF_CHALLENGE_DOMAIN,
        "challengeDomainHash": setup_proof_challenge_domain_hash(setup_profile_id)?,
        "challengeBits": SETUP_PROOF_CHALLENGE_BITS,
        "challengeCount": SETUP_PROOF_CHALLENGE_COUNT,
        "challengeCoefficientBound": SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND,
        "applicationRingDegree": POLYNOMIAL_DEGREE,
        "lnpTboxProofRingDegree": SETUP_PROOF_LNP_PROOF_RING_DEGREE,
        "lnpTboxChallengeLog2Range": SETUP_PROOF_LNP_CHALLENGE_LOG2_RANGE,
        "lnpTboxChallengeEncodedBits": SETUP_PROOF_LNP_CHALLENGE_ENCODED_BITS,
        "lnpTboxChallengeSpaceBits": SETUP_PROOF_LNP_CHALLENGE_SPACE_BITS,
        "challengeSpace": SETUP_PROOF_CHALLENGE_SPACE,
        "challengeSampler": SETUP_PROOF_CHALLENGE_SAMPLER,
        "challengeSeedDomain": SETUP_PROOF_CHALLENGE_SEED_DOMAIN,
        "challengeStreamDomain": SETUP_PROOF_CHALLENGE_STREAM_DOMAIN,
        "challengeDifferenceInvertibilityStatus": SETUP_PROOF_CHALLENGE_DIFFERENCE_INVERTIBILITY_STATUS,
        "challengeDifferenceInvertibilityAccounting": challenge_difference_invertibility_accounting_value()?,
        "proofBytesDomain": SETUP_PROOF_BYTES_DOMAIN,
        "proofSerialization": SETUP_PROOF_SERIALIZATION,
        "proofByteDecoder": SETUP_PROOF_LNP_TBOX_PROOF_BYTE_DECODER,
        "privateVssShareTboxParameterProfileHash": private_vss_share_lnp_tbox_parameter_profile_hash()?,
        "publicKeyShareTboxParameterProfileHash": public_key_share_lnp_tbox_parameter_profile_hash()?,
        "proofBytesAcceptedStatus": "private-vss-public-key-share-relinearization-and-galois-proof-bytes-accepted-for-setup-proof-accounting",
    }))
}

pub(in crate::bgv::setup) fn verify_setup_proof_record_binding(
    value: &Value,
    setup_profile_id: &str,
    setup_proof_profile_hash: &str,
) -> CanonicalResult<()> {
    let expected = setup_proof_record_binding_value(setup_profile_id, setup_proof_profile_hash)?;
    if value != &expected {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "setup proof record binding must match the fixed setup-proof profile and challenge domain",
        ));
    }

    Ok(())
}

pub(crate) fn setup_proof_material_transport_hashes(
    proof_family: &str,
    chunks: &[Vec<u8>],
    chunk_size_bytes: u64,
) -> CanonicalResult<SetupProofMaterialTransportHashes> {
    if !SETUP_PROOF_TRANSPORT_FAMILIES.contains(&proof_family) {
        return Err(setup_proof_error(
            "setup proof material proof family is not in the fixed setup-proof profile",
        ));
    }
    if chunk_size_bytes == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof material chunk size must be positive",
        ));
    }
    if chunks.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof material transport requires at least one chunk",
        ));
    }
    let chunk_size_usize = usize::try_from(chunk_size_bytes).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof material chunk size does not fit usize",
        )
    })?;
    let total_byte_length =
        chunks
            .iter()
            .enumerate()
            .try_fold(0_u64, |accumulator, (chunk_index, chunk)| {
                if chunk.is_empty() {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "setup proof material chunks must be non-empty",
                    ));
                }
                if chunk.len() > chunk_size_usize {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "setup proof material chunk exceeds the accepted chunk size",
                    ));
                }
                if chunk_index + 1 < chunks.len() && chunk.len() != chunk_size_usize {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "setup proof material contains a short non-final chunk",
                    ));
                }
                let chunk_length = u64::try_from(chunk.len()).map_err(|_| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "setup proof material chunk length does not fit u64",
                    )
                })?;
                accumulator.checked_add(chunk_length).ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "setup proof material byte length overflowed",
                    )
                })
            })?;

    let full_object_hash =
        setup_proof_material_full_object_hash(proof_family, total_byte_length, chunks)?;
    let mut chunk_hashes = Vec::with_capacity(chunks.len());
    for (chunk_index, chunk) in chunks.iter().enumerate() {
        chunk_hashes.push(setup_proof_material_chunk_hash(
            proof_family,
            &full_object_hash,
            chunk_index,
            chunk,
        )?);
    }
    let chunk_root = setup_proof_material_chunk_manifest_root(
        proof_family,
        chunk_size_bytes,
        u64::try_from(chunks.len()).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "setup proof material chunk count does not fit u64",
            )
        })?,
        total_byte_length,
        &chunk_hashes,
        &full_object_hash,
    )?;

    Ok(SetupProofMaterialTransportHashes {
        full_object_hash,
        chunk_hashes,
        chunk_root,
        total_byte_length,
    })
}

pub(crate) fn setup_proof_material_reference_root(
    input: SetupProofMaterialReferenceInput<'_>,
) -> CanonicalResult<String> {
    validate_hash_string(input.statement_hash_hex, "setupProofMaterial.statementHash")?;
    validate_hash_string(
        input.relation_commitment_hash_hex,
        "setupProofMaterial.relationCommitmentHash",
    )?;
    validate_hash_string(
        input.tbox_commitment_prefix_hash,
        "setupProofMaterial.tboxCommitmentPrefixHash",
    )?;
    validate_hash_string(input.proof_bytes_hash, "setupProofMaterial.proofBytesHash")?;
    validate_hash_string(
        &input.transport_hashes.full_object_hash,
        "setupProofMaterial.fullObjectHash",
    )?;
    validate_hash_string(
        &input.transport_hashes.chunk_root,
        "setupProofMaterial.chunkRoot",
    )?;
    for (chunk_index, chunk_hash) in input.transport_hashes.chunk_hashes.iter().enumerate() {
        validate_hash_string(
            chunk_hash,
            &format!("setupProofMaterial.chunkHashes[{chunk_index}]"),
        )?;
    }

    derive_protocol_hash(
        "SetupProofMaterialRoot",
        &json!({
            "objectType": "SetupProofMaterialReference",
            "objectVersion": 1,
            "setupProfileId": input.setup_profile_id,
            "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
            "proofFamily": input.proof_family,
            "proofBytesEncoding": SETUP_PROOF_MATERIAL_ENCODING,
            "trusteeIdentity": input.trustee_identity,
            "trusteeRosterPosition": input.trustee_roster_position,
            "statementHash": input.statement_hash_hex,
            "relationCommitmentHash": input.relation_commitment_hash_hex,
            "tboxCommitmentPrefixHash": input.tbox_commitment_prefix_hash,
            "proofSizeBytes": input.proof_size_bytes,
            "proofBytesHash": input.proof_bytes_hash,
            "chunkSizeBytes": SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
            "chunkCount": input.transport_hashes.chunk_hashes.len(),
            "totalByteLength": input.transport_hashes.total_byte_length,
            "fullObjectHash": input.transport_hashes.full_object_hash,
            "chunkRoot": input.transport_hashes.chunk_root,
            "chunkHashes": input.transport_hashes.chunk_hashes,
        }),
    )
}

fn setup_proof_material_full_object_hash(
    proof_family: &str,
    total_byte_length: u64,
    chunks: &[Vec<u8>],
) -> CanonicalResult<String> {
    let mut hasher = Shake256::default();
    hasher.update(HASH512_PREIMAGE_PREFIX);
    append_bytes_to_hasher(
        &mut hasher,
        b"sealed-lattice/setup/proof-material/full-object-v1",
    )?;
    append_bytes_to_hasher(&mut hasher, proof_family.as_bytes())?;
    let mut length = Vec::new();
    append_varuint(&mut length, total_byte_length);
    hasher.update(&length);
    for chunk in chunks {
        hasher.update(chunk);
    }
    let mut output = [0_u8; 64];
    hasher.finalize_xof().read(&mut output);

    Ok(to_hex(&output))
}

fn setup_proof_material_chunk_hash(
    proof_family: &str,
    full_object_hash: &str,
    chunk_index: usize,
    chunk: &[u8],
) -> CanonicalResult<String> {
    validate_hash_string(full_object_hash, "setupProofMaterial.fullObjectHash")?;
    let mut chunk_index_bytes = Vec::new();
    append_varuint(
        &mut chunk_index_bytes,
        u64::try_from(chunk_index).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "setup proof material chunk index does not fit u64",
            )
        })?,
    );

    Ok(hash512_hex(
        "sealed-lattice/setup/proof-material/chunk-v1",
        &[
            proof_family.as_bytes(),
            full_object_hash.as_bytes(),
            &chunk_index_bytes,
            chunk,
        ],
    ))
}

fn setup_proof_material_chunk_manifest_root(
    proof_family: &str,
    chunk_size_bytes: u64,
    chunk_count: u64,
    total_byte_length: u64,
    chunk_hashes: &[String],
    full_object_hash: &str,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "SetupProofChunkManifestRoot",
        &json!({
            "objectType": SETUP_PROOF_MATERIAL_CHUNK_MANIFEST_OBJECT_TYPE,
            "objectVersion": 1,
            "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
            "proofFamily": proof_family,
            "chunkSizeBytes": chunk_size_bytes,
            "chunkCount": chunk_count,
            "totalByteLength": total_byte_length,
            "chunkHashes": chunk_hashes,
            "fullObjectHash": full_object_hash,
        }),
    )
}

fn append_bytes_to_hasher(hasher: &mut Shake256, value: &[u8]) -> CanonicalResult<()> {
    let mut encoded = Vec::new();
    append_bytes(&mut encoded, value);
    hasher.update(&encoded);

    Ok(())
}
