use num_bigint::BigUint;
use num_traits::{One, Zero};
use serde_json::{Value, json};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::{
    bgv::profile::POLYNOMIAL_DEGREE,
    bgv::setup_helpers::validate_hash_string,
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult, append_bytes, append_varuint},
    hashing::{HASH512_PREIMAGE_PREFIX, derive_protocol_hash, hash512, hash512_hex, to_hex},
};

pub(super) const SETUP_PROOF_PROFILE_ID: &str = "SealedLattice-LNP-SetupProof-v1";
pub(super) const SETUP_PROOF_CHALLENGE_BITS: u64 = 128;
pub(super) const SETUP_PROOF_CHALLENGE_COUNT: u64 = 1;
pub(super) const SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND: u64 = 2;
pub(super) const SETUP_PROOF_LNP_PROOF_RING_DEGREE: usize = 128;
pub(super) const SETUP_PROOF_LNP_CHALLENGE_LOG2_RANGE: usize = 3;
pub(super) const SETUP_PROOF_LNP_CHALLENGE_ENCODED_BITS: u64 =
    SETUP_PROOF_LNP_PROOF_RING_DEGREE as u64 * SETUP_PROOF_LNP_CHALLENGE_LOG2_RANGE as u64;
pub(super) const SETUP_PROOF_LNP_CHALLENGE_SPACE_BITS: u64 = 147;
pub(super) const SETUP_PROOF_CHALLENGE_DOMAIN: &str =
    "sealed-lattice/collective-bgv-setup/lnp-challenge-v1";
pub(super) const SETUP_PROOF_CHALLENGE_DOMAIN_PURPOSE: &str = "setup-proof-challenge-domain-v1";
pub(super) const SETUP_PROOF_CHALLENGE_SPACE: &str =
    "fixed-lnp-small-coefficient-polynomial-challenge-set";
pub(super) const SETUP_PROOF_CHALLENGE_DIFFERENCE_INVERTIBILITY_STATUS: &str =
    "review-required-before-claim-closure";
pub(super) const SETUP_PROOF_CHALLENGE_SAMPLER: &str =
    "sealed-lattice-shake256-lazer-autostable-rejection-v1";
const SETUP_PROOF_CHALLENGE_SEED_DOMAIN: &str =
    "sealed-lattice/collective-bgv-setup/lnp-challenge-seed-v1";
const SETUP_PROOF_CHALLENGE_STREAM_DOMAIN: &str =
    "sealed-lattice/collective-bgv-setup/lnp-challenge-stream-v1";
pub(super) const SETUP_PROOF_BYTES_DOMAIN: &str =
    "sealed-lattice/collective-bgv-setup/lnp-proof-bytes-v1";
pub(super) const SETUP_PROOF_SERIALIZATION: &str = "binary";
pub(crate) const SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES: u64 = 1_048_576;
pub(crate) const SETUP_PROOF_MATERIAL_ENCODING: &str = "binary-chunked-proof-bytes";
const SETUP_PROOF_MATERIAL_CHUNK_MANIFEST_OBJECT_TYPE: &str = "SetupProofMaterialChunkManifest";
const SETUP_PROOF_LNP_TBOX_PROOF_BYTE_DECODER: &str =
    "sealed-lattice-lnp-tbox-proof-byte-decoder-v1";
pub(super) const SETUP_PROOF_FAMILIES: &[&str] = &[
    "vss-opening-carry",
    "same-secret-consistency",
    "public-key-share",
    "relinearization-key-share",
    "galois-key-share",
];

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
    pub(crate) proof_size_bytes: u64,
    pub(crate) proof_bytes_hash: &'a str,
    pub(crate) transport_hashes: &'a SetupProofMaterialTransportHashes,
}

#[derive(Debug, Clone)]
#[allow(
    dead_code,
    reason = "used by the accepted family verifier once generated LNP tbox dimensions are pinned"
)]
pub(crate) struct SetupProofLnpTboxLayout {
    pub(crate) proof_family: &'static str,
    pub(crate) proof_ring_degree: usize,
    pub(crate) proof_modulus: BigUint,
    pub(crate) proof_modulus_bit_count: usize,
    pub(crate) compression_dropped_bits: usize,
    pub(crate) t_b_polynomial_count: usize,
    pub(crate) h_polynomial_count: usize,
    pub(crate) t_a1_polynomial_count: usize,
    pub(crate) hint_polynomial_count: usize,
    pub(crate) z1_polynomial_count: usize,
    pub(crate) z21_polynomial_count: usize,
    pub(crate) z3_polynomial_count: usize,
    pub(crate) z4_polynomial_count: usize,
    pub(crate) z1_log2_standard_deviation: usize,
    pub(crate) z21_log2_standard_deviation: usize,
    pub(crate) z3_log2_standard_deviation: usize,
    pub(crate) z4_log2_standard_deviation: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "returned by the accepted family verifier once generated LNP tbox dimensions are pinned"
)]
pub(crate) struct SetupProofLnpTboxDecodedSummary {
    pub(crate) decoded_size_bytes: usize,
    pub(crate) t_b_coefficients: Vec<BigUint>,
    pub(crate) h_coefficients: Vec<BigUint>,
    pub(crate) t_a1_compressed_coefficients: Vec<BigUint>,
    pub(crate) challenge_coefficients: Vec<i64>,
    pub(crate) hint_coefficients: Vec<LnpTboxHintCoefficient>,
    pub(crate) z1_coefficients: Vec<LnpTboxGaussianCoefficient>,
    pub(crate) z21_coefficients: Vec<LnpTboxGaussianCoefficient>,
    pub(crate) z3_coefficients: Vec<LnpTboxGaussianCoefficient>,
    pub(crate) z4_coefficients: Vec<LnpTboxGaussianCoefficient>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "returned by the accepted family verifier once generated LNP tbox dimensions are pinned"
)]
pub(crate) struct LnpTboxHintCoefficient {
    pub(crate) first_bit: bool,
    pub(crate) second_bit: bool,
    pub(crate) extension_zero_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "returned by the accepted family verifier once generated LNP tbox dimensions are pinned"
)]
pub(crate) struct LnpTboxGaussianCoefficient {
    pub(crate) unary_ones: usize,
    pub(crate) low_bits: u64,
    pub(crate) low_bit_count: usize,
}

pub(super) fn setup_proof_challenge_domain_hash(setup_profile_id: &str) -> CanonicalResult<String> {
    derive_protocol_hash(
        "ChallengeDomainHash",
        &setup_proof_challenge_domain_value(setup_profile_id),
    )
}

pub(super) fn setup_proof_challenge_domain_value(setup_profile_id: &str) -> Value {
    json!({
        "objectType": "SetupProofChallengeDomain",
        "objectVersion": 1,
        "purpose": SETUP_PROOF_CHALLENGE_DOMAIN_PURPOSE,
        "setupProfileId": setup_profile_id,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "challengeDomain": SETUP_PROOF_CHALLENGE_DOMAIN,
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
        "proofFamilies": SETUP_PROOF_FAMILIES,
        "randomOracleModel": "QROM review required before claim-bearing proof acceptance",
    })
}

pub(super) fn setup_proof_record_binding_value(
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
        "proofBytesDomain": SETUP_PROOF_BYTES_DOMAIN,
        "proofSerialization": SETUP_PROOF_SERIALIZATION,
        "proofByteDecoder": SETUP_PROOF_LNP_TBOX_PROOF_BYTE_DECODER,
        "proofBytesAcceptedStatus": "not-accepted-until-family-verifier-is-implemented",
    }))
}

pub(super) fn verify_setup_proof_record_binding(
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
    if !SETUP_PROOF_FAMILIES.contains(&proof_family) {
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

pub(super) fn setup_proof_challenge_space_audit_value(
    ring_degree: usize,
) -> CanonicalResult<Value> {
    let statement_hash = hash512_hex(
        "sealed-lattice/collective-bgv-setup/challenge-audit-statement-v1",
        &[b"same-secret-consistency"],
    );
    let relation_commitment_hash = hash512_hex(
        "sealed-lattice/collective-bgv-setup/challenge-audit-relation-commitment-v1",
        &[b"same-secret-consistency"],
    );
    let challenge_coefficients = derive_setup_proof_challenge_coefficients(
        "same-secret-consistency",
        &statement_hash,
        &relation_commitment_hash,
        ring_degree,
    )?;
    let sample_positions = challenge_sample_positions(ring_degree)?;
    let samples = sample_positions
        .into_iter()
        .map(|coefficient_position| {
            json!({
                "coefficientPosition": coefficient_position,
                "coefficientValue": challenge_coefficients[coefficient_position],
            })
        })
        .collect::<Vec<_>>();

    Ok(json!({
        "objectType": "SetupProofChallengeSpaceAudit",
        "objectVersion": 1,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "proofFamily": "same-secret-consistency",
        "applicationRingDegree": POLYNOMIAL_DEGREE,
        "lnpTboxProofRingDegree": ring_degree,
        "challengeCoefficientBound": SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND,
        "lnpTboxChallengeLog2Range": SETUP_PROOF_LNP_CHALLENGE_LOG2_RANGE,
        "lnpTboxChallengeEncodedBits": u64::try_from(ring_degree)
            .map_err(|_| setup_proof_error("setup proof challenge audit ring degree does not fit u64"))?
            .checked_mul(SETUP_PROOF_LNP_CHALLENGE_LOG2_RANGE as u64)
            .ok_or_else(|| setup_proof_error("setup proof challenge encoded bit count overflowed"))?,
        "lnpTboxChallengeSpaceBits": SETUP_PROOF_LNP_CHALLENGE_SPACE_BITS,
        "challengeSpace": SETUP_PROOF_CHALLENGE_SPACE,
        "challengeSampler": SETUP_PROOF_CHALLENGE_SAMPLER,
        "challengeSeedDomain": SETUP_PROOF_CHALLENGE_SEED_DOMAIN,
        "challengeStreamDomain": SETUP_PROOF_CHALLENGE_STREAM_DOMAIN,
        "statementHash": statement_hash,
        "relationCommitmentHash": relation_commitment_hash,
        "sampledCoefficients": samples,
    }))
}

pub(super) fn derive_setup_proof_challenge_coefficients(
    proof_family: &str,
    statement_hash_hex: &str,
    relation_commitment_hash_hex: &str,
    ring_degree: usize,
) -> CanonicalResult<Vec<i64>> {
    if !SETUP_PROOF_FAMILIES.contains(&proof_family) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "setup proof challenge proof family is not in the fixed setup-proof profile",
        ));
    }
    validate_hash_string(statement_hash_hex, "setupProofChallenge.statementHash")?;
    validate_hash_string(
        relation_commitment_hash_hex,
        "setupProofChallenge.relationCommitmentHash",
    )?;
    if ring_degree < 2 || !ring_degree.is_multiple_of(2) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "setup proof challenge ring degree must be even and at least two",
        ));
    }

    let half_degree = ring_degree / 2;
    let mut coefficients = vec![0_i64; ring_degree];
    let mut sampler = SetupProofChallengeSampler::new(
        proof_family,
        statement_hash_hex,
        relation_commitment_hash_hex,
    );
    for coefficient in coefficients.iter_mut().take(half_degree) {
        let sample = sampler.next_bounded_sample(
            SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND
                .checked_mul(2)
                .and_then(|value| value.checked_add(1))
                .expect("fixed challenge modulus fits u64"),
            3,
        )?;
        *coefficient = i64::try_from(sample).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "setup proof challenge sample does not fit i64",
            )
        })? - i64::try_from(SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND)
            .expect("fixed challenge coefficient bound fits i64");
    }
    coefficients[half_degree] = 0;
    for coefficient_position in (half_degree + 1)..ring_degree {
        coefficients[coefficient_position] = -coefficients[ring_degree - coefficient_position];
    }

    Ok(coefficients)
}

pub(super) fn setup_proof_lnp_tbox_byte_layout_profile_value() -> Value {
    json!({
        "objectType": "SetupProofLnpTboxByteLayoutProfile",
        "objectVersion": 1,
        "decoder": SETUP_PROOF_LNP_TBOX_PROOF_BYTE_DECODER,
        "applicationRingDegree": POLYNOMIAL_DEGREE,
        "lnpTboxProofRingDegree": SETUP_PROOF_LNP_PROOF_RING_DEGREE,
        "challengeCoefficientBound": SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND,
        "challengeLog2Range": SETUP_PROOF_LNP_CHALLENGE_LOG2_RANGE,
        "challengeEncodedBits": SETUP_PROOF_LNP_CHALLENGE_ENCODED_BITS,
        "challengeSpaceBits": SETUP_PROOF_LNP_CHALLENGE_SPACE_BITS,
        "fieldOrder": [
            "tB full-sized polynomial vector",
            "h full-sized polynomial vector",
            "tA1 compressed polynomial vector",
            "c autostable challenge polynomial",
            "hint decompression hint polynomial vector",
            "z1 Gaussian response polynomial vector",
            "z21 Gaussian response polynomial vector",
            "z3 Gaussian response polynomial vector",
            "z4 Gaussian response polynomial vector",
            "final one bit and zero padding"
        ],
        "uniformResidueEncoding": "little-endian fixed-bit coder_enc_urandom with strict residue range",
        "hintEncoding": "LaZer coder_enc_ghint coefficient code",
        "gaussianEncoding": "LaZer coder_enc_grandom unary sign-magnitude quotient plus two's-complement low bits",
        "parameterStatus": "family-specific generated tbox dimensions and proof modulus must be pinned before claim-bearing proof acceptance",
    })
}

#[allow(
    dead_code,
    reason = "entry point for the accepted family verifier once generated LNP tbox dimensions are pinned"
)]
pub(crate) fn verify_setup_proof_lnp_tbox_proof_bytes(
    layout: &SetupProofLnpTboxLayout,
    statement_hash_hex: &str,
    relation_commitment_hash_hex: &str,
    proof_bytes: &[u8],
) -> CanonicalResult<SetupProofLnpTboxDecodedSummary> {
    validate_lnp_tbox_layout(layout)?;
    validate_hash_string(statement_hash_hex, "setupProofLnpTbox.statementHash")?;
    validate_hash_string(
        relation_commitment_hash_hex,
        "setupProofLnpTbox.relationCommitmentHash",
    )?;

    let expected_challenge_coefficients = derive_setup_proof_challenge_coefficients(
        layout.proof_family,
        statement_hash_hex,
        relation_commitment_hash_hex,
        layout.proof_ring_degree,
    )?;
    let mut reader = LnpBitReader::new(proof_bytes);
    let t_b_coefficients = decode_uniform_polyvec(
        &mut reader,
        layout.t_b_polynomial_count,
        layout.proof_ring_degree,
        &layout.proof_modulus,
        layout.proof_modulus_bit_count,
        "tB",
    )?;
    let h_coefficients = decode_uniform_polyvec(
        &mut reader,
        layout.h_polynomial_count,
        layout.proof_ring_degree,
        &layout.proof_modulus,
        layout.proof_modulus_bit_count,
        "h",
    )?;
    let compressed_bit_count = layout
        .proof_modulus_bit_count
        .checked_sub(layout.compression_dropped_bits)
        .ok_or_else(|| setup_proof_error("setup proof compressed tA1 bit count underflowed"))?;
    let compressed_modulus = BigUint::one() << compressed_bit_count;
    let t_a1_compressed_coefficients = decode_uniform_polyvec(
        &mut reader,
        layout.t_a1_polynomial_count,
        layout.proof_ring_degree,
        &compressed_modulus,
        compressed_bit_count,
        "tA1",
    )?;
    let decoded_challenge = decode_centered_challenge_polynomial(&mut reader, layout)?;
    if decoded_challenge != expected_challenge_coefficients {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "setup proof LNP tbox challenge does not match the fixed challenge sampler",
        ));
    }
    let hint_coefficients = decode_hint_polyvec(
        &mut reader,
        layout.hint_polynomial_count,
        layout.proof_ring_degree,
    )?;
    let z1_coefficients = decode_gaussian_polyvec(
        &mut reader,
        layout.z1_polynomial_count,
        layout.proof_ring_degree,
        layout.z1_log2_standard_deviation,
        "z1",
    )?;
    let z21_coefficients = decode_gaussian_polyvec(
        &mut reader,
        layout.z21_polynomial_count,
        layout.proof_ring_degree,
        layout.z21_log2_standard_deviation,
        "z21",
    )?;
    let z3_coefficients = decode_gaussian_polyvec(
        &mut reader,
        layout.z3_polynomial_count,
        layout.proof_ring_degree,
        layout.z3_log2_standard_deviation,
        "z3",
    )?;
    let z4_coefficients = decode_gaussian_polyvec(
        &mut reader,
        layout.z4_polynomial_count,
        layout.proof_ring_degree,
        layout.z4_log2_standard_deviation,
        "z4",
    )?;
    reader.finish_with_lazer_padding()?;

    Ok(SetupProofLnpTboxDecodedSummary {
        decoded_size_bytes: proof_bytes.len(),
        t_b_coefficients,
        h_coefficients,
        t_a1_compressed_coefficients,
        challenge_coefficients: decoded_challenge,
        hint_coefficients,
        z1_coefficients,
        z21_coefficients,
        z3_coefficients,
        z4_coefficients,
    })
}

#[allow(
    dead_code,
    reason = "used by the LNP tbox proof-byte verifier entry point"
)]
fn validate_lnp_tbox_layout(layout: &SetupProofLnpTboxLayout) -> CanonicalResult<()> {
    if !SETUP_PROOF_FAMILIES.contains(&layout.proof_family) {
        return Err(setup_proof_error(
            "setup proof LNP tbox layout proof family is not in the fixed profile",
        ));
    }
    if !matches!(layout.proof_ring_degree, 64 | 128) {
        return Err(setup_proof_error(
            "setup proof LNP tbox proof ring degree must be 64 or 128",
        ));
    }
    if layout.proof_ring_degree != SETUP_PROOF_LNP_PROOF_RING_DEGREE {
        return Err(setup_proof_error(
            "setup proof LNP tbox proof ring degree does not match the fixed first-profile challenge shape",
        ));
    }
    let challenge_modulus = setup_proof_challenge_modulus();
    if layout.proof_modulus <= challenge_modulus {
        return Err(setup_proof_error(
            "setup proof LNP tbox proof modulus must be larger than the challenge modulus",
        ));
    }
    if layout.proof_modulus.bits() > layout.proof_modulus_bit_count as u64 {
        return Err(setup_proof_error(
            "setup proof LNP tbox proof modulus does not fit its declared bit count",
        ));
    }
    if layout.proof_modulus_bit_count == 0
        || layout.compression_dropped_bits >= layout.proof_modulus_bit_count
    {
        return Err(setup_proof_error(
            "setup proof LNP tbox compression parameters are invalid",
        ));
    }
    for (name, count) in [
        ("tB", layout.t_b_polynomial_count),
        ("h", layout.h_polynomial_count),
        ("tA1", layout.t_a1_polynomial_count),
        ("hint", layout.hint_polynomial_count),
        ("z1", layout.z1_polynomial_count),
        ("z21", layout.z21_polynomial_count),
        ("z3", layout.z3_polynomial_count),
        ("z4", layout.z4_polynomial_count),
    ] {
        if count == 0 {
            return Err(setup_proof_error(format!(
                "setup proof LNP tbox {name} polynomial count must be non-zero",
            )));
        }
    }
    for (name, bit_count) in [
        ("z1", layout.z1_log2_standard_deviation),
        ("z21", layout.z21_log2_standard_deviation),
        ("z3", layout.z3_log2_standard_deviation),
        ("z4", layout.z4_log2_standard_deviation),
    ] {
        if bit_count > 61 {
            return Err(setup_proof_error(format!(
                "setup proof LNP tbox {name} standard-deviation bit count is outside the supported range",
            )));
        }
    }

    Ok(())
}

#[allow(
    dead_code,
    reason = "used by the LNP tbox proof-byte verifier entry point"
)]
fn decode_uniform_polyvec(
    reader: &mut LnpBitReader<'_>,
    polynomial_count: usize,
    proof_ring_degree: usize,
    modulus: &BigUint,
    bit_count: usize,
    field_name: &str,
) -> CanonicalResult<Vec<BigUint>> {
    let coefficient_count = polynomial_count
        .checked_mul(proof_ring_degree)
        .ok_or_else(|| setup_proof_error("setup proof LNP tbox coefficient count overflowed"))?;
    let mut coefficients = Vec::with_capacity(coefficient_count);
    for _ in 0..coefficient_count {
        let value = reader.read_big_uint_le_bits(bit_count)?;
        if &value >= modulus {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                format!("setup proof LNP tbox {field_name} residue is not canonical"),
            ));
        }
        coefficients.push(value);
    }

    Ok(coefficients)
}

#[allow(
    dead_code,
    reason = "used by the LNP tbox proof-byte verifier entry point"
)]
fn decode_centered_challenge_polynomial(
    reader: &mut LnpBitReader<'_>,
    layout: &SetupProofLnpTboxLayout,
) -> CanonicalResult<Vec<i64>> {
    let modulus = setup_proof_challenge_modulus();
    let mut coefficients = Vec::with_capacity(layout.proof_ring_degree);
    for _ in 0..layout.proof_ring_degree {
        let value = reader.read_big_uint_le_bits(SETUP_PROOF_LNP_CHALLENGE_LOG2_RANGE)?;
        if value >= modulus {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "setup proof LNP tbox challenge coefficient is not canonical",
            ));
        }
        let residue = big_uint_to_u64(&value, "setup proof LNP challenge residue")?;
        let coefficient = i64::try_from(residue)
            .map_err(|_| setup_proof_error("setup proof LNP challenge residue does not fit i64"))?
            - i64::try_from(SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND)
                .expect("fixed challenge coefficient bound fits i64");
        coefficients.push(coefficient);
    }

    Ok(coefficients)
}

#[allow(
    dead_code,
    reason = "used by the LNP tbox proof-byte verifier entry point"
)]
fn decode_hint_polyvec(
    reader: &mut LnpBitReader<'_>,
    polynomial_count: usize,
    proof_ring_degree: usize,
) -> CanonicalResult<Vec<LnpTboxHintCoefficient>> {
    let coefficient_count = polynomial_count
        .checked_mul(proof_ring_degree)
        .ok_or_else(|| setup_proof_error("setup proof LNP hint coefficient count overflowed"))?;
    let mut coefficients = Vec::with_capacity(coefficient_count);
    for _ in 0..coefficient_count {
        let first_bit = reader.read_bit()?;
        let second_bit = reader.read_bit()?;
        let mut extension_zero_count = 0_usize;
        if first_bit && second_bit {
            while !reader.read_bit()? {
                extension_zero_count = extension_zero_count.checked_add(1).ok_or_else(|| {
                    setup_proof_error("setup proof LNP hint unary extension overflowed")
                })?;
            }
        }
        coefficients.push(LnpTboxHintCoefficient {
            first_bit,
            second_bit,
            extension_zero_count,
        });
    }

    Ok(coefficients)
}

#[allow(
    dead_code,
    reason = "used by the LNP tbox proof-byte verifier entry point"
)]
fn decode_gaussian_polyvec(
    reader: &mut LnpBitReader<'_>,
    polynomial_count: usize,
    proof_ring_degree: usize,
    log2_standard_deviation: usize,
    field_name: &str,
) -> CanonicalResult<Vec<LnpTboxGaussianCoefficient>> {
    let coefficient_count = polynomial_count
        .checked_mul(proof_ring_degree)
        .ok_or_else(|| {
            setup_proof_error(format!(
                "setup proof LNP {field_name} coefficient count overflowed",
            ))
        })?;
    let low_bit_count = log2_standard_deviation.checked_add(1).ok_or_else(|| {
        setup_proof_error(format!(
            "setup proof LNP {field_name} low-bit count overflowed",
        ))
    })?;
    let mut coefficients = Vec::with_capacity(coefficient_count);
    for _ in 0..coefficient_count {
        let mut unary_ones = 0_usize;
        while reader.read_bit()? {
            unary_ones = unary_ones.checked_add(1).ok_or_else(|| {
                setup_proof_error(format!(
                    "setup proof LNP {field_name} unary coefficient overflowed"
                ))
            })?;
        }
        let low_bits = reader.read_u64_le_bits(low_bit_count)?;
        coefficients.push(LnpTboxGaussianCoefficient {
            unary_ones,
            low_bits,
            low_bit_count,
        });
    }

    Ok(coefficients)
}

#[allow(
    dead_code,
    reason = "used by the LNP tbox proof-byte verifier entry point"
)]
fn setup_proof_challenge_modulus() -> BigUint {
    BigUint::from(
        SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND
            .checked_mul(2)
            .and_then(|value| value.checked_add(1))
            .expect("fixed challenge modulus fits u64"),
    )
}

#[allow(
    dead_code,
    reason = "used by the LNP tbox proof-byte verifier entry point"
)]
fn big_uint_to_u64(value: &BigUint, label: &str) -> CanonicalResult<u64> {
    let digits = value.to_u64_digits();
    match digits.as_slice() {
        [] => Ok(0),
        [digit] => Ok(*digit),
        _ => Err(setup_proof_error(format!("{label} does not fit u64"))),
    }
}

#[allow(
    dead_code,
    reason = "used by the LNP tbox proof-byte verifier entry point"
)]
struct LnpBitReader<'a> {
    bytes: &'a [u8],
    bit_offset: usize,
}

#[allow(
    dead_code,
    reason = "used by the LNP tbox proof-byte verifier entry point"
)]
impl<'a> LnpBitReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            bit_offset: 0,
        }
    }

    fn read_big_uint_le_bits(&mut self, bit_count: usize) -> CanonicalResult<BigUint> {
        let mut value = BigUint::zero();
        for bit_index in 0..bit_count {
            if self.read_bit()? {
                value |= BigUint::one() << bit_index;
            }
        }

        Ok(value)
    }

    fn read_u64_le_bits(&mut self, bit_count: usize) -> CanonicalResult<u64> {
        if bit_count > u64::BITS as usize {
            return Err(setup_proof_error(
                "setup proof LNP tbox u64 bit read exceeds u64 width",
            ));
        }
        let mut value = 0_u64;
        for bit_index in 0..bit_count {
            if self.read_bit()? {
                value |= 1_u64 << bit_index;
            }
        }

        Ok(value)
    }

    fn read_bit(&mut self) -> CanonicalResult<bool> {
        let byte_index = self.bit_offset / 8;
        let bit_index = self.bit_offset % 8;
        let Some(byte) = self.bytes.get(byte_index) else {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "setup proof LNP tbox proof ended before the declared field layout",
            ));
        };
        let bit = ((*byte >> bit_index) & 1) == 1;
        self.bit_offset = self
            .bit_offset
            .checked_add(1)
            .ok_or_else(|| setup_proof_error("setup proof LNP tbox bit offset overflowed"))?;

        Ok(bit)
    }

    fn skip_bits(&mut self, bit_count: usize) -> CanonicalResult<()> {
        for _ in 0..bit_count {
            self.read_bit()?;
        }

        Ok(())
    }

    fn finish_with_lazer_padding(&mut self) -> CanonicalResult<()> {
        let byte_index = self.bit_offset / 8;
        let bit_index = self.bit_offset % 8;
        let Some(byte) = self.bytes.get(byte_index) else {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "setup proof LNP tbox proof is missing its final padding byte",
            ));
        };
        let high_bits = *byte & (!0_u8 << bit_index);
        if high_bits != (1_u8 << bit_index) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "setup proof LNP tbox final padding is not canonical",
            ));
        }
        let consumed_bytes = byte_index.checked_add(1).ok_or_else(|| {
            setup_proof_error("setup proof LNP tbox consumed byte count overflowed")
        })?;
        if consumed_bytes != self.bytes.len() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::TrailingBytes,
                "setup proof LNP tbox proof has trailing bytes after final padding",
            ));
        }
        self.bit_offset = consumed_bytes
            .checked_mul(8)
            .ok_or_else(|| setup_proof_error("setup proof LNP tbox final bit offset overflowed"))?;

        Ok(())
    }
}

struct SetupProofChallengeSampler {
    seed: [u8; 64],
    block_index: u64,
    block: [u8; 64],
    bit_offset: usize,
}

impl SetupProofChallengeSampler {
    fn new(
        proof_family: &str,
        statement_hash_hex: &str,
        relation_commitment_hash_hex: &str,
    ) -> Self {
        Self {
            seed: hash512(
                SETUP_PROOF_CHALLENGE_SEED_DOMAIN,
                &[
                    proof_family.as_bytes(),
                    statement_hash_hex.as_bytes(),
                    relation_commitment_hash_hex.as_bytes(),
                ],
            ),
            block_index: 0,
            block: [0_u8; 64],
            bit_offset: 512,
        }
    }

    fn next_bounded_sample(&mut self, modulus: u64, bit_count: usize) -> CanonicalResult<u64> {
        if bit_count == 0 || bit_count > 63 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "setup proof challenge sample bit count is outside the supported range",
            ));
        }
        if modulus < (1_u64 << (bit_count - 1)) || modulus >= (1_u64 << bit_count) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "setup proof challenge modulus does not match the rejection bit count",
            ));
        }

        loop {
            let candidate = self.next_bits(bit_count)?;
            if candidate < modulus {
                return Ok(candidate);
            }
        }
    }

    fn next_bits(&mut self, bit_count: usize) -> CanonicalResult<u64> {
        if self.bit_offset + bit_count > 512 {
            let block_index_bytes = self.block_index.to_le_bytes();
            self.block = hash512(
                SETUP_PROOF_CHALLENGE_STREAM_DOMAIN,
                &[&self.seed, &block_index_bytes],
            );
            self.block_index = self.block_index.checked_add(1).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "setup proof challenge stream block index overflowed",
                )
            })?;
            self.bit_offset = 0;
        }

        let mut value = 0_u64;
        for bit_index in 0..bit_count {
            let absolute_bit_index = self.bit_offset + bit_index;
            let byte = self.block[absolute_bit_index / 8];
            let bit = (byte >> (absolute_bit_index % 8)) & 1;
            value |= u64::from(bit) << bit_index;
        }
        self.bit_offset += bit_count;

        Ok(value)
    }
}

fn challenge_sample_positions(ring_degree: usize) -> CanonicalResult<Vec<usize>> {
    if ring_degree < 2 || !ring_degree.is_multiple_of(2) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "setup proof challenge sample positions require an even ring degree",
        ));
    }

    let half_degree = ring_degree / 2;
    let last_position = ring_degree - 1;
    let mut positions = vec![0, 1.min(last_position), half_degree - 1, half_degree];
    if half_degree + 1 < ring_degree {
        positions.push(half_degree + 1);
    }
    positions.push(last_position);
    positions.sort_unstable();
    positions.dedup();

    Ok(positions)
}

fn setup_proof_error(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::ProfileComponentMismatch, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing::hash512_hex;

    #[test]
    fn setup_proof_challenge_sampler_derives_autostable_bounded_coefficients() {
        let statement_hash = hash512_hex("test-statement", &[b"same-secret"]);
        let relation_commitment_hash = hash512_hex("test-relation", &[b"same-secret"]);

        let coefficients = derive_setup_proof_challenge_coefficients(
            "same-secret-consistency",
            &statement_hash,
            &relation_commitment_hash,
            16,
        )
        .expect("challenge coefficients");

        assert_eq!(coefficients.len(), 16);
        assert!(
            coefficients[..8]
                .iter()
                .any(|coefficient| *coefficient != 0)
        );
        assert_eq!(coefficients[8], 0);
        for coefficient in &coefficients {
            assert!((-2..=2).contains(coefficient));
        }
        for coefficient_position in 9..16 {
            assert_eq!(
                coefficients[coefficient_position],
                -coefficients[16 - coefficient_position]
            );
        }
    }

    #[test]
    fn setup_proof_challenge_sampler_binds_statement_and_relation() {
        let statement_hash = hash512_hex("test-statement", &[b"same-secret"]);
        let other_statement_hash = hash512_hex("test-statement", &[b"same-secret-drift"]);
        let relation_commitment_hash = hash512_hex("test-relation", &[b"same-secret"]);

        let first = derive_setup_proof_challenge_coefficients(
            "same-secret-consistency",
            &statement_hash,
            &relation_commitment_hash,
            32,
        )
        .expect("challenge coefficients");
        let second = derive_setup_proof_challenge_coefficients(
            "same-secret-consistency",
            &other_statement_hash,
            &relation_commitment_hash,
            32,
        )
        .expect("challenge coefficients");

        assert_ne!(first, second);
    }

    #[test]
    fn setup_proof_challenge_sampler_rejects_wrong_profile_shape() {
        let statement_hash = hash512_hex("test-statement", &[b"same-secret"]);
        let relation_commitment_hash = hash512_hex("test-relation", &[b"same-secret"]);

        let odd_ring_error = derive_setup_proof_challenge_coefficients(
            "same-secret-consistency",
            &statement_hash,
            &relation_commitment_hash,
            15,
        )
        .expect_err("odd ring degree should fail");
        let wrong_family_error = derive_setup_proof_challenge_coefficients(
            "unknown-proof-family",
            &statement_hash,
            &relation_commitment_hash,
            16,
        )
        .expect_err("unknown proof family should fail");

        assert_eq!(
            odd_ring_error.code,
            CanonicalErrorCode::ProfileComponentMismatch
        );
        assert_eq!(
            wrong_family_error.code,
            CanonicalErrorCode::ProfileComponentMismatch
        );
    }

    #[test]
    fn setup_proof_lnp_tbox_decoder_accepts_canonical_proof_byte_layout() {
        let statement_hash = hash512_hex("test-statement", &[b"same-secret"]);
        let relation_commitment_hash = hash512_hex("test-relation", &[b"same-secret"]);
        let layout = small_lnp_tbox_layout_for_test();
        let challenge = derive_setup_proof_challenge_coefficients(
            layout.proof_family,
            &statement_hash,
            &relation_commitment_hash,
            layout.proof_ring_degree,
        )
        .expect("challenge coefficients");
        let proof_bytes =
            encode_lnp_tbox_proof_for_test(&layout, &challenge, None).expect("proof bytes");

        let decoded = verify_setup_proof_lnp_tbox_proof_bytes(
            &layout,
            &statement_hash,
            &relation_commitment_hash,
            &proof_bytes,
        )
        .expect("proof byte layout");

        assert_eq!(decoded.decoded_size_bytes, proof_bytes.len());
        assert_eq!(decoded.challenge_coefficients, challenge);
        assert_eq!(
            decoded.t_b_coefficients.len(),
            layout.t_b_polynomial_count * layout.proof_ring_degree
        );
        assert_eq!(
            decoded.h_coefficients.len(),
            layout.h_polynomial_count * layout.proof_ring_degree
        );
        assert_eq!(
            decoded.t_a1_compressed_coefficients.len(),
            layout.t_a1_polynomial_count * layout.proof_ring_degree
        );
        assert_eq!(decoded.t_b_coefficients[1], BigUint::from(1_u64));
        assert_eq!(decoded.h_coefficients[2], BigUint::from(2_u64));
        assert_eq!(
            decoded.t_a1_compressed_coefficients[3],
            BigUint::from(3_u64)
        );
        assert_eq!(
            decoded.hint_coefficients[0],
            LnpTboxHintCoefficient {
                first_bit: true,
                second_bit: false,
                extension_zero_count: 0
            }
        );
        assert_eq!(
            decoded.hint_coefficients[1],
            LnpTboxHintCoefficient {
                first_bit: false,
                second_bit: true,
                extension_zero_count: 0
            }
        );
        assert_eq!(
            decoded.hint_coefficients[2],
            LnpTboxHintCoefficient {
                first_bit: true,
                second_bit: true,
                extension_zero_count: 2
            }
        );
        assert_eq!(
            decoded.z1_coefficients[0],
            LnpTboxGaussianCoefficient {
                unary_ones: 2,
                low_bits: 3,
                low_bit_count: layout.z1_log2_standard_deviation + 1
            }
        );
        assert_eq!(
            decoded.z21_coefficients[0],
            LnpTboxGaussianCoefficient {
                unary_ones: 2,
                low_bits: 3,
                low_bit_count: layout.z21_log2_standard_deviation + 1
            }
        );
        assert_eq!(
            decoded.z3_coefficients[0],
            LnpTboxGaussianCoefficient {
                unary_ones: 2,
                low_bits: 3,
                low_bit_count: layout.z3_log2_standard_deviation + 1
            }
        );
        assert_eq!(
            decoded.z4_coefficients[0],
            LnpTboxGaussianCoefficient {
                unary_ones: 2,
                low_bits: 3,
                low_bit_count: layout.z4_log2_standard_deviation + 1
            }
        );
    }

    #[test]
    fn setup_proof_lnp_tbox_decoder_rejects_noncanonical_uniform_residue() {
        let statement_hash = hash512_hex("test-statement", &[b"same-secret"]);
        let relation_commitment_hash = hash512_hex("test-relation", &[b"same-secret"]);
        let layout = small_lnp_tbox_layout_for_test();
        let challenge = derive_setup_proof_challenge_coefficients(
            layout.proof_family,
            &statement_hash,
            &relation_commitment_hash,
            layout.proof_ring_degree,
        )
        .expect("challenge coefficients");
        let proof_bytes =
            encode_lnp_tbox_proof_for_test(&layout, &challenge, Some(layout.proof_modulus.clone()))
                .expect("proof bytes");

        let error = verify_setup_proof_lnp_tbox_proof_bytes(
            &layout,
            &statement_hash,
            &relation_commitment_hash,
            &proof_bytes,
        )
        .expect_err("noncanonical residue should fail");

        assert_eq!(error.code, CanonicalErrorCode::InvalidProtocolObject);
        assert!(error.message.contains("tB"));
    }

    #[test]
    fn setup_proof_lnp_tbox_decoder_rejects_challenge_drift_and_trailing_bytes() {
        let statement_hash = hash512_hex("test-statement", &[b"same-secret"]);
        let relation_commitment_hash = hash512_hex("test-relation", &[b"same-secret"]);
        let layout = small_lnp_tbox_layout_for_test();
        let mut challenge = derive_setup_proof_challenge_coefficients(
            layout.proof_family,
            &statement_hash,
            &relation_commitment_hash,
            layout.proof_ring_degree,
        )
        .expect("challenge coefficients");
        challenge[0] = if challenge[0] == 2 {
            1
        } else {
            challenge[0] + 1
        };
        let proof_bytes =
            encode_lnp_tbox_proof_for_test(&layout, &challenge, None).expect("proof bytes");

        let challenge_error = verify_setup_proof_lnp_tbox_proof_bytes(
            &layout,
            &statement_hash,
            &relation_commitment_hash,
            &proof_bytes,
        )
        .expect_err("challenge drift should fail");

        assert_eq!(
            challenge_error.code,
            CanonicalErrorCode::InvalidProtocolObject
        );
        assert!(challenge_error.message.contains("challenge"));

        let expected_challenge = derive_setup_proof_challenge_coefficients(
            layout.proof_family,
            &statement_hash,
            &relation_commitment_hash,
            layout.proof_ring_degree,
        )
        .expect("challenge coefficients");
        let mut trailing_bytes = encode_lnp_tbox_proof_for_test(&layout, &expected_challenge, None)
            .expect("proof bytes");
        trailing_bytes.push(0);
        let trailing_error = verify_setup_proof_lnp_tbox_proof_bytes(
            &layout,
            &statement_hash,
            &relation_commitment_hash,
            &trailing_bytes,
        )
        .expect_err("trailing byte should fail");

        assert_eq!(trailing_error.code, CanonicalErrorCode::TrailingBytes);
    }

    fn small_lnp_tbox_layout_for_test() -> SetupProofLnpTboxLayout {
        SetupProofLnpTboxLayout {
            proof_family: "same-secret-consistency",
            proof_ring_degree: SETUP_PROOF_LNP_PROOF_RING_DEGREE,
            proof_modulus: BigUint::from(12_289_u64),
            proof_modulus_bit_count: 14,
            compression_dropped_bits: 3,
            t_b_polynomial_count: 1,
            h_polynomial_count: 1,
            t_a1_polynomial_count: 1,
            hint_polynomial_count: 1,
            z1_polynomial_count: 1,
            z21_polynomial_count: 1,
            z3_polynomial_count: 1,
            z4_polynomial_count: 1,
            z1_log2_standard_deviation: 2,
            z21_log2_standard_deviation: 2,
            z3_log2_standard_deviation: 2,
            z4_log2_standard_deviation: 2,
        }
    }

    fn encode_lnp_tbox_proof_for_test(
        layout: &SetupProofLnpTboxLayout,
        challenge_coefficients: &[i64],
        first_t_b_residue_override: Option<BigUint>,
    ) -> CanonicalResult<Vec<u8>> {
        let mut writer = LnpBitWriterForTest::new();
        encode_uniform_polyvec_for_test(
            &mut writer,
            layout.t_b_polynomial_count,
            layout.proof_ring_degree,
            layout.proof_modulus_bit_count,
            first_t_b_residue_override,
        )?;
        encode_uniform_polyvec_for_test(
            &mut writer,
            layout.h_polynomial_count,
            layout.proof_ring_degree,
            layout.proof_modulus_bit_count,
            None,
        )?;
        encode_uniform_polyvec_for_test(
            &mut writer,
            layout.t_a1_polynomial_count,
            layout.proof_ring_degree,
            layout.proof_modulus_bit_count - layout.compression_dropped_bits,
            None,
        )?;
        for coefficient in challenge_coefficients {
            let shifted = coefficient
                .checked_add(i64::try_from(SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND).unwrap())
                .ok_or_else(|| setup_proof_error("test challenge coefficient overflowed"))?;
            writer.write_u64_le_bits(
                u64::try_from(shifted)
                    .map_err(|_| setup_proof_error("test challenge coefficient was negative"))?,
                SETUP_PROOF_LNP_CHALLENGE_LOG2_RANGE,
            );
        }
        let hint_count = layout
            .hint_polynomial_count
            .checked_mul(layout.proof_ring_degree)
            .ok_or_else(|| setup_proof_error("test hint count overflowed"))?;
        for coefficient_index in 0..hint_count {
            match coefficient_index {
                0 => {
                    writer.write_bit(true);
                    writer.write_bit(false);
                }
                1 => {
                    writer.write_bit(false);
                    writer.write_bit(true);
                }
                2 => {
                    writer.write_bit(true);
                    writer.write_bit(true);
                    writer.write_bit(false);
                    writer.write_bit(false);
                    writer.write_bit(true);
                }
                _ => {
                    writer.write_bit(false);
                    writer.write_bit(false);
                }
            }
        }
        for (polynomial_count, log2_standard_deviation) in [
            (
                layout.z1_polynomial_count,
                layout.z1_log2_standard_deviation,
            ),
            (
                layout.z21_polynomial_count,
                layout.z21_log2_standard_deviation,
            ),
            (
                layout.z3_polynomial_count,
                layout.z3_log2_standard_deviation,
            ),
            (
                layout.z4_polynomial_count,
                layout.z4_log2_standard_deviation,
            ),
        ] {
            let coefficient_count = polynomial_count
                .checked_mul(layout.proof_ring_degree)
                .ok_or_else(|| setup_proof_error("test gaussian count overflowed"))?;
            for coefficient_index in 0..coefficient_count {
                if coefficient_index == 0 {
                    writer.write_bit(true);
                    writer.write_bit(true);
                    writer.write_bit(false);
                    writer.write_u64_le_bits(3, log2_standard_deviation + 1);
                } else {
                    writer.write_bit(false);
                    writer.write_u64_le_bits(0, log2_standard_deviation + 1);
                }
            }
        }
        writer.finish_lazer_padding();

        Ok(writer.into_bytes())
    }

    fn encode_uniform_polyvec_for_test(
        writer: &mut LnpBitWriterForTest,
        polynomial_count: usize,
        proof_ring_degree: usize,
        bit_count: usize,
        first_residue_override: Option<BigUint>,
    ) -> CanonicalResult<()> {
        let coefficient_count = polynomial_count
            .checked_mul(proof_ring_degree)
            .ok_or_else(|| setup_proof_error("test uniform count overflowed"))?;
        for coefficient_index in 0..coefficient_count {
            if coefficient_index == 0
                && let Some(value) = first_residue_override.as_ref()
            {
                writer.write_big_uint_le_bits(value, bit_count);
                continue;
            }
            writer.write_u64_le_bits(
                u64::try_from(coefficient_index)
                    .map_err(|_| setup_proof_error("test coefficient index overflowed"))?,
                bit_count,
            );
        }

        Ok(())
    }

    struct LnpBitWriterForTest {
        bytes: Vec<u8>,
        bit_offset: usize,
    }

    impl LnpBitWriterForTest {
        fn new() -> Self {
            Self {
                bytes: vec![0],
                bit_offset: 0,
            }
        }

        fn write_bit(&mut self, bit: bool) {
            let byte_index = self.bit_offset / 8;
            let bit_index = self.bit_offset % 8;
            if byte_index == self.bytes.len() {
                self.bytes.push(0);
            }
            if bit {
                self.bytes[byte_index] |= 1 << bit_index;
            }
            self.bit_offset += 1;
        }

        fn write_u64_le_bits(&mut self, value: u64, bit_count: usize) {
            for bit_index in 0..bit_count {
                self.write_bit(((value >> bit_index) & 1) == 1);
            }
        }

        fn write_big_uint_le_bits(&mut self, value: &BigUint, bit_count: usize) {
            let digits = value.to_u64_digits();
            for bit_index in 0..bit_count {
                let digit_index = bit_index / 64;
                let digit_bit_index = bit_index % 64;
                let bit = digits
                    .get(digit_index)
                    .map(|digit| ((digit >> digit_bit_index) & 1) == 1)
                    .unwrap_or(false);
                self.write_bit(bit);
            }
        }

        fn finish_lazer_padding(&mut self) {
            self.write_bit(true);
            while !self.bit_offset.is_multiple_of(8) {
                self.write_bit(false);
            }
        }

        fn into_bytes(mut self) -> Vec<u8> {
            let used_bytes = self.bit_offset.div_ceil(8);
            self.bytes.truncate(used_bytes);
            self.bytes
        }
    }
}
