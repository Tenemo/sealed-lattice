use std::collections::BTreeSet;

use serde_json::{Value, json};

use crate::{
    ballot_privacy::linear_proof::{
        parameters::{LinearProofEncoding, LinearProofParameterSet},
        sparse_matrix::{
            PolynomialRing, PolynomialVector, SparsePolynomialMatrix, SparsePolynomialMatrixEntry,
        },
        statement::{
            LinearProofMatrixCoefficientRepresentation, LinearProofTargetCoefficientRepresentation,
            LinearStatementTranscript, StreamedLinearProofStatement,
            rotate_left_negacyclic_signed_polynomial, source_modulus_inverse_mod_proof_modulus,
            source_polynomial_split_factor,
            split_source_polynomial_into_proof_ring_with_coefficient_representation,
            transform_target_vector_to_proof_ring,
        },
        transcript::shake128_32,
        verifier::{StreamedLinearProofVerificationInput, verify_streamed_linear_proof_components},
    },
    bgv::{
        modular_arithmetic::{add_mod, inverse_mod, mul_mod, sub_mod},
        profile::{
            BgvBasisKind, DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE,
            canonical_ciphertext_convention_hash, data_basis_modulus_bits, modulus_bit_length,
            profile_hash,
        },
        rns::RnsPolynomial,
        serialization::{
            BgvObjectKind, canonical_bytes_hash, ciphertext_root, parse_bgv_object_hex,
        },
        setup::validate_passive_setup_package_for_encrypted_evaluation,
        setup::validate_trustee_public_key_share_coefficient_material_sidecar,
        setup_helpers::{array_at_path, bool_at_path, hash_at_path, string_at_path, value_at_path},
        validation::reject_unexpected_bgv_request_fields,
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::{
        canonical_json, derive_protocol_hash, derive_protocol_hash_for_proof_bytes_payload,
        hash512_hex, to_hex,
    },
    transcript_core::decode_hex,
};

pub(crate) const MASKED_RANK_REFRESH_PROFILE_ID: &str = "sealed-lattice-masked-rank-refresh-v1";
const MASKED_RANK_REFRESH_TRANSCRIPT_OBJECT_TYPE: &str = "MaskedRankRefreshTranscript";
const MASKED_RANK_REFRESH_SHARE_OBJECT_TYPE: &str = "MaskedRankRefreshShareRecord";
const SELECTED_ALGEBRAIC_SHARE_VERIFICATION_KEY_BINDING_OBJECT_TYPE: &str =
    "MaskedRankRefreshSelectedAlgebraicShareVerificationKeyBinding";
const INPUT_RANK_CIPHERTEXT_COMPONENT_ONE_PAYLOAD_OBJECT_TYPE: &str =
    "MaskedRankRefreshInputRankCiphertextComponentOnePayload";
const PARTIAL_DECRYPTION_SHARE_PAYLOAD_OBJECT_TYPE: &str =
    "MaskedRankRefreshPartialDecryptionSharePayload";
const PART_DEC_SHARE_EQUATION_PROOF_OBJECT_TYPE: &str =
    "MaskedRankRefreshPartDecShareEquationProof";
const PART_DEC_LINEAR_RELATION_STATEMENT_OBJECT_TYPE: &str =
    "MaskedRankRefreshPartDecLinearRelationStatement";
const PART_DEC_LINEAR_PROOF_BACKEND_ADAPTER_OBJECT_TYPE: &str =
    "MaskedRankRefreshPartDecLinearProofBackendAdapter";
const PART_DEC_LINEAR_PROOF_BACKEND_INPUT_OBJECT_TYPE: &str =
    "MaskedRankRefreshPartDecLinearProofBackendInput";
const PART_DEC_PUBLIC_KEY_SHARE_LINEAR_PROOF_BACKEND_INPUT_OBJECT_TYPE: &str =
    "MaskedRankRefreshPartDecPublicKeyShareConsistencyLinearProofBackendInput";
const PART_DEC_MASKED_SHARE_LINEAR_PROOF_BACKEND_INPUT_OBJECT_TYPE: &str =
    "MaskedRankRefreshPartDecMaskedShareLinearProofBackendInput";
const PART_DEC_SPLIT_SAME_WITNESS_BINDING_OBJECT_TYPE: &str =
    "MaskedRankRefreshPartDecSplitSameWitnessBinding";
const SMUDGING_BOUND_CERTIFICATE_OBJECT_TYPE: &str = "MaskedRankRefreshSmudgingBoundCertificate";
const FIN_DEC_MASKED_OPENING_OBJECT_TYPE: &str = "MaskedRankRefreshFinDecMaskedOpening";
const FIN_DEC_MASKED_OPENING_PAYLOAD_OBJECT_TYPE: &str =
    "MaskedRankRefreshFinDecMaskedOpeningPayload";
const FIN_DEC_LAGRANGE_COEFFICIENT_AUDIT_OBJECT_TYPE: &str =
    "MaskedRankRefreshFinDecLagrangeCoefficientAudit";
const MASK_RE_ENCRYPTION_PROOF_RECORD_OBJECT_TYPE: &str =
    "MaskedRankRefreshMaskReEncryptionProofRecord";
const MASK_RE_ENCRYPTION_PROOF_STATEMENT_OBJECT_TYPE: &str =
    "MaskedRankRefreshMaskReEncryptionProofStatement";
const MASK_RE_ENCRYPTION_CIPHERTEXT_PAYLOAD_OBJECT_TYPE: &str =
    "MaskedRankRefreshMaskReEncryptionCiphertextPayload";
const MASK_COMMITMENT_OBJECT_TYPE: &str = "MaskedRankRefreshMaskCommitment";
const MASK_ENCRYPTION_RANDOMNESS_EVIDENCE_OBJECT_TYPE: &str =
    "MaskedRankRefreshMaskEncryptionRandomnessEvidence";
const PART_DEC_PROOF_METADATA_FIELDS: [&str; 6] = [
    "proofVerificationStatus",
    "proofBytesVerified",
    "proofBytesHex",
    "proofSizeBytes",
    "proofBytesHash",
    "proofStatementHash",
];
const SMUDGING_BOUND_PROOF_METADATA_FIELDS: [&str; 6] = [
    "boundProofVerificationStatus",
    "boundProofBytesVerified",
    "boundProofBytesHex",
    "boundProofSizeBytes",
    "boundProofBytesHash",
    "boundProofStatementHash",
];
const FIN_DEC_PROOF_METADATA_FIELDS: [&str; 6] = [
    "finDecProofVerificationStatus",
    "finDecProofBytesVerified",
    "proofBytesHex",
    "proofSizeBytes",
    "proofBytesHash",
    "proofStatementHash",
];
const MASK_RE_ENCRYPTION_PROOF_METADATA_FIELDS: [&str; 6] = [
    "proofVerificationStatus",
    "proofBytesVerified",
    "proofBytesHex",
    "proofSizeBytes",
    "proofBytesHash",
    "proofStatementHash",
];
const PART_DEC_LINEAR_PROOF_SYSTEM_RING_DEGREE: u64 = 64;
const PART_DEC_LINEAR_PROOF_SOURCE_POLYNOMIAL_SPLIT_FACTOR: u64 =
    (POLYNOMIAL_DEGREE as u64) / PART_DEC_LINEAR_PROOF_SYSTEM_RING_DEGREE;
const PART_DEC_LINEAR_PROOF_EXPECTED_SHORT_RESPONSE_VECTOR_LENGTH: u64 =
    3 * PART_DEC_LINEAR_PROOF_SOURCE_POLYNOMIAL_SPLIT_FACTOR + 1;
const PART_DEC_PUBLIC_KEY_SHARE_LINEAR_PROOF_EXPECTED_SHORT_RESPONSE_VECTOR_LENGTH: u64 =
    2 * PART_DEC_LINEAR_PROOF_SOURCE_POLYNOMIAL_SPLIT_FACTOR + 1;
const PART_DEC_SECRET_SHARE_COEFFICIENT_BOUND: u64 = 1;
const PART_DEC_ERROR_SHARE_COEFFICIENT_BOUND: u64 = 2;
const PART_DEC_WITNESS_BOUND_SOURCE: &str =
    "setup-secret-error-distribution-and-smudging-bound-certificate";
const PART_DEC_WITNESS_BOUND_COMPUTATION: &str = "N*(secretShareCoefficientBound^2+errorShareCoefficientBound^2+smudgingNoiseCoefficientBound^2)";
const PART_DEC_PUBLIC_KEY_SHARE_WITNESS_BOUND_SOURCE: &str =
    "setup-secret-error-distribution-certificate";
const PART_DEC_PUBLIC_KEY_SHARE_WITNESS_BOUND_COMPUTATION: &str =
    "N*(secretShareCoefficientBound^2+errorShareCoefficientBound^2)";
const PART_DEC_PUBLIC_KEY_SHARE_LINEAR_PROOF_PARAMETER_PROFILE_ID: &str =
    "masked-rank-refresh-partdec-public-key-share-consistency-linear-proof-parameter-v1";
const PART_DEC_PUBLIC_KEY_SHARE_LINEAR_PROOF_ENCODING_PROFILE_ID: &str =
    "masked-rank-refresh-partdec-public-key-share-consistency-linear-proof-encoding-v1";
const PART_DEC_PUBLIC_KEY_SHARE_LINEAR_PROOF_BACKEND_VERIFIED_STATUS: &str = "LinearProofVerified";
const PART_DEC_PUBLIC_KEY_SHARE_LINEAR_PROOF_VERIFIER_PENDING_STATUS: &str =
    "PartDecPublicKeyShareConsistencyLinearProofVerifierPending";
const PART_DEC_PUBLIC_KEY_SHARE_LINEAR_PROOF_VERIFIED_STATUS: &str =
    "PartDecPublicKeyShareConsistencyLinearProofVerified";
const PART_DEC_MASKED_SHARE_LINEAR_PROOF_VERIFIER_PENDING_STATUS: &str = "PartDecMaskedShareLinearProofVerifierPendingBecauseWitnessBoundExceedsCurrentLinearProofBackendCapacity";
const PART_DEC_SPLIT_SAME_WITNESS_BINDING_PENDING_STATUS: &str =
    "PartDecSplitSameWitnessBindingProofPending";
const PART_DEC_SPLIT_SAME_WITNESS_VERIFIER_PENDING_STATUS: &str =
    "PartDecSplitSameWitnessVerifierPending";
const PART_DEC_LINEAR_PROOF_BACKEND_WITNESS_BOUND_CAPACITY_BITS: u64 = u128::BITS as u64;
const PART_DEC_LINEAR_PROOF_BACKEND_WITNESS_BOUND_FITS_STATUS: &str =
    "PartDecWitnessBoundFitsCurrentLinearProofBackendCapacity";
const PART_DEC_LINEAR_PROOF_BACKEND_WITNESS_BOUND_EXCEEDS_STATUS: &str =
    "PartDecWitnessBoundExceedsCurrentLinearProofBackendCapacity";

struct ProofBytesBinding<'a> {
    proof_bytes_hex_field: &'a str,
    proof_size_bytes_field: &'a str,
    proof_bytes_hash_field: &'a str,
    proof_statement_hash_field: &'a str,
    statement_hash_namespace: &'a str,
    statement_metadata_fields: &'a [&'a str],
    label: &'a str,
}

struct MaskReEncryptionCiphertextPayloadBinding<'a> {
    payload_field: &'a str,
    payload_hash_field: &'a str,
    root_field: &'a str,
    root_alias_field: &'a str,
    hash_namespace: &'a str,
    ciphertext_role: &'a str,
    label: &'a str,
}

struct PartDecWitnessBound {
    secret_share_coefficient_bound: u64,
    error_share_coefficient_bound: u64,
    smudging_noise_coefficient_bound_bits: u64,
    smudging_noise_coefficient_bound_decimal: String,
    witness_l2_bound_squared_decimal: String,
    witness_l2_bound_squared_bit_length: u64,
    witness_l2_bound_squared_fits_current_backend: bool,
}

struct PartDecMaskedShareWitnessBound {
    secret_share_coefficient_bound: u64,
    smudging_noise_coefficient_bound_bits: u64,
    smudging_noise_coefficient_bound_decimal: String,
    witness_l2_bound_squared_decimal: String,
    witness_l2_bound_squared_bit_length: u64,
    witness_l2_bound_squared_fits_current_backend: bool,
}

pub(crate) fn describe_masked_rank_refresh_profile() -> CanonicalResult<Value> {
    let profile = masked_rank_refresh_profile_value()?;
    let profile_hash = masked_rank_refresh_profile_hash()?;

    Ok(json!({
        "profile": profile,
        "profileHash": profile_hash,
        "statusLabels": [
            "MaskedRankRefreshProfileBound",
            "PartDecFinDecShareVerificationRequired",
            "RankRefreshTranscriptVerifierFailsClosed"
        ],
    }))
}

fn masked_rank_refresh_profile_value() -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "MaskedRankRefreshProfile",
        "objectVersion": 1,
        "profileId": MASKED_RANK_REFRESH_PROFILE_ID,
        "bgvProfileHash": profile_hash()?,
        "canonicalCiphertextConventionHash": canonical_ciphertext_convention_hash()?,
        "basisId": "data",
        "dataPrimeCount": DATA_PRIMES.len(),
        "rankCiphertextRole": "packed-rank",
        "allowedRefreshScope": "accepted-evaluator-packed-rank-ciphertext-only",
        "forbiddenRefreshScopes": [
            "aggregate-input",
            "aggregate-score",
            "comparison-bit",
            "ahead-indicator",
            "top-k-bundle",
            "target-ciphertext",
            "user-supplied-ciphertext",
            "checkpoint-only-ciphertext"
        ],
        "maskedOpeningRequired": true,
        "partDecRequired": true,
        "inputRankCiphertextComponentOnePayloadRequired": true,
        "publicPartialDecryptionSharePayloadRequired": true,
        "finDecRequired": true,
        "finDecMaskedOpeningStatementRequired": true,
        "finDecMaskedOpeningPayloadRequired": true,
        "finDecLagrangeCoefficientAuditRequired": true,
        "finDecSelectedShareCombinerRequired": true,
        "setupBoundShareSelectionRequired": true,
        "selectedAlgebraicShareVerificationKeyBindingRequired": true,
        "shareSelectionMustUseSetupDecryptionThreshold": true,
        "shareEquationProofRequired": true,
        "partDecLinearRelationStatementRequired": true,
        "partDecLinearProofBackendAdapterRequired": true,
        "partDecLinearProofAdapterMustBindPublicMatrixAndTarget": true,
        "partDecLinearProofBackendInputRequired": true,
        "partDecLinearProofBackendInputMustBindVerifierRandomness": true,
        "partDecLinearProofBackendInputMustBindWitnessBound": true,
        "partDecLinearProofBackendMustRejectOutOfCapacityWitnessBound": true,
        "partDecLinearProofBackendMustSplitOutPublicKeyShareConsistency": true,
        "partDecPublicKeyShareConsistencyProofInputMustFitCurrentBackend": true,
        "partDecMaskedShareProofInputMustBindSmudgingRelation": true,
        "partDecSmudgingRelationProofRemainsBackendCapacityGated": true,
        "partDecSplitSameWitnessBindingRequired": true,
        "proofBytesMetadataRequired": true,
        "proofBytesMustBindPublicStatementHash": true,
        "maskReEncryptionProofRequired": true,
        "maskCommitmentRequired": true,
        "maskEncryptionRandomnessEvidenceRequired": true,
        "encryptedMaskCiphertextPayloadRequired": true,
        "refreshedRankCiphertextPayloadRequired": true,
        "maskReEncryptionProofMustBindCiphertextPayloads": true,
        "maskReEncryptionProofMustBindMaskCommitment": true,
        "maskReEncryptionProofMustBindMaskEncryptionRandomnessEvidence": true,
        "maskReEncryptionProofMustBindVerifierRandomness": true,
        "smudgingBoundCertificateRequired": true,
        "smudgingBoundMustBindLagrangeCoefficientAudit": true,
        "semanticRankDecryptionAllowed": false,
        "plaintextRankExportAllowed": false,
        "partDecProofMustBindInputCiphertextComponentOne": true,
        "refreshedCiphertextMustBindInputRankRoot": true,
        "partialDecryptionSharePayloadMustBindInputRankRoot": true,
        "refreshTranscriptMustBindEvaluationContext": true,
        "refreshTranscriptMustBindSetupRoots": true,
        "refreshTranscriptMustBindAlgebraicShareVerificationKeys": true,
        "refreshTranscriptMustBindFinality": true,
        "implementationStatus": "part-dec-fin-dec-proof-bytes-bound-proof-relations-pending"
    }))
}

pub(crate) fn masked_rank_refresh_profile_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "MaskedRankRefreshProfileHash",
        &masked_rank_refresh_profile_value()?,
    )
}

pub(crate) fn verify_masked_rank_refresh_transcript_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    reject_unexpected_bgv_request_fields(
        request,
        &[
            "rankRefreshTranscript",
            "setupPackage",
            "expectedAlgebraicShareVerificationKeyHash",
            "expectedAlgebraicShareVerificationKeyRoot",
            "expectedBgvPublicKeyRoot",
            "expectedCollectivePublicKeyRoot",
            "expectedEvaluationContextHash",
            "expectedEvaluationKeyRoot",
            "expectedInputRankCiphertextRoot",
            "expectedRefreshedRankCiphertextRoot",
            "expectedSetupPackageHash",
            "expectedTargetLayoutHash",
            "expectedThresholdShareVerificationKeyHash",
            "expectedThresholdShareVerificationKeyRoot",
            "expectedTopCount",
        ],
        "verifyMaskedRankRefreshTranscript",
    )?;
    reject_forbidden_rank_refresh_fields(request)?;

    let transcript = value_at_path(request, &["rankRefreshTranscript"])?;
    let setup_package = value_at_path(request, &["setupPackage"])?;
    validate_passive_setup_package_for_encrypted_evaluation(setup_package)?;
    validate_rank_refresh_transcript_shape(request, transcript)?;
    validate_setup_bound_refresh_transcript(setup_package, transcript)?;

    Err(CanonicalError::new(
        CanonicalErrorCode::ProfileComponentMismatch,
        "masked rank refresh transcript verification requires algebraic threshold LSSS certification, zero-knowledge PartDec share-equation verification, claim-bearing FinDec masked-opening proof verification, smudging-bound proof verification, and mask re-encryption proof support before accepted evaluation can consume refreshed ranks",
    ))
}

pub(crate) fn reject_rank_refresh_transcript_for_accepted_evaluation(
    request: &Value,
) -> CanonicalResult<()> {
    if request.get("rankRefreshTranscript").is_some()
        || request.get("rankRefreshTranscripts").is_some()
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "accepted encrypted aggregate evaluation cannot consume rank refresh transcripts until masked rank refresh PartDec/FinDec share verification is implemented",
        ));
    }

    Ok(())
}

fn validate_rank_refresh_transcript_shape(
    request: &Value,
    transcript: &Value,
) -> CanonicalResult<()> {
    require_string_at_path(
        transcript,
        &["objectType"],
        MASKED_RANK_REFRESH_TRANSCRIPT_OBJECT_TYPE,
        "rank refresh transcript object type",
    )?;
    require_u64_at_path(
        transcript,
        &["objectVersion"],
        1,
        "rank refresh transcript version",
    )?;
    require_string_at_path(
        transcript,
        &["profileId"],
        MASKED_RANK_REFRESH_PROFILE_ID,
        "rank refresh profile id",
    )?;
    compare_hash_at_request_field(
        request,
        transcript,
        "expectedEvaluationContextHash",
        &["evaluationContextHash"],
        "rank refresh evaluation context hash",
    )?;
    compare_hash_at_request_field(
        request,
        transcript,
        "expectedInputRankCiphertextRoot",
        &["inputRankCiphertextRoot"],
        "rank refresh input rank ciphertext root",
    )?;
    compare_hash_at_request_field(
        request,
        transcript,
        "expectedRefreshedRankCiphertextRoot",
        &["refreshedRankCiphertextRoot"],
        "rank refresh refreshed rank ciphertext root",
    )?;
    compare_hash_at_request_field(
        request,
        transcript,
        "expectedSetupPackageHash",
        &["setupPackageHash"],
        "rank refresh setup package hash",
    )?;
    compare_hash_at_request_field(
        request,
        transcript,
        "expectedCollectivePublicKeyRoot",
        &["collectivePublicKeyRoot"],
        "rank refresh collective public key root",
    )?;
    compare_hash_at_request_field(
        request,
        transcript,
        "expectedBgvPublicKeyRoot",
        &["bgvPublicKeyRoot"],
        "rank refresh BGV public key root",
    )?;
    compare_hash_at_request_field(
        request,
        transcript,
        "expectedEvaluationKeyRoot",
        &["evaluationKeyRoot"],
        "rank refresh evaluation key root",
    )?;
    compare_hash_at_request_field(
        request,
        transcript,
        "expectedTargetLayoutHash",
        &["targetLayoutHash"],
        "rank refresh target layout hash",
    )?;
    compare_hash_at_request_field(
        request,
        transcript,
        "expectedAlgebraicShareVerificationKeyRoot",
        &["algebraicShareVerificationKeyRoot"],
        "rank refresh algebraic share verification-key root",
    )?;
    compare_hash_at_request_field(
        request,
        transcript,
        "expectedAlgebraicShareVerificationKeyHash",
        &["algebraicShareVerificationKeyHash"],
        "rank refresh algebraic share verification-key hash",
    )?;
    compare_hash_at_request_field(
        request,
        transcript,
        "expectedThresholdShareVerificationKeyRoot",
        &["thresholdShareVerificationKeyRoot"],
        "rank refresh threshold share verification-key root",
    )?;
    compare_hash_at_request_field(
        request,
        transcript,
        "expectedThresholdShareVerificationKeyHash",
        &["thresholdShareVerificationKeyHash"],
        "rank refresh threshold share verification-key hash",
    )?;
    if let Some(expected_top_count) = request.get("expectedTopCount") {
        let expected_top_count = expected_top_count.as_u64().ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "expectedTopCount must be a non-negative integer",
            )
        })?;
        let actual_top_count = u64_at_path(transcript, &["topCount"])?;
        if actual_top_count != expected_top_count {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "rank refresh top count does not match the expected evaluator request",
            ));
        }
    }

    require_string_at_path(
        transcript,
        &["ciphertextRole"],
        "packed-rank",
        "rank refresh ciphertext role",
    )?;
    require_bool_at_path(
        transcript,
        &["semanticRankDecryptionAllowed"],
        false,
        "rank refresh semantic rank decryption flag",
    )?;
    require_bool_at_path(
        transcript,
        &["plaintextRankExported"],
        false,
        "rank refresh plaintext rank export flag",
    )?;
    require_bool_at_path(
        transcript,
        &["maskedOpeningOnly"],
        true,
        "rank refresh masked opening flag",
    )?;

    hash_at_path(transcript, &["maskedOpeningRoot"])?;
    value_at_path(transcript, &["maskedOpening"])?;
    hash_at_path(transcript, &["maskedOpeningPayloadRoot"])?;
    value_at_path(transcript, &["maskedOpeningPayload"])?;
    hash_at_path(transcript, &["finDecLagrangeCoefficientAuditRoot"])?;
    value_at_path(transcript, &["finDecLagrangeCoefficientAudit"])?;
    hash_at_path(transcript, &["smudgingBoundCertificateHash"])?;
    value_at_path(transcript, &["smudgingBoundCertificate"])?;
    hash_at_path(transcript, &["maskCommitmentRoot"])?;
    value_at_path(transcript, &["maskCommitment"])?;
    hash_at_path(transcript, &["maskEncryptionRandomnessEvidenceHash"])?;
    value_at_path(transcript, &["maskEncryptionRandomnessEvidence"])?;
    hash_at_path(transcript, &["encryptedMaskCiphertextRoot"])?;
    hash_at_path(transcript, &["encryptedMaskCiphertextPayloadHash"])?;
    value_at_path(transcript, &["encryptedMaskCiphertextPayload"])?;
    hash_at_path(transcript, &["refreshedRankCiphertextRoot"])?;
    hash_at_path(transcript, &["refreshedRankCiphertextPayloadHash"])?;
    value_at_path(transcript, &["refreshedRankCiphertextPayload"])?;
    hash_at_path(transcript, &["inputRankCiphertextComponentOnePayloadHash"])?;
    value_at_path(transcript, &["inputRankCiphertextComponentOnePayload"])?;
    hash_at_path(transcript, &["algebraicShareVerificationKeyRoot"])?;
    hash_at_path(transcript, &["algebraicShareVerificationKeyHash"])?;
    hash_at_path(transcript, &["thresholdShareVerificationKeyRoot"])?;
    hash_at_path(transcript, &["thresholdShareVerificationKeyHash"])?;
    hash_at_path(transcript, &["shareSelectionRuleHash"])?;
    array_at_path(transcript, &["publicKeyShareCoefficientMaterialSidecars"])?;
    array_at_path(
        transcript,
        &["selectedAlgebraicShareVerificationKeyBindings"],
    )?;
    validate_share_selection_rule_hash(transcript)?;
    require_u64_at_path(
        transcript,
        &["polynomialDegree"],
        POLYNOMIAL_DEGREE as u64,
        "rank refresh polynomial degree",
    )?;
    require_u64_at_path(
        transcript,
        &["dataPrimeCount"],
        DATA_PRIMES.len() as u64,
        "rank refresh data-prime count",
    )?;

    validate_smudging_bound_certificate(transcript)?;
    validate_input_rank_ciphertext_component_one_payload(transcript)?;
    validate_mask_re_encryption_ciphertext_payloads(transcript)?;
    validate_mask_commitment_and_randomness_evidence(transcript)?;
    validate_refresh_share_records(transcript)?;
    validate_fin_dec_lagrange_coefficient_audit(transcript)?;
    validate_fin_dec_masked_opening(transcript)?;
    validate_mask_re_encryption_proof_records(transcript)?;
    validate_rank_refresh_transcript_root(transcript)
}

#[derive(Clone)]
struct SetupTrusteeBinding {
    trustee_identity: String,
    roster_position: u64,
    board_position: u64,
    participant_setup_record_hash: String,
    public_key_share_root: String,
    public_key_share_coefficient_material_root: String,
    public_key_share_coefficient_material_hash: String,
    trustee_threshold_verification_key_hash: String,
    interpolation_point: u64,
    local_secret_share_commitment_hash: String,
    local_error_commitment_hash: String,
    threshold_lsss_witness_commitment_hash: String,
}

fn validate_setup_bound_refresh_transcript(
    setup_package: &Value,
    transcript: &Value,
) -> CanonicalResult<()> {
    let setup_package_hash = validated_setup_package_hash(setup_package)?;
    compare_required_hash(
        hash_at_path(transcript, &["setupPackageHash"])?,
        &setup_package_hash,
        "rank refresh setup package hash",
    )?;
    compare_required_hash(
        hash_at_path(transcript, &["collectivePublicKeyRoot"])?,
        string_at_path(
            setup_package,
            &["collectivePublicKey", "collectivePublicKeyRoot"],
        )?,
        "rank refresh collective public key root",
    )?;
    compare_required_hash(
        hash_at_path(transcript, &["bgvPublicKeyRoot"])?,
        string_at_path(setup_package, &["collectivePublicKey", "bgvPublicKeyRoot"])?,
        "rank refresh BGV public key root",
    )?;
    compare_required_hash(
        hash_at_path(transcript, &["evaluationKeyRoot"])?,
        string_at_path(setup_package, &["evaluationKeys", "evaluationKeyRoot"])?,
        "rank refresh evaluation key root",
    )?;
    compare_required_hash(
        hash_at_path(transcript, &["targetLayoutHash"])?,
        string_at_path(setup_package, &["profileBindings", "targetLayoutHash"])?,
        "rank refresh target layout hash",
    )?;
    compare_required_hash(
        hash_at_path(transcript, &["thresholdShareVerificationKeyRoot"])?,
        string_at_path(
            setup_package,
            &[
                "thresholdVerificationMaterial",
                "thresholdShareVerificationKeyRoot",
            ],
        )?,
        "rank refresh threshold share verification-key root",
    )?;
    compare_required_hash(
        hash_at_path(transcript, &["thresholdShareVerificationKeyHash"])?,
        string_at_path(
            setup_package,
            &[
                "thresholdVerificationMaterial",
                "thresholdShareVerificationKeyHash",
            ],
        )?,
        "rank refresh threshold share verification-key hash",
    )?;
    compare_required_hash(
        hash_at_path(transcript, &["algebraicShareVerificationKeyRoot"])?,
        string_at_path(
            setup_package,
            &[
                "thresholdVerificationMaterial",
                "algebraicShareVerificationKeyRoot",
            ],
        )?,
        "rank refresh algebraic share verification-key root",
    )?;
    compare_required_hash(
        hash_at_path(transcript, &["algebraicShareVerificationKeyHash"])?,
        string_at_path(
            setup_package,
            &[
                "thresholdVerificationMaterial",
                "algebraicShareVerificationKeyHash",
            ],
        )?,
        "rank refresh algebraic share verification-key hash",
    )?;

    let trustee_bindings = setup_trustee_bindings(setup_package)?;
    validate_share_selection_rule(setup_package, transcript, &trustee_bindings)?;
    validate_public_key_share_coefficient_material_sidecars(
        setup_package,
        transcript,
        &trustee_bindings,
    )?;
    validate_refresh_share_records_against_setup(setup_package, transcript, &trustee_bindings)
}

fn validated_setup_package_hash(setup_package: &Value) -> CanonicalResult<String> {
    let setup_package_hash = hash_at_path(setup_package, &["setupPackageHash"])?;
    let mut hash_input = setup_package.clone();
    hash_input
        .as_object_mut()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupPackage must be an object",
            )
        })?
        .remove("setupPackageHash");
    let expected_hash = derive_protocol_hash("BGVPassiveSetupPackageHash", &hash_input)?;
    compare_required_hash(
        setup_package_hash,
        &expected_hash,
        "rank refresh setup package canonical hash",
    )?;

    Ok(expected_hash)
}

fn setup_trustee_bindings(setup_package: &Value) -> CanonicalResult<Vec<SetupTrusteeBinding>> {
    let algebraic_trustee_keys = array_at_path(
        setup_package,
        &[
            "thresholdVerificationMaterial",
            "verificationKeySet",
            "algebraicShareVerificationKeySet",
            "trusteeVerificationKeys",
        ],
    )?;
    array_at_path(setup_package, &["participants"])?
        .iter()
        .map(|participant| {
            let trustee_identity = string_at_path(participant, &["trusteeIdentity"])?;
            let roster_position = u64_at_path(participant, &["rosterPosition"])?;
            let algebraic_trustee_key = algebraic_trustee_keys
                .iter()
                .find(|trustee_key| {
                    string_at_path(trustee_key, &["trusteeIdentity"])
                        .map(|value| value == trustee_identity)
                        .unwrap_or(false)
                        && u64_at_path(trustee_key, &["rosterPosition"])
                            .map(|value| value == roster_position)
                            .unwrap_or(false)
                })
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::ProfileComponentMismatch,
                        "rank refresh setup algebraic share-verification key is missing for trustee",
                    )
                })?;
            Ok(SetupTrusteeBinding {
                trustee_identity: trustee_identity.to_string(),
                roster_position,
                board_position: u64_at_path(participant, &["boardPosition"])?,
                participant_setup_record_hash: hash_at_path(
                    participant,
                    &["participantSetupRecordHash"],
                )?
                .to_string(),
                public_key_share_root: hash_at_path(participant, &["publicKeyShareRoot"])?
                    .to_string(),
                public_key_share_coefficient_material_root: hash_at_path(
                    algebraic_trustee_key,
                    &["publicKeyShareCoefficientMaterialRoot"],
                )?
                .to_string(),
                public_key_share_coefficient_material_hash: hash_at_path(
                    algebraic_trustee_key,
                    &["publicKeyShareCoefficientMaterialHash"],
                )?
                .to_string(),
                trustee_threshold_verification_key_hash: hash_at_path(
                    participant,
                    &["trusteeThresholdVerificationKeyHash"],
                )?
                .to_string(),
                interpolation_point: u64_at_path(algebraic_trustee_key, &["interpolationPoint"])?,
                local_secret_share_commitment_hash: hash_at_path(
                    participant,
                    &["localSecretShareCommitmentHash"],
                )?
                .to_string(),
                local_error_commitment_hash: hash_at_path(
                    participant,
                    &["localErrorCommitmentHash"],
                )?
                .to_string(),
                threshold_lsss_witness_commitment_hash: hash_at_path(
                    algebraic_trustee_key,
                    &["thresholdLsssWitnessCommitmentHash"],
                )?
                .to_string(),
            })
        })
        .collect()
}

fn validate_share_selection_rule_hash(transcript: &Value) -> CanonicalResult<()> {
    let rule = value_at_path(transcript, &["shareSelectionRule"])?;
    let expected_hash = derive_protocol_hash("MaskedRankRefreshShareSelectionRuleHash", rule)?;
    compare_required_hash(
        hash_at_path(transcript, &["shareSelectionRuleHash"])?,
        &expected_hash,
        "rank refresh share-selection rule hash",
    )
}

fn setup_decryption_threshold(setup_package: &Value) -> CanonicalResult<u64> {
    u64_at_path(
        setup_package,
        &[
            "thresholdVerificationMaterial",
            "verificationKeySet",
            "algebraicShareVerificationKeySet",
            "decryptionThreshold",
        ],
    )
}

fn validate_share_selection_rule(
    setup_package: &Value,
    transcript: &Value,
    trustee_bindings: &[SetupTrusteeBinding],
) -> CanonicalResult<()> {
    let rule = value_at_path(transcript, &["shareSelectionRule"])?;
    require_string_at_path(
        rule,
        &["objectType"],
        "MaskedRankRefreshShareSelectionRule",
        "rank refresh share-selection rule object type",
    )?;
    require_u64_at_path(
        rule,
        &["objectVersion"],
        1,
        "rank refresh share-selection rule version",
    )?;
    require_string_at_path(
        rule,
        &["profileId"],
        MASKED_RANK_REFRESH_PROFILE_ID,
        "rank refresh share-selection rule profile id",
    )?;
    compare_required_hash(
        hash_at_path(rule, &["setupPackageHash"])?,
        hash_at_path(transcript, &["setupPackageHash"])?,
        "rank refresh share-selection setup package hash",
    )?;
    compare_required_hash(
        hash_at_path(rule, &["thresholdProfileHash"])?,
        string_at_path(setup_package, &["setupInputs", "thresholdProfileHash"])?,
        "rank refresh share-selection threshold profile hash",
    )?;
    compare_required_hash(
        hash_at_path(rule, &["thresholdShareVerificationKeyHash"])?,
        hash_at_path(transcript, &["thresholdShareVerificationKeyHash"])?,
        "rank refresh share-selection threshold share verification-key hash",
    )?;
    compare_required_hash(
        hash_at_path(rule, &["algebraicShareVerificationKeyHash"])?,
        hash_at_path(transcript, &["algebraicShareVerificationKeyHash"])?,
        "rank refresh share-selection algebraic share verification-key hash",
    )?;
    require_string_at_path(
        rule,
        &["selectedShareRule"],
        "FirstValidSharesInCanonicalBoardOrder",
        "rank refresh selected share rule",
    )?;
    require_string_at_path(
        rule,
        &["invalidShareFilteringMode"],
        "ProofVerifiedSharesOnly",
        "rank refresh invalid-share filtering mode",
    )?;
    let decryption_threshold = setup_decryption_threshold(setup_package)?;
    require_u64_at_path(
        rule,
        &["decryptionThreshold"],
        decryption_threshold,
        "rank refresh share-selection decryption threshold",
    )?;
    let participant_count = u64_at_path(rule, &["participantCount"])?;
    if participant_count
        != u64::try_from(trustee_bindings.len()).expect("participant count fits u64")
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "rank refresh share-selection participant count does not match setup",
        ));
    }
    let selected_share_count = u64_at_path(rule, &["selectedShareCount"])?;
    let minimum_shares_for_interpolation = u64_at_path(rule, &["minimumSharesForInterpolation"])?;
    if selected_share_count != decryption_threshold
        || minimum_shares_for_interpolation != decryption_threshold
        || decryption_threshold == 0
        || decryption_threshold > participant_count
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "rank refresh share-selection must select exactly the setup decryption threshold",
        ));
    }
    let decryption_threshold_usize = usize::try_from(decryption_threshold).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rank refresh share-selection threshold does not fit usize",
        )
    })?;
    let mut expected_canonical_trustees = trustee_bindings.iter().collect::<Vec<_>>();
    expected_canonical_trustees.sort_by(|left, right| {
        left.board_position
            .cmp(&right.board_position)
            .then_with(|| left.roster_position.cmp(&right.roster_position))
            .then_with(|| left.trustee_identity.cmp(&right.trustee_identity))
    });
    let expected_canonical_trustees = expected_canonical_trustees
        .get(..decryption_threshold_usize)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "rank refresh share-selection threshold exceeds setup participants",
            )
        })?;

    let share_records = array_at_path(transcript, &["rankRefreshShareRecords"])?;
    if selected_share_count
        != u64::try_from(share_records.len()).expect("share record count fits u64")
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "rank refresh selected share count does not match share records",
        ));
    }
    let selected_identities = array_at_path(rule, &["selectedTrusteeIdentities"])?;
    let selected_roster_positions = array_at_path(rule, &["selectedRosterPositions"])?;
    if selected_identities.len() != share_records.len()
        || selected_roster_positions.len() != share_records.len()
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rank refresh selected trustee lists must match share records",
        ));
    }

    for (record_index, share_record) in share_records.iter().enumerate() {
        let selected_identity = selected_identities[record_index].as_str().ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "rank refresh selected trustee identities must be strings",
            )
        })?;
        let selected_roster_position = selected_roster_positions[record_index]
            .as_u64()
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "rank refresh selected roster positions must be non-negative integers",
                )
            })?;
        let expected_trustee = expected_canonical_trustees[record_index];
        if selected_identity != expected_trustee.trustee_identity
            || selected_roster_position != expected_trustee.roster_position
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "rank refresh share-selection trustees do not match canonical threshold board order",
            ));
        }
        if selected_identity != string_at_path(share_record, &["trusteeIdentity"])?
            || selected_roster_position != u64_at_path(share_record, &["rosterPosition"])?
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "rank refresh share-selection trustee order does not match share records",
            ));
        }
    }

    Ok(())
}

fn validate_refresh_share_records_against_setup(
    setup_package: &Value,
    transcript: &Value,
    trustee_bindings: &[SetupTrusteeBinding],
) -> CanonicalResult<()> {
    let threshold_share_verification_key_root =
        hash_at_path(transcript, &["thresholdShareVerificationKeyRoot"])?;
    let threshold_share_verification_key_hash =
        hash_at_path(transcript, &["thresholdShareVerificationKeyHash"])?;
    let algebraic_share_verification_key_hash =
        hash_at_path(transcript, &["algebraicShareVerificationKeyHash"])?;
    let algebraic_share_verification_key_root =
        hash_at_path(transcript, &["algebraicShareVerificationKeyRoot"])?;
    let share_records = array_at_path(transcript, &["rankRefreshShareRecords"])?;
    let sidecars = array_at_path(transcript, &["publicKeyShareCoefficientMaterialSidecars"])?;
    let selected_key_bindings = array_at_path(
        transcript,
        &["selectedAlgebraicShareVerificationKeyBindings"],
    )?;
    if sidecars.len() != share_records.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rank refresh public key-share coefficient sidecars must match share records",
        ));
    }
    if selected_key_bindings.len() != share_records.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rank refresh selected algebraic share-verification key bindings must match share records",
        ));
    }
    for (record_index, record) in share_records.iter().enumerate() {
        let trustee_identity = string_at_path(record, &["trusteeIdentity"])?;
        let trustee_binding = trustee_bindings
            .iter()
            .find(|binding| binding.trustee_identity == trustee_identity)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "rank refresh share trustee is not part of setup",
                )
            })?;
        if u64_at_path(record, &["rosterPosition"])? != trustee_binding.roster_position {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "rank refresh share roster position does not match setup",
            ));
        }
        compare_required_hash(
            hash_at_path(record, &["participantSetupRecordHash"])?,
            &trustee_binding.participant_setup_record_hash,
            "rank refresh share participant setup record hash",
        )?;
        compare_required_hash(
            hash_at_path(record, &["publicKeyShareCoefficientMaterialRoot"])?,
            &trustee_binding.public_key_share_coefficient_material_root,
            "rank refresh share public key-share coefficient material root",
        )?;
        compare_required_hash(
            hash_at_path(record, &["publicKeyShareCoefficientMaterialHash"])?,
            &trustee_binding.public_key_share_coefficient_material_hash,
            "rank refresh share public key-share coefficient material hash",
        )?;
        compare_required_hash(
            hash_at_path(record, &["trusteeThresholdVerificationKeyHash"])?,
            &trustee_binding.trustee_threshold_verification_key_hash,
            "rank refresh share trustee verification-key hash",
        )?;
        compare_required_hash(
            hash_at_path(record, &["thresholdShareVerificationKeyRoot"])?,
            threshold_share_verification_key_root,
            "rank refresh share threshold verification-key root",
        )?;
        compare_required_hash(
            hash_at_path(record, &["thresholdShareVerificationKeyHash"])?,
            threshold_share_verification_key_hash,
            "rank refresh share threshold verification-key hash",
        )?;
        compare_required_hash(
            hash_at_path(record, &["algebraicShareVerificationKeyHash"])?,
            algebraic_share_verification_key_hash,
            "rank refresh share algebraic verification-key hash",
        )?;
        validate_selected_algebraic_share_verification_key_binding(
            SelectedAlgebraicShareVerificationKeyBindingContext {
                transcript,
                selected_key_binding: &selected_key_bindings[record_index],
                record,
                trustee_binding,
                selected_share_index: record_index,
                threshold_share_verification_key_root,
                threshold_share_verification_key_hash,
                algebraic_share_verification_key_root,
                algebraic_share_verification_key_hash,
            },
        )?;
        validate_part_dec_share_equation_proof(PartDecShareEquationProofContext {
            setup_package,
            transcript,
            record,
            selected_sidecar: &sidecars[record_index],
            trustee_binding,
            threshold_share_verification_key_hash,
            algebraic_share_verification_key_root,
            algebraic_share_verification_key_hash,
        })?;
    }

    Ok(())
}

struct SelectedAlgebraicShareVerificationKeyBindingContext<'a> {
    transcript: &'a Value,
    selected_key_binding: &'a Value,
    record: &'a Value,
    trustee_binding: &'a SetupTrusteeBinding,
    selected_share_index: usize,
    threshold_share_verification_key_root: &'a str,
    threshold_share_verification_key_hash: &'a str,
    algebraic_share_verification_key_root: &'a str,
    algebraic_share_verification_key_hash: &'a str,
}

fn validate_selected_algebraic_share_verification_key_binding(
    context: SelectedAlgebraicShareVerificationKeyBindingContext<'_>,
) -> CanonicalResult<()> {
    let SelectedAlgebraicShareVerificationKeyBindingContext {
        transcript,
        selected_key_binding,
        record,
        trustee_binding,
        selected_share_index,
        threshold_share_verification_key_root,
        threshold_share_verification_key_hash,
        algebraic_share_verification_key_root,
        algebraic_share_verification_key_hash,
    } = context;
    compare_derived_hash(
        "MaskedRankRefreshSelectedAlgebraicShareVerificationKeyBindingRoot",
        selected_key_binding,
        hash_at_path(
            record,
            &["selectedAlgebraicShareVerificationKeyBindingRoot"],
        )?,
        "rank refresh selected algebraic share-verification key binding root",
    )?;
    require_string_at_path(
        selected_key_binding,
        &["objectType"],
        SELECTED_ALGEBRAIC_SHARE_VERIFICATION_KEY_BINDING_OBJECT_TYPE,
        "rank refresh selected algebraic share-verification key binding object type",
    )?;
    require_u64_at_path(
        selected_key_binding,
        &["objectVersion"],
        1,
        "rank refresh selected algebraic share-verification key binding version",
    )?;
    require_string_at_path(
        selected_key_binding,
        &["profileId"],
        MASKED_RANK_REFRESH_PROFILE_ID,
        "rank refresh selected algebraic share-verification key binding profile id",
    )?;
    require_string_at_path(
        selected_key_binding,
        &["bindingStatus"],
        "SelectedAlgebraicShareVerificationKeyBound",
        "rank refresh selected algebraic share-verification key binding status",
    )?;
    require_string_at_path(
        selected_key_binding,
        &["proofSystemStatus"],
        "ZeroKnowledgeShareEquationProofPending",
        "rank refresh selected algebraic share-verification proof status",
    )?;
    require_u64_at_path(
        selected_key_binding,
        &["selectedShareIndex"],
        selected_share_index as u64,
        "rank refresh selected algebraic share-verification key binding index",
    )?;
    compare_required_hash(
        hash_at_path(selected_key_binding, &["setupPackageHash"])?,
        hash_at_path(transcript, &["setupPackageHash"])?,
        "rank refresh selected algebraic share-verification setup package hash",
    )?;
    compare_required_hash(
        hash_at_path(selected_key_binding, &["shareSelectionRuleHash"])?,
        hash_at_path(transcript, &["shareSelectionRuleHash"])?,
        "rank refresh selected algebraic share-verification share-selection hash",
    )?;
    compare_required_hash(
        hash_at_path(selected_key_binding, &["thresholdShareVerificationKeyRoot"])?,
        threshold_share_verification_key_root,
        "rank refresh selected algebraic share-verification threshold key root",
    )?;
    compare_required_hash(
        hash_at_path(selected_key_binding, &["thresholdShareVerificationKeyHash"])?,
        threshold_share_verification_key_hash,
        "rank refresh selected algebraic share-verification threshold key hash",
    )?;
    compare_required_hash(
        hash_at_path(selected_key_binding, &["algebraicShareVerificationKeyRoot"])?,
        algebraic_share_verification_key_root,
        "rank refresh selected algebraic share-verification key root",
    )?;
    compare_required_hash(
        hash_at_path(selected_key_binding, &["algebraicShareVerificationKeyHash"])?,
        algebraic_share_verification_key_hash,
        "rank refresh selected algebraic share-verification key hash",
    )?;
    compare_required_hash(
        hash_at_path(selected_key_binding, &["participantSetupRecordHash"])?,
        &trustee_binding.participant_setup_record_hash,
        "rank refresh selected algebraic share-verification participant setup hash",
    )?;
    compare_required_hash(
        hash_at_path(selected_key_binding, &["publicKeyShareRoot"])?,
        &trustee_binding.public_key_share_root,
        "rank refresh selected algebraic share-verification public key-share root",
    )?;
    compare_required_hash(
        hash_at_path(
            selected_key_binding,
            &["publicKeyShareCoefficientMaterialRoot"],
        )?,
        &trustee_binding.public_key_share_coefficient_material_root,
        "rank refresh selected algebraic share-verification public sidecar root",
    )?;
    compare_required_hash(
        hash_at_path(
            selected_key_binding,
            &["publicKeyShareCoefficientMaterialHash"],
        )?,
        &trustee_binding.public_key_share_coefficient_material_hash,
        "rank refresh selected algebraic share-verification public sidecar hash",
    )?;
    compare_required_hash(
        hash_at_path(
            selected_key_binding,
            &["trusteeThresholdVerificationKeyHash"],
        )?,
        &trustee_binding.trustee_threshold_verification_key_hash,
        "rank refresh selected algebraic share-verification trustee key hash",
    )?;
    compare_required_hash(
        hash_at_path(selected_key_binding, &["localSecretShareCommitmentHash"])?,
        &trustee_binding.local_secret_share_commitment_hash,
        "rank refresh selected algebraic share-verification local secret commitment hash",
    )?;
    compare_required_hash(
        hash_at_path(selected_key_binding, &["localErrorCommitmentHash"])?,
        &trustee_binding.local_error_commitment_hash,
        "rank refresh selected algebraic share-verification local error commitment hash",
    )?;
    compare_required_hash(
        hash_at_path(
            selected_key_binding,
            &["thresholdLsssWitnessCommitmentHash"],
        )?,
        &trustee_binding.threshold_lsss_witness_commitment_hash,
        "rank refresh selected algebraic share-verification witness commitment hash",
    )?;
    compare_string_value(
        string_at_path(selected_key_binding, &["trusteeIdentity"])?,
        &trustee_binding.trustee_identity,
        "rank refresh selected algebraic share-verification trustee identity",
    )?;
    if u64_at_path(selected_key_binding, &["rosterPosition"])? != trustee_binding.roster_position
        || u64_at_path(selected_key_binding, &["interpolationPoint"])?
            != trustee_binding.interpolation_point
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "rank refresh selected algebraic share-verification trustee position does not match setup",
        ));
    }
    require_string_at_path(
        selected_key_binding,
        &["publicKeyShareCoefficientMaterialTransport"],
        "root-bound-public-sidecar-required-for-claim-bearing-PartDec-verification",
        "rank refresh selected algebraic share-verification sidecar transport",
    )?;
    require_string_at_path(
        selected_key_binding,
        &["publicKeyShareConsistencyEquation"],
        "publicKeyShareComponentZero + publicCommonRandomPolynomial * trusteeSecretShare = plaintextModulus * trusteeErrorShare mod q",
        "rank refresh selected algebraic share-verification public key-share equation",
    )?;
    require_string_at_path(
        selected_key_binding,
        &["partDecShareEquation"],
        "partialDecryptionShare = ciphertextComponentOne * trusteeSecretShare + smudgingNoise mod q",
        "rank refresh selected algebraic share-verification PartDec equation",
    )?;
    require_bool_at_path(
        selected_key_binding,
        &["shareEquationProofRequired"],
        true,
        "rank refresh selected algebraic share-verification proof-required flag",
    )?;
    require_bool_at_path(
        selected_key_binding,
        &["publicKeyShareCoefficientMaterialIncluded"],
        false,
        "rank refresh selected algebraic share-verification sidecar-included flag",
    )?;
    require_bool_at_path(
        selected_key_binding,
        &["rawSecretShareExported"],
        false,
        "rank refresh selected algebraic share-verification secret export flag",
    )?;
    require_bool_at_path(
        selected_key_binding,
        &["thresholdSecretShareExported"],
        false,
        "rank refresh selected algebraic share-verification threshold share export flag",
    )?;
    compare_required_hash(
        hash_at_path(
            value_at_path(record, &["shareEquationProof"])?,
            &["selectedAlgebraicShareVerificationKeyBindingRoot"],
        )?,
        hash_at_path(
            record,
            &["selectedAlgebraicShareVerificationKeyBindingRoot"],
        )?,
        "rank refresh PartDec proof selected algebraic share-verification key binding root",
    )?;

    Ok(())
}

fn validate_public_key_share_coefficient_material_sidecars(
    setup_package: &Value,
    transcript: &Value,
    trustee_bindings: &[SetupTrusteeBinding],
) -> CanonicalResult<()> {
    let sidecars = array_at_path(transcript, &["publicKeyShareCoefficientMaterialSidecars"])?;
    let share_records = array_at_path(transcript, &["rankRefreshShareRecords"])?;
    if sidecars.len() != share_records.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rank refresh public key-share coefficient sidecars must match share records",
        ));
    }
    for (sidecar_index, (sidecar, share_record)) in
        sidecars.iter().zip(share_records.iter()).enumerate()
    {
        let trustee_identity = string_at_path(share_record, &["trusteeIdentity"])?;
        let trustee_binding = trustee_bindings
            .iter()
            .find(|binding| binding.trustee_identity == trustee_identity)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "rank refresh public key-share coefficient sidecar trustee is not part of setup",
                )
            })?;
        let verification = validate_trustee_public_key_share_coefficient_material_sidecar(
            setup_package,
            trustee_identity,
            sidecar,
        )?;
        compare_required_hash(
            hash_at_path(&verification, &["publicKeyShareCoefficientMaterialRoot"])?,
            &trustee_binding.public_key_share_coefficient_material_root,
            "rank refresh sidecar public key-share coefficient material root",
        )?;
        compare_required_hash(
            hash_at_path(&verification, &["publicKeyShareCoefficientMaterialHash"])?,
            &trustee_binding.public_key_share_coefficient_material_hash,
            "rank refresh sidecar public key-share coefficient material hash",
        )?;
        compare_required_hash(
            hash_at_path(share_record, &["publicKeyShareCoefficientMaterialRoot"])?,
            hash_at_path(&verification, &["publicKeyShareCoefficientMaterialRoot"])?,
            "rank refresh share public key-share coefficient sidecar root",
        )?;
        compare_required_hash(
            hash_at_path(share_record, &["publicKeyShareCoefficientMaterialHash"])?,
            hash_at_path(&verification, &["publicKeyShareCoefficientMaterialHash"])?,
            "rank refresh share public key-share coefficient sidecar hash",
        )?;
        let proof = value_at_path(share_record, &["shareEquationProof"])?;
        compare_required_hash(
            hash_at_path(proof, &["publicKeyShareCoefficientMaterialRoot"])?,
            hash_at_path(&verification, &["publicKeyShareCoefficientMaterialRoot"])?,
            "rank refresh PartDec proof public key-share coefficient sidecar root",
        )?;
        compare_required_hash(
            hash_at_path(proof, &["publicKeyShareCoefficientMaterialHash"])?,
            hash_at_path(&verification, &["publicKeyShareCoefficientMaterialHash"])?,
            "rank refresh PartDec proof public key-share coefficient sidecar hash",
        )?;
        if string_at_path(sidecar, &["trusteeIdentity"])? != trustee_identity {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!(
                    "rank refresh public key-share coefficient sidecar {sidecar_index} trustee identity does not match share record"
                ),
            ));
        }
    }

    Ok(())
}

fn validate_input_rank_ciphertext_component_one_payload(transcript: &Value) -> CanonicalResult<()> {
    let payload = value_at_path(transcript, &["inputRankCiphertextComponentOnePayload"])?;
    compare_derived_hash(
        "MaskedRankRefreshInputRankCiphertextComponentOnePayloadHash",
        payload,
        hash_at_path(transcript, &["inputRankCiphertextComponentOnePayloadHash"])?,
        "rank refresh input rank ciphertext component-one payload hash",
    )?;
    require_string_at_path(
        payload,
        &["objectType"],
        INPUT_RANK_CIPHERTEXT_COMPONENT_ONE_PAYLOAD_OBJECT_TYPE,
        "rank refresh input rank ciphertext component-one payload object type",
    )?;
    require_u64_at_path(
        payload,
        &["objectVersion"],
        1,
        "rank refresh input rank ciphertext component-one payload version",
    )?;
    require_string_at_path(
        payload,
        &["profileId"],
        MASKED_RANK_REFRESH_PROFILE_ID,
        "rank refresh input rank ciphertext component-one payload profile id",
    )?;
    require_string_at_path(
        payload,
        &["payloadStatus"],
        "PublicInputRankCiphertextComponentOnePayloadBound",
        "rank refresh input rank ciphertext component-one payload status",
    )?;
    require_string_at_path(
        payload,
        &["ciphertextRole"],
        "packed-rank",
        "rank refresh input rank ciphertext component-one payload ciphertext role",
    )?;
    require_string_at_path(
        payload,
        &["ciphertextComponentRole"],
        "ciphertext-component-one",
        "rank refresh input rank ciphertext component-one role",
    )?;
    require_u64_at_path(
        payload,
        &["componentIndex"],
        1,
        "rank refresh input rank ciphertext component-one index",
    )?;
    require_u64_at_path(
        payload,
        &["componentCount"],
        2,
        "rank refresh input rank ciphertext component count",
    )?;
    require_string_at_path(
        payload,
        &["basisId"],
        "data",
        "rank refresh input rank ciphertext component-one basis id",
    )?;
    require_string_at_path(
        payload,
        &["coefficientDomain"],
        "coefficient",
        "rank refresh input rank ciphertext component-one coefficient domain",
    )?;
    require_string_at_path(
        payload,
        &["coefficientEncoding"],
        "little-endian-u64-coefficient-vectors-by-data-prime",
        "rank refresh input rank ciphertext component-one coefficient encoding",
    )?;
    require_u64_at_path(
        payload,
        &["polynomialDegree"],
        POLYNOMIAL_DEGREE as u64,
        "rank refresh input rank ciphertext component-one polynomial degree",
    )?;
    compare_required_hash(
        hash_at_path(payload, &["setupPackageHash"])?,
        hash_at_path(transcript, &["setupPackageHash"])?,
        "rank refresh input rank ciphertext component-one setup package hash",
    )?;
    compare_required_hash(
        hash_at_path(payload, &["evaluationContextHash"])?,
        hash_at_path(transcript, &["evaluationContextHash"])?,
        "rank refresh input rank ciphertext component-one evaluation context hash",
    )?;
    compare_required_hash(
        hash_at_path(payload, &["inputRankCiphertextRoot"])?,
        hash_at_path(transcript, &["inputRankCiphertextRoot"])?,
        "rank refresh input rank ciphertext component-one input rank root",
    )?;
    compare_required_hash(
        hash_at_path(payload, &["canonicalCiphertextConventionHash"])?,
        &canonical_ciphertext_convention_hash()?,
        "rank refresh input rank ciphertext component-one convention hash",
    )?;

    let canonical_bytes_hex = string_at_path(payload, &["canonicalBytesHex"])?;
    let canonical_bytes = decode_hex(canonical_bytes_hex)?;
    let parsed = parse_bgv_object_hex(canonical_bytes_hex)?;
    if parsed.object_kind != BgvObjectKind::Ciphertext {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "rank refresh input rank payload must be a canonical BGV ciphertext",
        ));
    }
    if parsed.components.len() != 2 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rank refresh input rank payload must be a two-component BGV ciphertext",
        ));
    }
    let component_one = &parsed.components[1];
    require_u64_at_path(
        payload,
        &["level"],
        component_one.level as u64,
        "rank refresh input rank ciphertext component-one level",
    )?;
    require_u64_at_path(
        payload,
        &["dataPrimeCount"],
        component_one.moduli.len() as u64,
        "rank refresh input rank ciphertext component-one data-prime count",
    )?;
    compare_required_hash(
        hash_at_path(payload, &["ciphertextRoot"])?,
        &ciphertext_root(&canonical_bytes),
        "rank refresh input rank ciphertext root",
    )?;
    compare_required_hash(
        hash_at_path(payload, &["inputRankCiphertextRoot"])?,
        hash_at_path(payload, &["ciphertextRoot"])?,
        "rank refresh input rank component-one payload root alias",
    )?;
    compare_required_hash(
        string_at_path(payload, &["canonicalBytesHash512"])?,
        &canonical_bytes_hash(&canonical_bytes),
        "rank refresh input rank ciphertext canonical bytes hash",
    )?;
    require_u64_at_path(
        payload,
        &["canonicalByteLength"],
        canonical_bytes.len() as u64,
        "rank refresh input rank ciphertext canonical byte length",
    )?;
    validate_component_one_coefficient_tables(
        payload,
        &component_one.moduli,
        &component_one.residues_by_modulus,
    )
}

fn validate_component_one_coefficient_tables(
    payload: &Value,
    moduli: &[u64],
    residues_by_modulus: &[Vec<u64>],
) -> CanonicalResult<()> {
    let tables = array_at_path(payload, &["componentOneCoefficientTables"])?;
    if tables.len() != residues_by_modulus.len() || tables.len() != moduli.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rank refresh input rank ciphertext component-one tables must match the canonical ciphertext level",
        ));
    }
    for (modulus_index, ((table, modulus), residues)) in tables
        .iter()
        .zip(moduli.iter())
        .zip(residues_by_modulus.iter())
        .enumerate()
    {
        require_u64_at_path(
            table,
            &["modulusIndex"],
            modulus_index as u64,
            "rank refresh input rank ciphertext component-one modulus index",
        )?;
        require_u64_at_path(
            table,
            &["modulus"],
            *modulus,
            "rank refresh input rank ciphertext component-one modulus",
        )?;
        require_string_at_path(
            table,
            &["coefficientEncoding"],
            "little-endian-u64",
            "rank refresh input rank ciphertext component-one coefficient encoding",
        )?;
        require_u64_at_path(
            table,
            &["coefficientByteLength"],
            (POLYNOMIAL_DEGREE * 8) as u64,
            "rank refresh input rank ciphertext component-one coefficient byte length",
        )?;
        let coefficients = coefficient_vector_from_le_hex(
            string_at_path(table, &["componentOneCoefficientsLeHex"])?,
            "rank refresh input rank ciphertext component-one coefficients",
        )?;
        if coefficients != *residues {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "rank refresh input rank ciphertext component-one coefficients do not match canonical bytes",
            ));
        }
        compare_required_hash(
            string_at_path(table, &["componentOneCoefficientHash512"])?,
            &hash512_hex(
                "sealed-lattice-bgv-rns/masked-rank-refresh-input-rank-ciphertext-component-one-coefficient-vector-v1",
                &[&coefficient_vector_bytes(&coefficients)],
            ),
            "rank refresh input rank ciphertext component-one coefficient hash",
        )?;
    }

    Ok(())
}

fn validate_mask_re_encryption_ciphertext_payloads(transcript: &Value) -> CanonicalResult<()> {
    validate_mask_re_encryption_ciphertext_payload(
        transcript,
        &MaskReEncryptionCiphertextPayloadBinding {
            payload_field: "encryptedMaskCiphertextPayload",
            payload_hash_field: "encryptedMaskCiphertextPayloadHash",
            root_field: "encryptedMaskCiphertextRoot",
            root_alias_field: "encryptedMaskCiphertextRoot",
            hash_namespace: "MaskedRankRefreshEncryptedMaskCiphertextPayloadHash",
            ciphertext_role: "encrypted-mask",
            label: "rank refresh encrypted mask ciphertext payload",
        },
    )?;
    validate_mask_re_encryption_ciphertext_payload(
        transcript,
        &MaskReEncryptionCiphertextPayloadBinding {
            payload_field: "refreshedRankCiphertextPayload",
            payload_hash_field: "refreshedRankCiphertextPayloadHash",
            root_field: "refreshedRankCiphertextRoot",
            root_alias_field: "refreshedRankCiphertextRoot",
            hash_namespace: "MaskedRankRefreshRefreshedRankCiphertextPayloadHash",
            ciphertext_role: "refreshed-packed-rank",
            label: "rank refresh refreshed rank ciphertext payload",
        },
    )
}

fn validate_mask_re_encryption_ciphertext_payload(
    transcript: &Value,
    binding: &MaskReEncryptionCiphertextPayloadBinding<'_>,
) -> CanonicalResult<()> {
    let payload = value_at_path(transcript, &[binding.payload_field])?;
    compare_derived_hash(
        binding.hash_namespace,
        payload,
        hash_at_path(transcript, &[binding.payload_hash_field])?,
        &format!("{} hash", binding.label),
    )?;
    require_string_at_path(
        payload,
        &["objectType"],
        MASK_RE_ENCRYPTION_CIPHERTEXT_PAYLOAD_OBJECT_TYPE,
        &format!("{} object type", binding.label),
    )?;
    require_u64_at_path(
        payload,
        &["objectVersion"],
        1,
        &format!("{} version", binding.label),
    )?;
    require_string_at_path(
        payload,
        &["profileId"],
        MASKED_RANK_REFRESH_PROFILE_ID,
        &format!("{} profile id", binding.label),
    )?;
    require_string_at_path(
        payload,
        &["payloadStatus"],
        "PublicMaskReEncryptionCiphertextPayloadBound",
        &format!("{} status", binding.label),
    )?;
    require_string_at_path(
        payload,
        &["ciphertextRole"],
        binding.ciphertext_role,
        &format!("{} ciphertext role", binding.label),
    )?;
    require_string_at_path(
        payload,
        &["basisId"],
        "data",
        &format!("{} basis", binding.label),
    )?;
    require_string_at_path(
        payload,
        &["coefficientDomain"],
        "coefficient",
        &format!("{} coefficient domain", binding.label),
    )?;
    require_string_at_path(
        payload,
        &["coefficientEncoding"],
        "canonical-bgv-rns-ciphertext-bytes",
        &format!("{} coefficient encoding", binding.label),
    )?;
    require_u64_at_path(
        payload,
        &["componentCount"],
        2,
        &format!("{} component count", binding.label),
    )?;
    require_u64_at_path(
        payload,
        &["level"],
        (DATA_PRIMES.len() - 1) as u64,
        &format!("{} level", binding.label),
    )?;
    require_u64_at_path(
        payload,
        &["dataPrimeCount"],
        DATA_PRIMES.len() as u64,
        &format!("{} data prime count", binding.label),
    )?;
    require_u64_at_path(
        payload,
        &["polynomialDegree"],
        POLYNOMIAL_DEGREE as u64,
        &format!("{} polynomial degree", binding.label),
    )?;
    compare_required_hash(
        hash_at_path(payload, &["setupPackageHash"])?,
        hash_at_path(transcript, &["setupPackageHash"])?,
        &format!("{} setup package hash", binding.label),
    )?;
    compare_required_hash(
        hash_at_path(payload, &["collectivePublicKeyRoot"])?,
        hash_at_path(transcript, &["collectivePublicKeyRoot"])?,
        &format!("{} collective public key root", binding.label),
    )?;
    compare_required_hash(
        hash_at_path(payload, &["bgvPublicKeyRoot"])?,
        hash_at_path(transcript, &["bgvPublicKeyRoot"])?,
        &format!("{} BGV public key root", binding.label),
    )?;
    compare_required_hash(
        hash_at_path(payload, &["targetLayoutHash"])?,
        hash_at_path(transcript, &["targetLayoutHash"])?,
        &format!("{} target layout hash", binding.label),
    )?;
    compare_required_hash(
        hash_at_path(payload, &["evaluationContextHash"])?,
        hash_at_path(transcript, &["evaluationContextHash"])?,
        &format!("{} evaluation context hash", binding.label),
    )?;
    compare_required_hash(
        hash_at_path(payload, &[binding.root_alias_field])?,
        hash_at_path(transcript, &[binding.root_field])?,
        &format!("{} transcript root alias", binding.label),
    )?;
    compare_required_hash(
        hash_at_path(payload, &["canonicalCiphertextConventionHash"])?,
        &canonical_ciphertext_convention_hash()?,
        &format!("{} convention hash", binding.label),
    )?;

    let canonical_bytes_hex = string_at_path(payload, &["canonicalBytesHex"])?;
    let canonical_bytes = decode_hex(canonical_bytes_hex)?;
    let parsed = parse_bgv_object_hex(canonical_bytes_hex)?;
    if parsed.object_kind != BgvObjectKind::Ciphertext {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{} must be a canonical BGV ciphertext", binding.label),
        ));
    }
    if parsed.components.len() != 2 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{} must be a two-component BGV ciphertext", binding.label),
        ));
    }
    for component in &parsed.components {
        if component.basis_id != BgvBasisKind::Data.basis_id()
            || component.level != DATA_PRIMES.len() - 1
            || component.moduli.as_slice() != DATA_PRIMES.as_slice()
            || component.coefficient_count != POLYNOMIAL_DEGREE
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!("{} shape does not match the full data basis", binding.label),
            ));
        }
    }
    let actual_ciphertext_root = ciphertext_root(&canonical_bytes);
    compare_required_hash(
        hash_at_path(payload, &["ciphertextRoot"])?,
        &actual_ciphertext_root,
        &format!("{} ciphertext root", binding.label),
    )?;
    compare_required_hash(
        hash_at_path(payload, &[binding.root_alias_field])?,
        &actual_ciphertext_root,
        &format!("{} root alias", binding.label),
    )?;
    compare_required_hash(
        string_at_path(payload, &["canonicalBytesHash512"])?,
        &canonical_bytes_hash(&canonical_bytes),
        &format!("{} canonical bytes hash", binding.label),
    )?;
    require_u64_at_path(
        payload,
        &["canonicalByteLength"],
        canonical_bytes.len() as u64,
        &format!("{} canonical byte length", binding.label),
    )?;

    Ok(())
}

fn validate_mask_commitment_and_randomness_evidence(transcript: &Value) -> CanonicalResult<()> {
    let mask_commitment = value_at_path(transcript, &["maskCommitment"])?;
    compare_derived_hash(
        "MaskedRankRefreshMaskCommitmentRoot",
        mask_commitment,
        hash_at_path(transcript, &["maskCommitmentRoot"])?,
        "rank refresh mask commitment root",
    )?;
    require_string_at_path(
        mask_commitment,
        &["objectType"],
        MASK_COMMITMENT_OBJECT_TYPE,
        "rank refresh mask commitment object type",
    )?;
    require_u64_at_path(
        mask_commitment,
        &["objectVersion"],
        1,
        "rank refresh mask commitment version",
    )?;
    require_string_at_path(
        mask_commitment,
        &["profileId"],
        MASKED_RANK_REFRESH_PROFILE_ID,
        "rank refresh mask commitment profile id",
    )?;
    require_string_at_path(
        mask_commitment,
        &["commitmentStatus"],
        "MaskCommitmentBound",
        "rank refresh mask commitment status",
    )?;
    require_string_at_path(
        mask_commitment,
        &["commitmentScheme"],
        "masked-rank-refresh-witness-private-mask-commitment-v1",
        "rank refresh mask commitment scheme",
    )?;
    require_string_at_path(
        mask_commitment,
        &["openingProofStatus"],
        "MaskOpeningProofPending",
        "rank refresh mask commitment opening proof status",
    )?;
    require_bool_at_path(
        mask_commitment,
        &["rawWitnessExported"],
        false,
        "rank refresh mask commitment raw witness export flag",
    )?;
    require_bool_at_path(
        mask_commitment,
        &["maskPlaintextExported"],
        false,
        "rank refresh mask commitment plaintext export flag",
    )?;
    require_bool_at_path(
        mask_commitment,
        &["semanticRankOpeningAllowed"],
        false,
        "rank refresh mask commitment semantic opening flag",
    )?;
    compare_required_hash(
        hash_at_path(mask_commitment, &["setupPackageHash"])?,
        hash_at_path(transcript, &["setupPackageHash"])?,
        "rank refresh mask commitment setup package hash",
    )?;
    compare_required_hash(
        hash_at_path(mask_commitment, &["evaluationContextHash"])?,
        hash_at_path(transcript, &["evaluationContextHash"])?,
        "rank refresh mask commitment evaluation context hash",
    )?;
    compare_required_hash(
        hash_at_path(mask_commitment, &["inputRankCiphertextRoot"])?,
        hash_at_path(transcript, &["inputRankCiphertextRoot"])?,
        "rank refresh mask commitment input rank root",
    )?;
    compare_required_hash(
        hash_at_path(mask_commitment, &["maskedOpeningPayloadRoot"])?,
        hash_at_path(transcript, &["maskedOpeningPayloadRoot"])?,
        "rank refresh mask commitment masked-opening payload root",
    )?;
    compare_required_hash(
        hash_at_path(mask_commitment, &["smudgingBoundCertificateHash"])?,
        hash_at_path(transcript, &["smudgingBoundCertificateHash"])?,
        "rank refresh mask commitment smudging-bound certificate hash",
    )?;
    compare_required_hash(
        hash_at_path(mask_commitment, &["shareSelectionRuleHash"])?,
        hash_at_path(transcript, &["shareSelectionRuleHash"])?,
        "rank refresh mask commitment share-selection rule hash",
    )?;
    compare_required_hash(
        hash_at_path(mask_commitment, &["encryptedMaskCiphertextRoot"])?,
        hash_at_path(transcript, &["encryptedMaskCiphertextRoot"])?,
        "rank refresh mask commitment encrypted mask root",
    )?;
    compare_required_hash(
        hash_at_path(mask_commitment, &["encryptedMaskCiphertextPayloadHash"])?,
        hash_at_path(transcript, &["encryptedMaskCiphertextPayloadHash"])?,
        "rank refresh mask commitment encrypted mask ciphertext payload hash",
    )?;
    hash_at_path(mask_commitment, &["maskPlaintextCommitmentHash"])?;

    let randomness_evidence = value_at_path(transcript, &["maskEncryptionRandomnessEvidence"])?;
    compare_derived_hash(
        "MaskedRankRefreshMaskEncryptionRandomnessEvidenceHash",
        randomness_evidence,
        hash_at_path(transcript, &["maskEncryptionRandomnessEvidenceHash"])?,
        "rank refresh mask encryption randomness evidence hash",
    )?;
    require_string_at_path(
        randomness_evidence,
        &["objectType"],
        MASK_ENCRYPTION_RANDOMNESS_EVIDENCE_OBJECT_TYPE,
        "rank refresh mask encryption randomness evidence object type",
    )?;
    require_u64_at_path(
        randomness_evidence,
        &["objectVersion"],
        1,
        "rank refresh mask encryption randomness evidence version",
    )?;
    require_string_at_path(
        randomness_evidence,
        &["profileId"],
        MASKED_RANK_REFRESH_PROFILE_ID,
        "rank refresh mask encryption randomness evidence profile id",
    )?;
    require_string_at_path(
        randomness_evidence,
        &["evidenceStatus"],
        "MaskEncryptionRandomnessEvidenceBound",
        "rank refresh mask encryption randomness evidence status",
    )?;
    require_string_at_path(
        randomness_evidence,
        &["freshnessProofStatus"],
        "MaskEncryptionFreshnessProofPending",
        "rank refresh mask encryption freshness proof status",
    )?;
    require_string_at_path(
        randomness_evidence,
        &["randomnessSourceKind"],
        "witness-private-mask-encryption-randomness",
        "rank refresh mask encryption randomness source kind",
    )?;
    require_bool_at_path(
        randomness_evidence,
        &["claimBearingFreshRandomnessEvidence"],
        false,
        "rank refresh mask encryption claim-bearing randomness evidence flag",
    )?;
    require_bool_at_path(
        randomness_evidence,
        &["developmentRandomnessAcceptedForClaim"],
        false,
        "rank refresh mask encryption development randomness acceptance flag",
    )?;
    require_bool_at_path(
        randomness_evidence,
        &["rawRandomnessExported"],
        false,
        "rank refresh mask encryption raw randomness export flag",
    )?;
    compare_required_hash(
        hash_at_path(randomness_evidence, &["setupPackageHash"])?,
        hash_at_path(transcript, &["setupPackageHash"])?,
        "rank refresh mask encryption randomness evidence setup package hash",
    )?;
    compare_required_hash(
        hash_at_path(randomness_evidence, &["collectivePublicKeyRoot"])?,
        hash_at_path(transcript, &["collectivePublicKeyRoot"])?,
        "rank refresh mask encryption randomness evidence collective public key root",
    )?;
    compare_required_hash(
        hash_at_path(randomness_evidence, &["bgvPublicKeyRoot"])?,
        hash_at_path(transcript, &["bgvPublicKeyRoot"])?,
        "rank refresh mask encryption randomness evidence BGV public key root",
    )?;
    compare_required_hash(
        hash_at_path(randomness_evidence, &["evaluationContextHash"])?,
        hash_at_path(transcript, &["evaluationContextHash"])?,
        "rank refresh mask encryption randomness evidence evaluation context hash",
    )?;
    compare_required_hash(
        hash_at_path(randomness_evidence, &["inputRankCiphertextRoot"])?,
        hash_at_path(transcript, &["inputRankCiphertextRoot"])?,
        "rank refresh mask encryption randomness evidence input rank root",
    )?;
    compare_required_hash(
        hash_at_path(randomness_evidence, &["maskCommitmentRoot"])?,
        hash_at_path(transcript, &["maskCommitmentRoot"])?,
        "rank refresh mask encryption randomness evidence mask commitment root",
    )?;
    compare_required_hash(
        hash_at_path(randomness_evidence, &["encryptedMaskCiphertextRoot"])?,
        hash_at_path(transcript, &["encryptedMaskCiphertextRoot"])?,
        "rank refresh mask encryption randomness evidence encrypted mask root",
    )?;
    compare_required_hash(
        hash_at_path(randomness_evidence, &["encryptedMaskCiphertextPayloadHash"])?,
        hash_at_path(transcript, &["encryptedMaskCiphertextPayloadHash"])?,
        "rank refresh mask encryption randomness evidence encrypted mask ciphertext payload hash",
    )?;
    compare_required_hash(
        hash_at_path(randomness_evidence, &["canonicalCiphertextConventionHash"])?,
        &canonical_ciphertext_convention_hash()?,
        "rank refresh mask encryption randomness evidence ciphertext convention hash",
    )?;
    hash_at_path(randomness_evidence, &["randomnessCommitmentHash"])?;
    hash_at_path(randomness_evidence, &["freshnessEvidenceHash"])?;

    Ok(())
}

struct PartDecShareEquationProofContext<'a> {
    setup_package: &'a Value,
    transcript: &'a Value,
    record: &'a Value,
    selected_sidecar: &'a Value,
    trustee_binding: &'a SetupTrusteeBinding,
    threshold_share_verification_key_hash: &'a str,
    algebraic_share_verification_key_root: &'a str,
    algebraic_share_verification_key_hash: &'a str,
}

fn validate_part_dec_share_equation_proof(
    context: PartDecShareEquationProofContext<'_>,
) -> CanonicalResult<()> {
    let PartDecShareEquationProofContext {
        setup_package,
        transcript,
        record,
        selected_sidecar,
        trustee_binding,
        threshold_share_verification_key_hash,
        algebraic_share_verification_key_root,
        algebraic_share_verification_key_hash,
    } = context;
    let proof = value_at_path(record, &["shareEquationProof"])?;
    compare_derived_hash(
        "MaskedRankRefreshPartDecShareEquationProofRoot",
        proof,
        hash_at_path(record, &["shareEquationProofRoot"])?,
        "rank refresh PartDec share-equation proof root",
    )?;
    require_string_at_path(
        proof,
        &["objectType"],
        PART_DEC_SHARE_EQUATION_PROOF_OBJECT_TYPE,
        "rank refresh PartDec share-equation proof object type",
    )?;
    require_u64_at_path(
        proof,
        &["objectVersion"],
        1,
        "rank refresh PartDec share-equation proof version",
    )?;
    require_string_at_path(
        proof,
        &["profileId"],
        MASKED_RANK_REFRESH_PROFILE_ID,
        "rank refresh PartDec share-equation proof profile id",
    )?;
    require_string_at_path(
        proof,
        &["proofStatementFormat"],
        "masked-rank-refresh-partdec-share-equation-v1",
        "rank refresh PartDec proof statement format",
    )?;
    require_string_at_path(
        proof,
        &["proofVerificationStatus"],
        "ZeroKnowledgePartDecVerifierPending",
        "rank refresh PartDec proof verification status",
    )?;
    require_bool_at_path(
        proof,
        &["proofBytesVerified"],
        false,
        "rank refresh PartDec proof-byte verification flag",
    )?;
    validate_proof_bytes_binding(
        proof,
        &ProofBytesBinding {
            proof_bytes_hex_field: "proofBytesHex",
            proof_size_bytes_field: "proofSizeBytes",
            proof_bytes_hash_field: "proofBytesHash",
            proof_statement_hash_field: "proofStatementHash",
            statement_hash_namespace: "MaskedRankRefreshPartDecShareEquationProofStatementHash",
            statement_metadata_fields: &PART_DEC_PROOF_METADATA_FIELDS,
            label: "rank refresh PartDec share-equation",
        },
    )?;
    require_bool_at_path(
        proof,
        &["rawWitnessExported"],
        false,
        "rank refresh PartDec raw witness export flag",
    )?;
    require_bool_at_path(
        proof,
        &["semanticRankOpeningAllowed"],
        false,
        "rank refresh PartDec semantic opening flag",
    )?;
    require_bool_at_path(
        proof,
        &["smudgingBoundCertificateRequired"],
        true,
        "rank refresh PartDec smudging-bound requirement",
    )?;
    require_string_at_path(
        proof,
        &["ciphertextComponentRole"],
        "ciphertext-component-one",
        "rank refresh PartDec ciphertext component role",
    )?;
    require_string_at_path(
        proof,
        &["shareEquation"],
        "partialDecryptionShare = ciphertextComponentOne * trusteeSecretShare + smudgingNoise mod q",
        "rank refresh PartDec share equation",
    )?;
    compare_required_hash(
        hash_at_path(proof, &["setupPackageHash"])?,
        hash_at_path(transcript, &["setupPackageHash"])?,
        "rank refresh PartDec proof setup package hash",
    )?;
    compare_required_hash(
        hash_at_path(proof, &["evaluationContextHash"])?,
        hash_at_path(transcript, &["evaluationContextHash"])?,
        "rank refresh PartDec proof evaluation context hash",
    )?;
    compare_required_hash(
        hash_at_path(proof, &["inputRankCiphertextRoot"])?,
        hash_at_path(transcript, &["inputRankCiphertextRoot"])?,
        "rank refresh PartDec proof input rank root",
    )?;
    compare_required_hash(
        hash_at_path(proof, &["inputRankCiphertextComponentOnePayloadHash"])?,
        hash_at_path(transcript, &["inputRankCiphertextComponentOnePayloadHash"])?,
        "rank refresh PartDec proof input rank ciphertext component-one payload hash",
    )?;
    compare_required_hash(
        hash_at_path(proof, &["thresholdShareVerificationKeyHash"])?,
        threshold_share_verification_key_hash,
        "rank refresh PartDec proof threshold verification-key hash",
    )?;
    compare_required_hash(
        hash_at_path(proof, &["algebraicShareVerificationKeyRoot"])?,
        algebraic_share_verification_key_root,
        "rank refresh PartDec proof algebraic verification-key root",
    )?;
    compare_required_hash(
        hash_at_path(proof, &["algebraicShareVerificationKeyHash"])?,
        algebraic_share_verification_key_hash,
        "rank refresh PartDec proof algebraic verification-key hash",
    )?;
    compare_required_hash(
        hash_at_path(proof, &["participantSetupRecordHash"])?,
        &trustee_binding.participant_setup_record_hash,
        "rank refresh PartDec proof participant setup hash",
    )?;
    compare_required_hash(
        hash_at_path(proof, &["publicKeyShareRoot"])?,
        &trustee_binding.public_key_share_root,
        "rank refresh PartDec proof public key-share root",
    )?;
    compare_required_hash(
        hash_at_path(proof, &["selectedAlgebraicShareVerificationKeyBindingRoot"])?,
        hash_at_path(
            record,
            &["selectedAlgebraicShareVerificationKeyBindingRoot"],
        )?,
        "rank refresh PartDec proof selected algebraic share-verification key binding root",
    )?;
    compare_required_hash(
        hash_at_path(proof, &["publicKeyShareCoefficientMaterialRoot"])?,
        &trustee_binding.public_key_share_coefficient_material_root,
        "rank refresh PartDec proof public key-share coefficient material root",
    )?;
    compare_required_hash(
        hash_at_path(proof, &["publicKeyShareCoefficientMaterialHash"])?,
        &trustee_binding.public_key_share_coefficient_material_hash,
        "rank refresh PartDec proof public key-share coefficient material hash",
    )?;
    compare_required_hash(
        hash_at_path(proof, &["trusteeThresholdVerificationKeyHash"])?,
        &trustee_binding.trustee_threshold_verification_key_hash,
        "rank refresh PartDec proof trustee verification-key hash",
    )?;
    compare_required_hash(
        hash_at_path(proof, &["localSecretShareCommitmentHash"])?,
        &trustee_binding.local_secret_share_commitment_hash,
        "rank refresh PartDec proof local secret commitment hash",
    )?;
    compare_required_hash(
        hash_at_path(proof, &["localErrorCommitmentHash"])?,
        &trustee_binding.local_error_commitment_hash,
        "rank refresh PartDec proof local error commitment hash",
    )?;
    compare_required_hash(
        hash_at_path(proof, &["thresholdLsssWitnessCommitmentHash"])?,
        &trustee_binding.threshold_lsss_witness_commitment_hash,
        "rank refresh PartDec proof LSSS witness commitment hash",
    )?;
    compare_required_hash(
        hash_at_path(proof, &["partialDecryptionShareRoot"])?,
        hash_at_path(record, &["partialDecryptionShareRoot"])?,
        "rank refresh PartDec proof partial-decryption share root",
    )?;
    compare_required_hash(
        hash_at_path(proof, &["shareFreshnessHash"])?,
        hash_at_path(record, &["shareFreshnessHash"])?,
        "rank refresh PartDec proof share freshness hash",
    )?;
    compare_required_hash(
        hash_at_path(proof, &["smudgingBoundCertificateHash"])?,
        hash_at_path(record, &["smudgingBoundCertificateHash"])?,
        "rank refresh PartDec proof smudging-bound certificate hash",
    )?;
    compare_string_value(
        string_at_path(proof, &["trusteeIdentity"])?,
        &trustee_binding.trustee_identity,
        "rank refresh PartDec proof trustee identity",
    )?;
    if u64_at_path(proof, &["rosterPosition"])? != trustee_binding.roster_position {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "rank refresh PartDec proof roster position does not match setup",
        ));
    }
    validate_part_dec_linear_relation_statement(
        setup_package,
        transcript,
        record,
        selected_sidecar,
        proof,
        trustee_binding,
    )?;
    validate_part_dec_linear_proof_backend_input(
        setup_package,
        selected_sidecar,
        proof,
        value_at_path(proof, &["partDecLinearRelationStatement"])?,
        transcript,
    )?;

    Ok(())
}

fn validate_part_dec_linear_relation_statement(
    setup_package: &Value,
    transcript: &Value,
    record: &Value,
    selected_sidecar: &Value,
    proof: &Value,
    trustee_binding: &SetupTrusteeBinding,
) -> CanonicalResult<()> {
    let statement = value_at_path(proof, &["partDecLinearRelationStatement"])?;
    compare_derived_hash(
        "MaskedRankRefreshPartDecLinearRelationStatementRoot",
        statement,
        hash_at_path(proof, &["partDecLinearRelationStatementRoot"])?,
        "rank refresh PartDec linear relation statement root",
    )?;
    require_string_at_path(
        statement,
        &["objectType"],
        PART_DEC_LINEAR_RELATION_STATEMENT_OBJECT_TYPE,
        "rank refresh PartDec linear relation statement object type",
    )?;
    require_u64_at_path(
        statement,
        &["objectVersion"],
        1,
        "rank refresh PartDec linear relation statement version",
    )?;
    require_string_at_path(
        statement,
        &["profileId"],
        MASKED_RANK_REFRESH_PROFILE_ID,
        "rank refresh PartDec linear relation statement profile id",
    )?;
    require_string_at_path(
        statement,
        &["statementFormat"],
        "masked-rank-refresh-partdec-linear-relation-v1",
        "rank refresh PartDec linear relation statement format",
    )?;
    require_string_at_path(
        statement,
        &["relationKind"],
        "same-secret-public-key-share-and-masked-partdec-linear-relation",
        "rank refresh PartDec linear relation kind",
    )?;
    require_string_at_path(
        statement,
        &["proofBackendRequired"],
        "LinearLatticeRelationOverBgvDataBasis",
        "rank refresh PartDec linear relation proof backend",
    )?;
    require_string_at_path(
        statement,
        &["proofBackendStatus"],
        "VerifierPending",
        "rank refresh PartDec linear relation proof backend status",
    )?;
    require_string_at_path(
        statement,
        &["witnessLayout"],
        "trusteeSecretShare,trusteeErrorShare,smudgingNoise",
        "rank refresh PartDec linear relation witness layout",
    )?;
    require_string_at_path(
        statement,
        &["commonWitness"],
        "trusteeSecretShare",
        "rank refresh PartDec linear relation common witness",
    )?;
    require_string_at_path(
        statement,
        &["publicKeyShareEquation"],
        "publicKeyShareComponentZero + publicCommonRandomPolynomial * trusteeSecretShare = plaintextModulus * trusteeErrorShare mod q",
        "rank refresh PartDec public key-share equation",
    )?;
    require_string_at_path(
        statement,
        &["partDecShareEquation"],
        "partialDecryptionShare = inputCiphertextComponentOne * trusteeSecretShare + smudgingNoise mod q",
        "rank refresh PartDec share equation",
    )?;
    require_string_at_path(
        statement,
        &["smudgingBoundSource"],
        "smudgingBoundCertificate",
        "rank refresh PartDec smudging-bound source",
    )?;
    require_bool_at_path(
        statement,
        &["rawWitnessExported"],
        false,
        "rank refresh PartDec linear relation raw witness export flag",
    )?;
    require_bool_at_path(
        statement,
        &["semanticRankOpeningAllowed"],
        false,
        "rank refresh PartDec linear relation semantic opening flag",
    )?;
    require_u64_at_path(
        statement,
        &["polynomialDegree"],
        POLYNOMIAL_DEGREE as u64,
        "rank refresh PartDec linear relation polynomial degree",
    )?;
    require_u64_at_path(
        statement,
        &["dataPrimeCount"],
        DATA_PRIMES.len() as u64,
        "rank refresh PartDec linear relation data-prime count",
    )?;
    require_u64_at_path(
        statement,
        &["plaintextModulus"],
        PLAINTEXT_MODULUS,
        "rank refresh PartDec linear relation plaintext modulus",
    )?;
    compare_required_hash(
        hash_at_path(statement, &["setupPackageHash"])?,
        hash_at_path(transcript, &["setupPackageHash"])?,
        "rank refresh PartDec linear relation setup package hash",
    )?;
    compare_required_hash(
        hash_at_path(statement, &["evaluationContextHash"])?,
        hash_at_path(transcript, &["evaluationContextHash"])?,
        "rank refresh PartDec linear relation evaluation context hash",
    )?;
    compare_required_hash(
        hash_at_path(statement, &["inputRankCiphertextRoot"])?,
        hash_at_path(transcript, &["inputRankCiphertextRoot"])?,
        "rank refresh PartDec linear relation input rank root",
    )?;
    compare_required_hash(
        hash_at_path(statement, &["inputRankCiphertextComponentOnePayloadHash"])?,
        hash_at_path(transcript, &["inputRankCiphertextComponentOnePayloadHash"])?,
        "rank refresh PartDec linear relation input rank component-one payload hash",
    )?;
    compare_required_hash(
        hash_at_path(statement, &["partialDecryptionShareRoot"])?,
        hash_at_path(record, &["partialDecryptionShareRoot"])?,
        "rank refresh PartDec linear relation partial-decryption share root",
    )?;
    compare_required_hash(
        hash_at_path(statement, &["publicKeyShareCoefficientMaterialRoot"])?,
        hash_at_path(record, &["publicKeyShareCoefficientMaterialRoot"])?,
        "rank refresh PartDec linear relation public key-share coefficient material root",
    )?;
    compare_required_hash(
        hash_at_path(statement, &["publicKeyShareCoefficientMaterialHash"])?,
        hash_at_path(record, &["publicKeyShareCoefficientMaterialHash"])?,
        "rank refresh PartDec linear relation public key-share coefficient material hash",
    )?;
    compare_required_hash(
        hash_at_path(statement, &["participantSetupRecordHash"])?,
        &trustee_binding.participant_setup_record_hash,
        "rank refresh PartDec linear relation participant setup hash",
    )?;
    compare_required_hash(
        hash_at_path(statement, &["publicKeyShareRoot"])?,
        &trustee_binding.public_key_share_root,
        "rank refresh PartDec linear relation public key-share root",
    )?;
    compare_required_hash(
        hash_at_path(
            statement,
            &["selectedAlgebraicShareVerificationKeyBindingRoot"],
        )?,
        hash_at_path(
            record,
            &["selectedAlgebraicShareVerificationKeyBindingRoot"],
        )?,
        "rank refresh PartDec linear relation selected algebraic share-verification key binding root",
    )?;
    compare_required_hash(
        hash_at_path(statement, &["smudgingBoundCertificateHash"])?,
        hash_at_path(record, &["smudgingBoundCertificateHash"])?,
        "rank refresh PartDec linear relation smudging-bound certificate hash",
    )?;
    compare_required_hash(
        hash_at_path(statement, &["shareFreshnessHash"])?,
        hash_at_path(record, &["shareFreshnessHash"])?,
        "rank refresh PartDec linear relation share freshness hash",
    )?;
    compare_string_value(
        string_at_path(statement, &["trusteeIdentity"])?,
        &trustee_binding.trustee_identity,
        "rank refresh PartDec linear relation trustee identity",
    )?;
    if u64_at_path(statement, &["rosterPosition"])? != trustee_binding.roster_position {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "rank refresh PartDec linear relation roster position does not match setup",
        ));
    }
    compare_string_value(
        string_at_path(selected_sidecar, &["trusteeIdentity"])?,
        string_at_path(record, &["trusteeIdentity"])?,
        "rank refresh PartDec linear relation sidecar trustee identity",
    )?;
    validate_part_dec_linear_relation_tables(transcript, record, selected_sidecar, statement)?;
    validate_part_dec_linear_proof_backend_adapter(
        setup_package,
        transcript,
        record,
        selected_sidecar,
        statement,
    )
}

fn validate_part_dec_linear_relation_tables(
    transcript: &Value,
    record: &Value,
    selected_sidecar: &Value,
    statement: &Value,
) -> CanonicalResult<()> {
    let relation_tables = array_at_path(statement, &["linearRelationTables"])?;
    if relation_tables.len() != DATA_PRIMES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rank refresh PartDec linear relation statement must include one table per data prime",
        ));
    }
    let sidecar_tables = array_at_path(selected_sidecar, &["coefficientTables"])?;
    let input_rank_payload =
        value_at_path(transcript, &["inputRankCiphertextComponentOnePayload"])?;
    let input_rank_tables = array_at_path(input_rank_payload, &["componentOneCoefficientTables"])?;
    let partial_share_payload = value_at_path(record, &["partialDecryptionSharePayload"])?;
    let partial_share_tables = array_at_path(partial_share_payload, &["coefficientTables"])?;
    if sidecar_tables.len() != DATA_PRIMES.len()
        || input_rank_tables.len() != DATA_PRIMES.len()
        || partial_share_tables.len() != DATA_PRIMES.len()
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rank refresh PartDec linear relation source tables must cover the data-prime basis",
        ));
    }

    for (modulus_index, relation_table) in relation_tables.iter().enumerate() {
        require_u64_at_path(
            relation_table,
            &["modulusIndex"],
            modulus_index as u64,
            "rank refresh PartDec linear relation modulus index",
        )?;
        let modulus = DATA_PRIMES[modulus_index];
        require_u64_at_path(
            relation_table,
            &["modulus"],
            modulus,
            "rank refresh PartDec linear relation modulus",
        )?;
        compare_required_hash(
            string_at_path(relation_table, &["publicKeyShareComponentZeroHash512"])?,
            string_at_path(&sidecar_tables[modulus_index], &["componentZeroBHash512"])?,
            "rank refresh PartDec linear relation public key-share component-zero hash",
        )?;
        compare_required_hash(
            string_at_path(relation_table, &["publicCommonRandomPolynomialHash512"])?,
            string_at_path(&sidecar_tables[modulus_index], &["componentOneAHash512"])?,
            "rank refresh PartDec linear relation public common-random polynomial hash",
        )?;
        compare_required_hash(
            string_at_path(relation_table, &["inputRankCiphertextComponentOneHash512"])?,
            string_at_path(
                &input_rank_tables[modulus_index],
                &["componentOneCoefficientHash512"],
            )?,
            "rank refresh PartDec linear relation input rank component-one hash",
        )?;
        compare_required_hash(
            string_at_path(relation_table, &["partialDecryptionShareHash512"])?,
            string_at_path(
                &partial_share_tables[modulus_index],
                &["shareCoefficientHash512"],
            )?,
            "rank refresh PartDec linear relation partial-decryption share hash",
        )?;
    }

    Ok(())
}

fn validate_part_dec_linear_proof_backend_adapter(
    setup_package: &Value,
    transcript: &Value,
    record: &Value,
    selected_sidecar: &Value,
    statement: &Value,
) -> CanonicalResult<()> {
    let adapter = value_at_path(statement, &["linearProofBackendAdapter"])?;
    require_string_at_path(
        adapter,
        &["objectType"],
        PART_DEC_LINEAR_PROOF_BACKEND_ADAPTER_OBJECT_TYPE,
        "rank refresh PartDec linear proof adapter object type",
    )?;
    require_u64_at_path(
        adapter,
        &["objectVersion"],
        1,
        "rank refresh PartDec linear proof adapter version",
    )?;
    require_string_at_path(
        adapter,
        &["profileId"],
        MASKED_RANK_REFRESH_PROFILE_ID,
        "rank refresh PartDec linear proof adapter profile id",
    )?;
    require_string_at_path(
        adapter,
        &["adapterStatus"],
        "PartDecLinearProofBackendAdapterBound",
        "rank refresh PartDec linear proof adapter status",
    )?;
    require_string_at_path(
        adapter,
        &["proofBackend"],
        "sealed-lattice-linear-proof",
        "rank refresh PartDec linear proof adapter backend",
    )?;
    require_string_at_path(
        adapter,
        &["proofBackendStatus"],
        "VerifierPending",
        "rank refresh PartDec linear proof adapter backend status",
    )?;
    require_string_at_path(
        adapter,
        &["sourceMatrixCoefficientRepresentation"],
        "canonicalUnsignedSourceModulus",
        "rank refresh PartDec linear proof adapter matrix coefficient representation",
    )?;
    require_string_at_path(
        adapter,
        &["targetCoefficientRepresentation"],
        "canonicalUnsignedSourceModulus",
        "rank refresh PartDec linear proof adapter target coefficient representation",
    )?;
    require_string_at_path(
        adapter,
        &["publicCommonRandomPolynomialSource"],
        "setup-collective-public-key-coefficient-material",
        "rank refresh PartDec linear proof adapter common-random source",
    )?;
    require_u64_at_path(
        adapter,
        &["statementRows"],
        2,
        "rank refresh PartDec linear proof adapter statement rows",
    )?;
    require_u64_at_path(
        adapter,
        &["witnessColumnCount"],
        3,
        "rank refresh PartDec linear proof adapter witness column count",
    )?;
    compare_json_value(
        value_at_path(adapter, &["witnessColumns"])?,
        &json!(["trusteeSecretShare", "trusteeErrorShare", "smudgingNoise"]),
        "rank refresh PartDec linear proof adapter witness columns",
    )?;
    compare_json_value(
        value_at_path(adapter, &["rowEquations"])?,
        &json!([
            "publicKeyShareComponentZero + publicCommonRandomPolynomial * trusteeSecretShare = plaintextModulus * trusteeErrorShare mod q",
            "partialDecryptionShare = inputCiphertextComponentOne * trusteeSecretShare + smudgingNoise mod q"
        ]),
        "rank refresh PartDec linear proof adapter row equations",
    )?;
    require_u64_at_path(
        adapter,
        &["polynomialDegree"],
        POLYNOMIAL_DEGREE as u64,
        "rank refresh PartDec linear proof adapter polynomial degree",
    )?;
    require_u64_at_path(
        adapter,
        &["dataPrimeCount"],
        DATA_PRIMES.len() as u64,
        "rank refresh PartDec linear proof adapter data-prime count",
    )?;
    require_u64_at_path(
        adapter,
        &["plaintextModulus"],
        PLAINTEXT_MODULUS,
        "rank refresh PartDec linear proof adapter plaintext modulus",
    )?;
    compare_required_hash(
        hash_at_path(adapter, &["setupPackageHash"])?,
        hash_at_path(transcript, &["setupPackageHash"])?,
        "rank refresh PartDec linear proof adapter setup package hash",
    )?;
    compare_required_hash(
        hash_at_path(adapter, &["collectivePublicKeyRoot"])?,
        hash_at_path(transcript, &["collectivePublicKeyRoot"])?,
        "rank refresh PartDec linear proof adapter collective public key root",
    )?;
    compare_required_hash(
        hash_at_path(adapter, &["bgvPublicKeyRoot"])?,
        hash_at_path(transcript, &["bgvPublicKeyRoot"])?,
        "rank refresh PartDec linear proof adapter BGV public key root",
    )?;
    compare_required_hash(
        hash_at_path(adapter, &["evaluationContextHash"])?,
        hash_at_path(transcript, &["evaluationContextHash"])?,
        "rank refresh PartDec linear proof adapter evaluation context hash",
    )?;
    compare_required_hash(
        hash_at_path(adapter, &["inputRankCiphertextComponentOnePayloadHash"])?,
        hash_at_path(transcript, &["inputRankCiphertextComponentOnePayloadHash"])?,
        "rank refresh PartDec linear proof adapter input rank component-one payload hash",
    )?;
    compare_required_hash(
        hash_at_path(adapter, &["partialDecryptionShareRoot"])?,
        hash_at_path(record, &["partialDecryptionShareRoot"])?,
        "rank refresh PartDec linear proof adapter partial-decryption share root",
    )?;
    compare_required_hash(
        hash_at_path(adapter, &["publicKeyShareCoefficientMaterialRoot"])?,
        hash_at_path(record, &["publicKeyShareCoefficientMaterialRoot"])?,
        "rank refresh PartDec linear proof adapter public key-share coefficient material root",
    )?;
    compare_required_hash(
        hash_at_path(
            adapter,
            &["selectedAlgebraicShareVerificationKeyBindingRoot"],
        )?,
        hash_at_path(
            record,
            &["selectedAlgebraicShareVerificationKeyBindingRoot"],
        )?,
        "rank refresh PartDec linear proof adapter selected algebraic share-verification key binding root",
    )?;

    let adapter_tables = array_at_path(adapter, &["adapterTables"])?;
    if adapter_tables.len() != DATA_PRIMES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rank refresh PartDec linear proof adapter must include one table per data prime",
        ));
    }
    let relation_tables = array_at_path(statement, &["linearRelationTables"])?;
    let sidecar_tables = array_at_path(selected_sidecar, &["coefficientTables"])?;
    let input_rank_payload =
        value_at_path(transcript, &["inputRankCiphertextComponentOnePayload"])?;
    let input_rank_tables = array_at_path(input_rank_payload, &["componentOneCoefficientTables"])?;
    let partial_share_payload = value_at_path(record, &["partialDecryptionSharePayload"])?;
    let partial_share_tables = array_at_path(partial_share_payload, &["coefficientTables"])?;
    for (modulus_index, adapter_table) in adapter_tables.iter().enumerate() {
        validate_part_dec_linear_proof_adapter_table(PartDecLinearProofAdapterTableContext {
            setup_package,
            adapter_table,
            relation_table: &relation_tables[modulus_index],
            sidecar_table: &sidecar_tables[modulus_index],
            input_rank_table: &input_rank_tables[modulus_index],
            partial_share_table: &partial_share_tables[modulus_index],
            modulus_index,
        })?;
    }

    Ok(())
}

struct PartDecLinearProofAdapterTableContext<'a> {
    setup_package: &'a Value,
    adapter_table: &'a Value,
    relation_table: &'a Value,
    sidecar_table: &'a Value,
    input_rank_table: &'a Value,
    partial_share_table: &'a Value,
    modulus_index: usize,
}

fn validate_part_dec_linear_proof_adapter_table(
    context: PartDecLinearProofAdapterTableContext<'_>,
) -> CanonicalResult<()> {
    let PartDecLinearProofAdapterTableContext {
        setup_package,
        adapter_table,
        relation_table,
        sidecar_table,
        input_rank_table,
        partial_share_table,
        modulus_index,
    } = context;
    require_u64_at_path(
        adapter_table,
        &["modulusIndex"],
        modulus_index as u64,
        "rank refresh PartDec linear proof adapter modulus index",
    )?;
    let modulus = DATA_PRIMES[modulus_index];
    require_u64_at_path(
        adapter_table,
        &["modulus"],
        modulus,
        "rank refresh PartDec linear proof adapter modulus",
    )?;
    require_u64_at_path(
        adapter_table,
        &["publicKeyShareEquationRowIndex"],
        0,
        "rank refresh PartDec linear proof adapter public key-share row index",
    )?;
    require_u64_at_path(
        adapter_table,
        &["partDecShareEquationRowIndex"],
        1,
        "rank refresh PartDec linear proof adapter PartDec row index",
    )?;

    let public_common_random_coefficients =
        setup_public_common_random_coefficients_for_modulus(setup_package, modulus_index, modulus)?;
    let public_key_share_component_zero_coefficients = coefficient_vector_from_le_hex(
        string_at_path(sidecar_table, &["componentZeroBLeHex"])?,
        "rank refresh PartDec linear proof adapter public key-share component-zero coefficients",
    )?;
    let input_rank_component_one_coefficients = coefficient_vector_from_le_hex(
        string_at_path(input_rank_table, &["componentOneCoefficientsLeHex"])?,
        "rank refresh PartDec linear proof adapter input component-one coefficients",
    )?;
    let partial_decryption_share_coefficients = coefficient_vector_from_le_hex(
        string_at_path(partial_share_table, &["shareCoefficientsLeHex"])?,
        "rank refresh PartDec linear proof adapter partial-decryption share coefficients",
    )?;
    let negative_plaintext_modulus_coefficients =
        scalar_polynomial_coefficients(sub_mod(0, PLAINTEXT_MODULUS % modulus, modulus)?, modulus);
    let zero_polynomial_coefficients = vec![0_u64; POLYNOMIAL_DEGREE];
    let one_scalar_coefficients = scalar_polynomial_coefficients(1, modulus);
    let negative_partial_decryption_share_coefficients = partial_decryption_share_coefficients
        .iter()
        .map(|coefficient| sub_mod(0, *coefficient, modulus))
        .collect::<CanonicalResult<Vec<_>>>()?;

    compare_required_hash(
        string_at_path(adapter_table, &["publicCommonRandomPolynomialHash512"])?,
        &setup_public_key_coefficient_hash(&public_common_random_coefficients),
        "rank refresh PartDec linear proof adapter public common-random polynomial hash",
    )?;
    compare_required_hash(
        string_at_path(adapter_table, &["publicCommonRandomPolynomialHash512"])?,
        string_at_path(relation_table, &["publicCommonRandomPolynomialHash512"])?,
        "rank refresh PartDec linear proof adapter relation common-random hash",
    )?;
    compare_required_hash(
        string_at_path(adapter_table, &["publicKeyShareComponentZeroHash512"])?,
        string_at_path(relation_table, &["publicKeyShareComponentZeroHash512"])?,
        "rank refresh PartDec linear proof adapter public key-share component-zero hash",
    )?;
    compare_required_hash(
        string_at_path(adapter_table, &["inputRankCiphertextComponentOneHash512"])?,
        string_at_path(relation_table, &["inputRankCiphertextComponentOneHash512"])?,
        "rank refresh PartDec linear proof adapter input component-one hash",
    )?;
    compare_required_hash(
        string_at_path(adapter_table, &["partialDecryptionShareHash512"])?,
        string_at_path(relation_table, &["partialDecryptionShareHash512"])?,
        "rank refresh PartDec linear proof adapter partial-decryption share hash",
    )?;
    compare_required_hash(
        string_at_path(adapter_table, &["negativePlaintextModulusScalarHash512"])?,
        &part_dec_linear_proof_coefficient_hash(&negative_plaintext_modulus_coefficients),
        "rank refresh PartDec linear proof adapter negative plaintext-modulus scalar hash",
    )?;
    compare_required_hash(
        string_at_path(adapter_table, &["zeroPolynomialHash512"])?,
        &part_dec_linear_proof_coefficient_hash(&zero_polynomial_coefficients),
        "rank refresh PartDec linear proof adapter zero polynomial hash",
    )?;
    compare_required_hash(
        string_at_path(adapter_table, &["oneScalarPolynomialHash512"])?,
        &part_dec_linear_proof_coefficient_hash(&one_scalar_coefficients),
        "rank refresh PartDec linear proof adapter one scalar polynomial hash",
    )?;
    compare_required_hash(
        string_at_path(adapter_table, &["publicKeyShareComponentZeroTargetHash512"])?,
        &part_dec_linear_proof_coefficient_hash(&public_key_share_component_zero_coefficients),
        "rank refresh PartDec linear proof adapter public key-share target hash",
    )?;
    compare_required_hash(
        string_at_path(
            adapter_table,
            &["negativePartialDecryptionShareTargetHash512"],
        )?,
        &part_dec_linear_proof_coefficient_hash(&negative_partial_decryption_share_coefficients),
        "rank refresh PartDec linear proof adapter negative partial-decryption share target hash",
    )?;
    compare_required_hash(
        string_at_path(adapter_table, &["sourceMatrixHash512"])?,
        &part_dec_source_matrix_hash(
            modulus,
            &public_common_random_coefficients,
            &negative_plaintext_modulus_coefficients,
            &zero_polynomial_coefficients,
            &input_rank_component_one_coefficients,
            &one_scalar_coefficients,
        ),
        "rank refresh PartDec linear proof adapter source matrix hash",
    )?;
    compare_required_hash(
        string_at_path(adapter_table, &["targetVectorHash512"])?,
        &part_dec_target_vector_hash(
            modulus,
            &public_key_share_component_zero_coefficients,
            &negative_partial_decryption_share_coefficients,
        ),
        "rank refresh PartDec linear proof adapter target vector hash",
    )?;
    compare_required_hash(
        string_at_path(
            adapter_table,
            &["publicKeyShareConsistencySourceMatrixHash512"],
        )?,
        &part_dec_public_key_share_consistency_source_matrix_hash(
            modulus,
            &public_common_random_coefficients,
            &negative_plaintext_modulus_coefficients,
        ),
        "rank refresh PartDec linear proof adapter public key-share consistency source matrix hash",
    )?;
    compare_required_hash(
        string_at_path(
            adapter_table,
            &["publicKeyShareConsistencyTargetVectorHash512"],
        )?,
        &part_dec_public_key_share_consistency_target_vector_hash(
            modulus,
            &public_key_share_component_zero_coefficients,
        ),
        "rank refresh PartDec linear proof adapter public key-share consistency target vector hash",
    )?;
    compare_required_hash(
        string_at_path(adapter_table, &["maskedShareSourceMatrixHash512"])?,
        &part_dec_masked_share_source_matrix_hash(
            modulus,
            &input_rank_component_one_coefficients,
            &one_scalar_coefficients,
        ),
        "rank refresh PartDec linear proof adapter masked-share source matrix hash",
    )?;
    compare_required_hash(
        string_at_path(adapter_table, &["maskedShareTargetVectorHash512"])?,
        &part_dec_masked_share_target_vector_hash(
            modulus,
            &negative_partial_decryption_share_coefficients,
        ),
        "rank refresh PartDec linear proof adapter masked-share target vector hash",
    )
}

fn validate_part_dec_linear_proof_backend_input(
    setup_package: &Value,
    selected_sidecar: &Value,
    proof: &Value,
    statement: &Value,
    transcript: &Value,
) -> CanonicalResult<()> {
    let backend_input = value_at_path(proof, &["linearProofBackendInput"])?;
    compare_derived_hash(
        "MaskedRankRefreshPartDecLinearProofBackendInputRoot",
        backend_input,
        hash_at_path(proof, &["linearProofBackendInputRoot"])?,
        "rank refresh PartDec linear proof backend input root",
    )?;
    require_string_at_path(
        backend_input,
        &["objectType"],
        PART_DEC_LINEAR_PROOF_BACKEND_INPUT_OBJECT_TYPE,
        "rank refresh PartDec linear proof backend input object type",
    )?;
    require_u64_at_path(
        backend_input,
        &["objectVersion"],
        1,
        "rank refresh PartDec linear proof backend input version",
    )?;
    require_string_at_path(
        backend_input,
        &["profileId"],
        MASKED_RANK_REFRESH_PROFILE_ID,
        "rank refresh PartDec linear proof backend input profile id",
    )?;
    require_string_at_path(
        backend_input,
        &["inputStatus"],
        "PartDecLinearProofBackendInputBound",
        "rank refresh PartDec linear proof backend input status",
    )?;
    require_string_at_path(
        backend_input,
        &["proofBackend"],
        "sealed-lattice-linear-proof",
        "rank refresh PartDec linear proof backend input backend",
    )?;
    require_string_at_path(
        backend_input,
        &["proofBackendStatus"],
        "VerifierPending",
        "rank refresh PartDec linear proof backend input backend status",
    )?;
    require_string_at_path(
        backend_input,
        &["proofInputFormat"],
        "masked-rank-refresh-partdec-per-data-prime-linear-proof-input-v1",
        "rank refresh PartDec linear proof backend input format",
    )?;
    require_string_at_path(
        backend_input,
        &["proofBytesSource"],
        "partDecShareEquationProof.proofBytesHex",
        "rank refresh PartDec linear proof backend input proof bytes source",
    )?;
    require_string_at_path(
        backend_input,
        &["statementMaterialMode"],
        "streamed-derived-from-adapter-tables",
        "rank refresh PartDec linear proof backend input statement material mode",
    )?;
    require_bool_at_path(
        backend_input,
        &["sameWitnessAcrossDataPrimesRequired"],
        true,
        "rank refresh PartDec linear proof backend input same-witness requirement",
    )?;
    require_string_at_path(
        backend_input,
        &["sameWitnessBindingStatus"],
        "PublicRootsBoundWitnessProofPending",
        "rank refresh PartDec linear proof backend input same-witness binding status",
    )?;
    require_bool_at_path(
        backend_input,
        &["splitProofObligationsRequired"],
        true,
        "rank refresh PartDec linear proof backend input split obligation requirement",
    )?;
    require_string_at_path(
        backend_input,
        &["splitProofObligationReason"],
        "smudging-witness-bound-exceeds-current-linear-proof-backend-capacity",
        "rank refresh PartDec linear proof backend input split obligation reason",
    )?;
    require_string_at_path(
        backend_input,
        &["publicKeyShareConsistencyProofInputStatus"],
        "PartDecPublicKeyShareConsistencyLinearProofBackendInputBound",
        "rank refresh PartDec linear proof backend input public key-share proof input status",
    )?;
    require_string_at_path(
        backend_input,
        &["maskedPartDecShareProofInputStatus"],
        "PartDecMaskedShareLinearProofBackendInputBound",
        "rank refresh PartDec linear proof backend input masked share proof input status",
    )?;
    require_u64_at_path(
        backend_input,
        &["proofSystemRingDegree"],
        PART_DEC_LINEAR_PROOF_SYSTEM_RING_DEGREE,
        "rank refresh PartDec linear proof backend input proof-system ring degree",
    )?;
    require_u64_at_path(
        backend_input,
        &["sourcePolynomialSplitFactor"],
        PART_DEC_LINEAR_PROOF_SOURCE_POLYNOMIAL_SPLIT_FACTOR,
        "rank refresh PartDec linear proof backend input source split factor",
    )?;
    require_u64_at_path(
        backend_input,
        &["expectedShortResponseVectorLength"],
        PART_DEC_LINEAR_PROOF_EXPECTED_SHORT_RESPONSE_VECTOR_LENGTH,
        "rank refresh PartDec linear proof backend input expected short-response length",
    )?;
    require_u64_at_path(
        backend_input,
        &["dataPrimeProofInputCount"],
        DATA_PRIMES.len() as u64,
        "rank refresh PartDec linear proof backend input data-prime input count",
    )?;

    let statement_root = part_dec_linear_relation_statement_root(statement)?;
    compare_required_hash(
        hash_at_path(backend_input, &["partDecLinearRelationStatementRoot"])?,
        &statement_root,
        "rank refresh PartDec linear proof backend input statement root",
    )?;
    let adapter = value_at_path(statement, &["linearProofBackendAdapter"])?;
    let adapter_root = part_dec_linear_proof_backend_adapter_root(adapter)?;
    compare_required_hash(
        hash_at_path(backend_input, &["linearProofBackendAdapterRoot"])?,
        &adapter_root,
        "rank refresh PartDec linear proof backend input adapter root",
    )?;
    compare_required_hash(
        hash_at_path(backend_input, &["setupPackageHash"])?,
        hash_at_path(proof, &["setupPackageHash"])?,
        "rank refresh PartDec linear proof backend input setup package hash",
    )?;
    compare_required_hash(
        hash_at_path(backend_input, &["evaluationContextHash"])?,
        hash_at_path(proof, &["evaluationContextHash"])?,
        "rank refresh PartDec linear proof backend input evaluation context hash",
    )?;
    compare_required_hash(
        hash_at_path(
            backend_input,
            &["inputRankCiphertextComponentOnePayloadHash"],
        )?,
        hash_at_path(proof, &["inputRankCiphertextComponentOnePayloadHash"])?,
        "rank refresh PartDec linear proof backend input component-one payload hash",
    )?;
    compare_required_hash(
        hash_at_path(backend_input, &["partialDecryptionShareRoot"])?,
        hash_at_path(proof, &["partialDecryptionShareRoot"])?,
        "rank refresh PartDec linear proof backend input partial-decryption share root",
    )?;
    compare_required_hash(
        hash_at_path(
            backend_input,
            &["selectedAlgebraicShareVerificationKeyBindingRoot"],
        )?,
        hash_at_path(proof, &["selectedAlgebraicShareVerificationKeyBindingRoot"])?,
        "rank refresh PartDec linear proof backend input selected key binding root",
    )?;
    compare_required_hash(
        hash_at_path(backend_input, &["smudgingBoundCertificateHash"])?,
        hash_at_path(proof, &["smudgingBoundCertificateHash"])?,
        "rank refresh PartDec linear proof backend input smudging-bound certificate hash",
    )?;
    compare_required_hash(
        hash_at_path(backend_input, &["smudgingBoundCertificateHash"])?,
        hash_at_path(transcript, &["smudgingBoundCertificateHash"])?,
        "rank refresh PartDec linear proof backend input transcript smudging-bound certificate hash",
    )?;

    let challenge_domain_hash = part_dec_linear_proof_backend_input_challenge_domain_hash(
        proof,
        &statement_root,
        &adapter_root,
    )?;
    compare_required_hash(
        hash_at_path(backend_input, &["challengeDomainHash"])?,
        &challenge_domain_hash,
        "rank refresh PartDec linear proof backend input challenge-domain hash",
    )?;
    require_string_at_path(
        backend_input,
        &["publicRandomnessSource"],
        "challenge-domain-hash-prefix-32-bytes",
        "rank refresh PartDec linear proof backend input public randomness source",
    )?;
    let expected_public_randomness_hex = challenge_domain_hash.get(..64).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rank refresh PartDec linear proof backend input challenge-domain hash is too short",
        )
    })?;
    compare_string_value(
        string_at_path(backend_input, &["publicRandomnessHex"])?,
        expected_public_randomness_hex,
        "rank refresh PartDec linear proof backend input public randomness",
    )?;

    let proof_inputs = array_at_path(backend_input, &["dataPrimeProofInputs"])?;
    if proof_inputs.len() != DATA_PRIMES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rank refresh PartDec linear proof backend input must include one proof input per data prime",
        ));
    }
    let smudging_bound_certificate = value_at_path(transcript, &["smudgingBoundCertificate"])?;
    let expected_witness_bound =
        part_dec_witness_bound_from_smudging_certificate(smudging_bound_certificate)?;
    let expected_masked_share_witness_bound =
        part_dec_masked_share_witness_bound_from_smudging_certificate(smudging_bound_certificate)?;
    validate_part_dec_linear_proof_backend_capacity(backend_input, &expected_witness_bound)?;
    let adapter_tables = array_at_path(adapter, &["adapterTables"])?;
    validate_part_dec_public_key_share_consistency_linear_proof_backend_input(
        setup_package,
        selected_sidecar,
        proof,
        backend_input,
        &statement_root,
        &adapter_root,
        adapter,
    )?;
    validate_part_dec_masked_share_linear_proof_backend_input(
        proof,
        backend_input,
        &statement_root,
        &adapter_root,
        adapter,
        &expected_masked_share_witness_bound,
    )?;
    validate_part_dec_split_same_witness_binding(
        proof,
        backend_input,
        &statement_root,
        &adapter_root,
    )?;
    for (modulus_index, proof_input) in proof_inputs.iter().enumerate() {
        validate_part_dec_linear_proof_backend_prime_input(
            proof_input,
            &adapter_tables[modulus_index],
            modulus_index,
            &expected_witness_bound,
        )?;
    }

    Ok(())
}

fn validate_part_dec_public_key_share_consistency_linear_proof_backend_input(
    setup_package: &Value,
    selected_sidecar: &Value,
    proof: &Value,
    parent_backend_input: &Value,
    statement_root: &str,
    adapter_root: &str,
    adapter: &Value,
) -> CanonicalResult<()> {
    let backend_input = value_at_path(
        parent_backend_input,
        &["publicKeyShareConsistencyLinearProofBackendInput"],
    )?;
    compare_required_hash(
        hash_at_path(
            parent_backend_input,
            &["publicKeyShareConsistencyLinearProofBackendInputRoot"],
        )?,
        &part_dec_public_key_share_consistency_linear_proof_backend_input_root(backend_input)?,
        "rank refresh PartDec public key-share consistency linear proof backend input root",
    )?;
    require_string_at_path(
        backend_input,
        &["objectType"],
        PART_DEC_PUBLIC_KEY_SHARE_LINEAR_PROOF_BACKEND_INPUT_OBJECT_TYPE,
        "rank refresh PartDec public key-share consistency linear proof backend input object type",
    )?;
    require_u64_at_path(
        backend_input,
        &["objectVersion"],
        1,
        "rank refresh PartDec public key-share consistency linear proof backend input version",
    )?;
    require_string_at_path(
        backend_input,
        &["profileId"],
        MASKED_RANK_REFRESH_PROFILE_ID,
        "rank refresh PartDec public key-share consistency linear proof backend input profile id",
    )?;
    require_string_at_path(
        backend_input,
        &["inputStatus"],
        "PartDecPublicKeyShareConsistencyLinearProofBackendInputBound",
        "rank refresh PartDec public key-share consistency linear proof backend input status",
    )?;
    require_string_at_path(
        backend_input,
        &["proofBackend"],
        "sealed-lattice-linear-proof",
        "rank refresh PartDec public key-share consistency linear proof backend input backend",
    )?;
    let proof_backend_status = string_at_path(backend_input, &["proofBackendStatus"])?;
    let verified_proof_required = match proof_backend_status {
        "VerifierPending" => {
            require_string_at_path(
                backend_input,
                &["proofVerificationStatus"],
                PART_DEC_PUBLIC_KEY_SHARE_LINEAR_PROOF_VERIFIER_PENDING_STATUS,
                "rank refresh PartDec public key-share consistency linear proof backend input proof verification status",
            )?;
            require_bool_at_path(
                backend_input,
                &["proofBytesVerified"],
                false,
                "rank refresh PartDec public key-share consistency linear proof backend input proof-byte verification flag",
            )?;
            false
        }
        PART_DEC_PUBLIC_KEY_SHARE_LINEAR_PROOF_BACKEND_VERIFIED_STATUS => {
            require_string_at_path(
                backend_input,
                &["proofVerificationStatus"],
                PART_DEC_PUBLIC_KEY_SHARE_LINEAR_PROOF_VERIFIED_STATUS,
                "rank refresh PartDec public key-share consistency linear proof backend input proof verification status",
            )?;
            require_bool_at_path(
                backend_input,
                &["proofBytesVerified"],
                true,
                "rank refresh PartDec public key-share consistency linear proof backend input proof-byte verification flag",
            )?;
            true
        }
        _ => {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "rank refresh PartDec public key-share consistency linear proof backend input backend status must be pending or verified",
            ));
        }
    };
    require_string_at_path(
        backend_input,
        &["proofInputFormat"],
        "masked-rank-refresh-partdec-public-key-share-consistency-per-data-prime-linear-proof-input-v1",
        "rank refresh PartDec public key-share consistency linear proof backend input format",
    )?;
    require_string_at_path(
        backend_input,
        &["relationScope"],
        "public-key-share-consistency-only",
        "rank refresh PartDec public key-share consistency linear proof backend input relation scope",
    )?;
    require_bool_at_path(
        backend_input,
        &["smudgingWitnessExcluded"],
        true,
        "rank refresh PartDec public key-share consistency linear proof backend input smudging exclusion",
    )?;
    require_bool_at_path(
        backend_input,
        &["maskedPartDecShareRelationExcluded"],
        true,
        "rank refresh PartDec public key-share consistency linear proof backend input masked share exclusion",
    )?;
    require_string_at_path(
        backend_input,
        &["statementMaterialMode"],
        "streamed-derived-from-adapter-tables",
        "rank refresh PartDec public key-share consistency linear proof backend input statement material mode",
    )?;
    require_bool_at_path(
        backend_input,
        &["sameWitnessAcrossDataPrimesRequired"],
        true,
        "rank refresh PartDec public key-share consistency linear proof backend input same-witness requirement",
    )?;
    require_string_at_path(
        backend_input,
        &["sameWitnessBindingStatus"],
        "PublicRootsBoundWitnessProofPending",
        "rank refresh PartDec public key-share consistency linear proof backend input same-witness status",
    )?;
    require_u64_at_path(
        backend_input,
        &["proofSystemRingDegree"],
        PART_DEC_LINEAR_PROOF_SYSTEM_RING_DEGREE,
        "rank refresh PartDec public key-share consistency linear proof backend input proof-system ring degree",
    )?;
    require_u64_at_path(
        backend_input,
        &["sourcePolynomialSplitFactor"],
        PART_DEC_LINEAR_PROOF_SOURCE_POLYNOMIAL_SPLIT_FACTOR,
        "rank refresh PartDec public key-share consistency linear proof backend input source split factor",
    )?;
    require_u64_at_path(
        backend_input,
        &["expectedShortResponseVectorLength"],
        PART_DEC_PUBLIC_KEY_SHARE_LINEAR_PROOF_EXPECTED_SHORT_RESPONSE_VECTOR_LENGTH,
        "rank refresh PartDec public key-share consistency linear proof backend input expected short-response length",
    )?;
    require_u64_at_path(
        backend_input,
        &["dataPrimeProofInputCount"],
        DATA_PRIMES.len() as u64,
        "rank refresh PartDec public key-share consistency linear proof backend input data-prime input count",
    )?;
    compare_required_hash(
        hash_at_path(backend_input, &["setupPackageHash"])?,
        hash_at_path(parent_backend_input, &["setupPackageHash"])?,
        "rank refresh PartDec public key-share consistency linear proof backend input setup package hash",
    )?;
    compare_required_hash(
        hash_at_path(backend_input, &["evaluationContextHash"])?,
        hash_at_path(parent_backend_input, &["evaluationContextHash"])?,
        "rank refresh PartDec public key-share consistency linear proof backend input evaluation context hash",
    )?;
    compare_required_hash(
        hash_at_path(
            backend_input,
            &["selectedAlgebraicShareVerificationKeyBindingRoot"],
        )?,
        hash_at_path(
            parent_backend_input,
            &["selectedAlgebraicShareVerificationKeyBindingRoot"],
        )?,
        "rank refresh PartDec public key-share consistency linear proof backend input selected key binding root",
    )?;
    compare_required_hash(
        hash_at_path(backend_input, &["publicKeyShareCoefficientMaterialRoot"])?,
        hash_at_path(proof, &["publicKeyShareCoefficientMaterialRoot"])?,
        "rank refresh PartDec public key-share consistency linear proof backend input sidecar root",
    )?;
    compare_required_hash(
        hash_at_path(backend_input, &["publicKeyShareCoefficientMaterialHash"])?,
        hash_at_path(proof, &["publicKeyShareCoefficientMaterialHash"])?,
        "rank refresh PartDec public key-share consistency linear proof backend input sidecar hash",
    )?;
    compare_required_hash(
        hash_at_path(backend_input, &["partDecLinearRelationStatementRoot"])?,
        statement_root,
        "rank refresh PartDec public key-share consistency linear proof backend input statement root",
    )?;
    compare_required_hash(
        hash_at_path(backend_input, &["linearProofBackendAdapterRoot"])?,
        adapter_root,
        "rank refresh PartDec public key-share consistency linear proof backend input adapter root",
    )?;

    validate_part_dec_public_key_share_consistency_linear_proof_backend_capacity(backend_input)?;

    let challenge_domain_hash =
        part_dec_public_key_share_consistency_linear_proof_backend_input_challenge_domain_hash(
            proof,
            statement_root,
            adapter_root,
        )?;
    compare_required_hash(
        hash_at_path(backend_input, &["challengeDomainHash"])?,
        &challenge_domain_hash,
        "rank refresh PartDec public key-share consistency linear proof backend input challenge-domain hash",
    )?;
    require_string_at_path(
        backend_input,
        &["publicRandomnessSource"],
        "challenge-domain-hash-prefix-32-bytes",
        "rank refresh PartDec public key-share consistency linear proof backend input public randomness source",
    )?;
    let expected_public_randomness_hex = challenge_domain_hash.get(..64).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rank refresh PartDec public key-share consistency linear proof backend input challenge-domain hash is too short",
        )
    })?;
    compare_string_value(
        string_at_path(backend_input, &["publicRandomnessHex"])?,
        expected_public_randomness_hex,
        "rank refresh PartDec public key-share consistency linear proof backend input public randomness",
    )?;

    let proof_inputs = array_at_path(backend_input, &["dataPrimeProofInputs"])?;
    if proof_inputs.len() != DATA_PRIMES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rank refresh PartDec public key-share consistency linear proof backend input must include one proof input per data prime",
        ));
    }
    let adapter_tables = array_at_path(adapter, &["adapterTables"])?;
    for (modulus_index, proof_input) in proof_inputs.iter().enumerate() {
        validate_part_dec_public_key_share_consistency_linear_proof_prime_input(
            proof_input,
            &adapter_tables[modulus_index],
            modulus_index,
        )?;
    }
    if verified_proof_required {
        validate_part_dec_public_key_share_consistency_verified_linear_proofs(
            setup_package,
            selected_sidecar,
            backend_input,
            adapter,
            proof_inputs,
        )?;
    }

    Ok(())
}

fn validate_part_dec_masked_share_linear_proof_backend_input(
    proof: &Value,
    parent_backend_input: &Value,
    statement_root: &str,
    adapter_root: &str,
    adapter: &Value,
    expected_witness_bound: &PartDecMaskedShareWitnessBound,
) -> CanonicalResult<()> {
    let backend_input = value_at_path(
        parent_backend_input,
        &["maskedShareLinearProofBackendInput"],
    )?;
    compare_required_hash(
        hash_at_path(
            parent_backend_input,
            &["maskedShareLinearProofBackendInputRoot"],
        )?,
        &part_dec_masked_share_linear_proof_backend_input_root(backend_input)?,
        "rank refresh PartDec masked-share linear proof backend input root",
    )?;
    require_string_at_path(
        backend_input,
        &["objectType"],
        PART_DEC_MASKED_SHARE_LINEAR_PROOF_BACKEND_INPUT_OBJECT_TYPE,
        "rank refresh PartDec masked-share linear proof backend input object type",
    )?;
    require_u64_at_path(
        backend_input,
        &["objectVersion"],
        1,
        "rank refresh PartDec masked-share linear proof backend input version",
    )?;
    require_string_at_path(
        backend_input,
        &["profileId"],
        MASKED_RANK_REFRESH_PROFILE_ID,
        "rank refresh PartDec masked-share linear proof backend input profile id",
    )?;
    require_string_at_path(
        backend_input,
        &["inputStatus"],
        "PartDecMaskedShareLinearProofBackendInputBound",
        "rank refresh PartDec masked-share linear proof backend input status",
    )?;
    require_string_at_path(
        backend_input,
        &["proofBackend"],
        "sealed-lattice-linear-proof",
        "rank refresh PartDec masked-share linear proof backend input backend",
    )?;
    require_string_at_path(
        backend_input,
        &["proofBackendStatus"],
        "VerifierPending",
        "rank refresh PartDec masked-share linear proof backend input backend status",
    )?;
    require_string_at_path(
        backend_input,
        &["proofVerificationStatus"],
        PART_DEC_MASKED_SHARE_LINEAR_PROOF_VERIFIER_PENDING_STATUS,
        "rank refresh PartDec masked-share linear proof backend input proof verification status",
    )?;
    require_bool_at_path(
        backend_input,
        &["proofBytesVerified"],
        false,
        "rank refresh PartDec masked-share linear proof backend input proof-byte verification flag",
    )?;
    require_string_at_path(
        backend_input,
        &["proofInputFormat"],
        "masked-rank-refresh-partdec-masked-share-per-data-prime-linear-proof-input-v1",
        "rank refresh PartDec masked-share linear proof backend input format",
    )?;
    require_string_at_path(
        backend_input,
        &["relationScope"],
        "masked-partdec-share-only",
        "rank refresh PartDec masked-share linear proof backend input relation scope",
    )?;
    require_bool_at_path(
        backend_input,
        &["publicKeyShareConsistencyRelationExcluded"],
        true,
        "rank refresh PartDec masked-share linear proof backend input public key-share exclusion",
    )?;
    require_bool_at_path(
        backend_input,
        &["errorShareWitnessExcluded"],
        true,
        "rank refresh PartDec masked-share linear proof backend input error-share exclusion",
    )?;
    require_string_at_path(
        backend_input,
        &["statementMaterialMode"],
        "streamed-derived-from-adapter-tables",
        "rank refresh PartDec masked-share linear proof backend input statement material mode",
    )?;
    require_bool_at_path(
        backend_input,
        &["sameSecretShareWitnessAsPublicKeyShareProofRequired"],
        true,
        "rank refresh PartDec masked-share linear proof backend input same secret-share witness requirement",
    )?;
    require_string_at_path(
        backend_input,
        &["sameSecretShareWitnessBindingStatus"],
        "PublicRootsBoundWitnessProofPending",
        "rank refresh PartDec masked-share linear proof backend input same secret-share witness status",
    )?;
    require_string_at_path(
        backend_input,
        &["splitProofObligationReason"],
        "smudging-witness-bound-exceeds-current-linear-proof-backend-capacity",
        "rank refresh PartDec masked-share linear proof backend input split obligation reason",
    )?;
    require_u64_at_path(
        backend_input,
        &["proofSystemRingDegree"],
        PART_DEC_LINEAR_PROOF_SYSTEM_RING_DEGREE,
        "rank refresh PartDec masked-share linear proof backend input proof-system ring degree",
    )?;
    require_u64_at_path(
        backend_input,
        &["sourcePolynomialSplitFactor"],
        PART_DEC_LINEAR_PROOF_SOURCE_POLYNOMIAL_SPLIT_FACTOR,
        "rank refresh PartDec masked-share linear proof backend input source split factor",
    )?;
    require_u64_at_path(
        backend_input,
        &["expectedShortResponseVectorLength"],
        PART_DEC_PUBLIC_KEY_SHARE_LINEAR_PROOF_EXPECTED_SHORT_RESPONSE_VECTOR_LENGTH,
        "rank refresh PartDec masked-share linear proof backend input expected short-response length",
    )?;
    require_u64_at_path(
        backend_input,
        &["dataPrimeProofInputCount"],
        DATA_PRIMES.len() as u64,
        "rank refresh PartDec masked-share linear proof backend input data-prime input count",
    )?;
    compare_required_hash(
        hash_at_path(backend_input, &["setupPackageHash"])?,
        hash_at_path(parent_backend_input, &["setupPackageHash"])?,
        "rank refresh PartDec masked-share linear proof backend input setup package hash",
    )?;
    compare_required_hash(
        hash_at_path(backend_input, &["evaluationContextHash"])?,
        hash_at_path(parent_backend_input, &["evaluationContextHash"])?,
        "rank refresh PartDec masked-share linear proof backend input evaluation context hash",
    )?;
    compare_required_hash(
        hash_at_path(
            backend_input,
            &["inputRankCiphertextComponentOnePayloadHash"],
        )?,
        hash_at_path(
            parent_backend_input,
            &["inputRankCiphertextComponentOnePayloadHash"],
        )?,
        "rank refresh PartDec masked-share linear proof backend input component-one payload hash",
    )?;
    compare_required_hash(
        hash_at_path(backend_input, &["partialDecryptionShareRoot"])?,
        hash_at_path(parent_backend_input, &["partialDecryptionShareRoot"])?,
        "rank refresh PartDec masked-share linear proof backend input partial-decryption share root",
    )?;
    compare_required_hash(
        hash_at_path(
            backend_input,
            &["selectedAlgebraicShareVerificationKeyBindingRoot"],
        )?,
        hash_at_path(
            parent_backend_input,
            &["selectedAlgebraicShareVerificationKeyBindingRoot"],
        )?,
        "rank refresh PartDec masked-share linear proof backend input selected key binding root",
    )?;
    compare_required_hash(
        hash_at_path(backend_input, &["smudgingBoundCertificateHash"])?,
        hash_at_path(parent_backend_input, &["smudgingBoundCertificateHash"])?,
        "rank refresh PartDec masked-share linear proof backend input smudging-bound certificate hash",
    )?;
    compare_required_hash(
        hash_at_path(backend_input, &["partDecLinearRelationStatementRoot"])?,
        statement_root,
        "rank refresh PartDec masked-share linear proof backend input statement root",
    )?;
    compare_required_hash(
        hash_at_path(backend_input, &["linearProofBackendAdapterRoot"])?,
        adapter_root,
        "rank refresh PartDec masked-share linear proof backend input adapter root",
    )?;

    validate_part_dec_masked_share_linear_proof_backend_capacity(
        backend_input,
        expected_witness_bound,
    )?;

    let challenge_domain_hash =
        part_dec_masked_share_linear_proof_backend_input_challenge_domain_hash(
            proof,
            statement_root,
            adapter_root,
        )?;
    compare_required_hash(
        hash_at_path(backend_input, &["challengeDomainHash"])?,
        &challenge_domain_hash,
        "rank refresh PartDec masked-share linear proof backend input challenge-domain hash",
    )?;
    require_string_at_path(
        backend_input,
        &["publicRandomnessSource"],
        "challenge-domain-hash-prefix-32-bytes",
        "rank refresh PartDec masked-share linear proof backend input public randomness source",
    )?;
    let expected_public_randomness_hex = challenge_domain_hash.get(..64).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rank refresh PartDec masked-share linear proof backend input challenge-domain hash is too short",
        )
    })?;
    compare_string_value(
        string_at_path(backend_input, &["publicRandomnessHex"])?,
        expected_public_randomness_hex,
        "rank refresh PartDec masked-share linear proof backend input public randomness",
    )?;

    let proof_inputs = array_at_path(backend_input, &["dataPrimeProofInputs"])?;
    if proof_inputs.len() != DATA_PRIMES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rank refresh PartDec masked-share linear proof backend input must include one proof input per data prime",
        ));
    }
    let adapter_tables = array_at_path(adapter, &["adapterTables"])?;
    for (modulus_index, proof_input) in proof_inputs.iter().enumerate() {
        validate_part_dec_masked_share_linear_proof_prime_input(
            proof_input,
            &adapter_tables[modulus_index],
            modulus_index,
            expected_witness_bound,
        )?;
    }

    Ok(())
}

fn validate_part_dec_split_same_witness_binding(
    proof: &Value,
    parent_backend_input: &Value,
    statement_root: &str,
    adapter_root: &str,
) -> CanonicalResult<()> {
    let binding = value_at_path(parent_backend_input, &["splitSameWitnessBinding"])?;
    compare_required_hash(
        hash_at_path(parent_backend_input, &["splitSameWitnessBindingRoot"])?,
        &part_dec_split_same_witness_binding_root(binding)?,
        "rank refresh PartDec split same-witness binding root",
    )?;
    require_string_at_path(
        binding,
        &["objectType"],
        PART_DEC_SPLIT_SAME_WITNESS_BINDING_OBJECT_TYPE,
        "rank refresh PartDec split same-witness binding object type",
    )?;
    require_u64_at_path(
        binding,
        &["objectVersion"],
        1,
        "rank refresh PartDec split same-witness binding version",
    )?;
    require_string_at_path(
        binding,
        &["profileId"],
        MASKED_RANK_REFRESH_PROFILE_ID,
        "rank refresh PartDec split same-witness binding profile id",
    )?;
    require_string_at_path(
        binding,
        &["bindingScheme"],
        "masked-rank-refresh-partdec-split-same-witness-binding-v1",
        "rank refresh PartDec split same-witness binding scheme",
    )?;
    require_string_at_path(
        binding,
        &["bindingStatus"],
        PART_DEC_SPLIT_SAME_WITNESS_BINDING_PENDING_STATUS,
        "rank refresh PartDec split same-witness binding status",
    )?;
    require_string_at_path(
        binding,
        &["proofVerificationStatus"],
        PART_DEC_SPLIT_SAME_WITNESS_VERIFIER_PENDING_STATUS,
        "rank refresh PartDec split same-witness proof verification status",
    )?;
    require_bool_at_path(
        binding,
        &["proofBytesVerified"],
        false,
        "rank refresh PartDec split same-witness proof-byte verification flag",
    )?;
    require_bool_at_path(
        binding,
        &["sameSecretShareWitnessRequired"],
        true,
        "rank refresh PartDec split same-witness requirement",
    )?;
    require_string_at_path(
        binding,
        &["sharedWitnessColumn"],
        "trusteeSecretShare",
        "rank refresh PartDec split same-witness shared witness column",
    )?;
    require_bool_at_path(
        binding,
        &["sameWitnessAcrossDataPrimesRequired"],
        true,
        "rank refresh PartDec split same-witness data-prime requirement",
    )?;
    require_bool_at_path(
        binding,
        &["rawSecretShareWitnessExported"],
        false,
        "rank refresh PartDec split same-witness raw secret-share export flag",
    )?;
    require_bool_at_path(
        binding,
        &["publicKeyShareErrorWitnessExcludedFromMaskedShareRelation"],
        true,
        "rank refresh PartDec split same-witness error-share exclusion",
    )?;
    require_bool_at_path(
        binding,
        &["maskedShareSmudgingWitnessExcludedFromPublicKeyShareRelation"],
        true,
        "rank refresh PartDec split same-witness smudging exclusion",
    )?;
    compare_json_value(
        value_at_path(binding, &["publicKeyShareWitnessColumns"])?,
        &json!(["trusteeSecretShare", "trusteeErrorShare"]),
        "rank refresh PartDec split same-witness public key-share witness columns",
    )?;
    compare_json_value(
        value_at_path(binding, &["maskedShareWitnessColumns"])?,
        &json!(["trusteeSecretShare", "smudgingNoise"]),
        "rank refresh PartDec split same-witness masked-share witness columns",
    )?;
    compare_string_value(
        string_at_path(binding, &["trusteeIdentity"])?,
        string_at_path(proof, &["trusteeIdentity"])?,
        "rank refresh PartDec split same-witness trustee identity",
    )?;
    require_u64_at_path(
        binding,
        &["rosterPosition"],
        u64_at_path(proof, &["rosterPosition"])?,
        "rank refresh PartDec split same-witness roster position",
    )?;
    compare_required_hash(
        hash_at_path(binding, &["setupPackageHash"])?,
        hash_at_path(proof, &["setupPackageHash"])?,
        "rank refresh PartDec split same-witness setup package hash",
    )?;
    compare_required_hash(
        hash_at_path(binding, &["evaluationContextHash"])?,
        hash_at_path(proof, &["evaluationContextHash"])?,
        "rank refresh PartDec split same-witness evaluation context hash",
    )?;
    compare_required_hash(
        hash_at_path(
            binding,
            &["selectedAlgebraicShareVerificationKeyBindingRoot"],
        )?,
        hash_at_path(proof, &["selectedAlgebraicShareVerificationKeyBindingRoot"])?,
        "rank refresh PartDec split same-witness selected key binding root",
    )?;
    compare_required_hash(
        hash_at_path(binding, &["partDecLinearRelationStatementRoot"])?,
        statement_root,
        "rank refresh PartDec split same-witness statement root",
    )?;
    compare_required_hash(
        hash_at_path(binding, &["linearProofBackendAdapterRoot"])?,
        adapter_root,
        "rank refresh PartDec split same-witness adapter root",
    )?;

    let public_key_share_input = value_at_path(
        parent_backend_input,
        &["publicKeyShareConsistencyLinearProofBackendInput"],
    )?;
    let masked_share_input = value_at_path(
        parent_backend_input,
        &["maskedShareLinearProofBackendInput"],
    )?;
    compare_required_hash(
        hash_at_path(
            binding,
            &["publicKeyShareConsistencyLinearProofBackendInputRoot"],
        )?,
        hash_at_path(
            parent_backend_input,
            &["publicKeyShareConsistencyLinearProofBackendInputRoot"],
        )?,
        "rank refresh PartDec split same-witness public key-share backend input root",
    )?;
    compare_required_hash(
        hash_at_path(binding, &["maskedShareLinearProofBackendInputRoot"])?,
        hash_at_path(
            parent_backend_input,
            &["maskedShareLinearProofBackendInputRoot"],
        )?,
        "rank refresh PartDec split same-witness masked-share backend input root",
    )?;
    compare_required_hash(
        hash_at_path(binding, &["publicKeyShareConsistencyChallengeDomainHash"])?,
        hash_at_path(public_key_share_input, &["challengeDomainHash"])?,
        "rank refresh PartDec split same-witness public key-share challenge-domain hash",
    )?;
    compare_required_hash(
        hash_at_path(binding, &["maskedShareChallengeDomainHash"])?,
        hash_at_path(masked_share_input, &["challengeDomainHash"])?,
        "rank refresh PartDec split same-witness masked-share challenge-domain hash",
    )?;
    compare_string_value(
        string_at_path(binding, &["publicKeyShareConsistencyPublicRandomnessHex"])?,
        string_at_path(public_key_share_input, &["publicRandomnessHex"])?,
        "rank refresh PartDec split same-witness public key-share public randomness",
    )?;
    compare_string_value(
        string_at_path(binding, &["maskedSharePublicRandomnessHex"])?,
        string_at_path(masked_share_input, &["publicRandomnessHex"])?,
        "rank refresh PartDec split same-witness masked-share public randomness",
    )?;
    compare_required_hash(
        hash_at_path(binding, &["publicKeyShareCoefficientMaterialRoot"])?,
        hash_at_path(
            public_key_share_input,
            &["publicKeyShareCoefficientMaterialRoot"],
        )?,
        "rank refresh PartDec split same-witness public key-share sidecar root",
    )?;
    compare_required_hash(
        hash_at_path(binding, &["publicKeyShareCoefficientMaterialHash"])?,
        hash_at_path(
            public_key_share_input,
            &["publicKeyShareCoefficientMaterialHash"],
        )?,
        "rank refresh PartDec split same-witness public key-share sidecar hash",
    )?;
    compare_required_hash(
        hash_at_path(binding, &["inputRankCiphertextComponentOnePayloadHash"])?,
        hash_at_path(
            masked_share_input,
            &["inputRankCiphertextComponentOnePayloadHash"],
        )?,
        "rank refresh PartDec split same-witness component-one payload hash",
    )?;
    compare_required_hash(
        hash_at_path(binding, &["partialDecryptionShareRoot"])?,
        hash_at_path(masked_share_input, &["partialDecryptionShareRoot"])?,
        "rank refresh PartDec split same-witness partial-decryption share root",
    )?;
    compare_required_hash(
        hash_at_path(binding, &["smudgingBoundCertificateHash"])?,
        hash_at_path(masked_share_input, &["smudgingBoundCertificateHash"])?,
        "rank refresh PartDec split same-witness smudging-bound certificate hash",
    )?;
    compare_string_value(
        string_at_path(binding, &["publicKeyShareProofBackendStatus"])?,
        string_at_path(public_key_share_input, &["proofBackendStatus"])?,
        "rank refresh PartDec split same-witness public key-share proof backend status",
    )?;
    compare_string_value(
        string_at_path(binding, &["publicKeyShareProofVerificationStatus"])?,
        string_at_path(public_key_share_input, &["proofVerificationStatus"])?,
        "rank refresh PartDec split same-witness public key-share proof verification status",
    )?;
    require_bool_at_path(
        binding,
        &["publicKeyShareProofBytesVerified"],
        bool_at_path(public_key_share_input, &["proofBytesVerified"])?,
        "rank refresh PartDec split same-witness public key-share proof-byte flag",
    )?;
    compare_string_value(
        string_at_path(binding, &["maskedShareProofBackendStatus"])?,
        string_at_path(masked_share_input, &["proofBackendStatus"])?,
        "rank refresh PartDec split same-witness masked-share proof backend status",
    )?;
    compare_string_value(
        string_at_path(binding, &["maskedShareProofVerificationStatus"])?,
        string_at_path(masked_share_input, &["proofVerificationStatus"])?,
        "rank refresh PartDec split same-witness masked-share proof verification status",
    )?;
    require_bool_at_path(
        binding,
        &["maskedShareProofBytesVerified"],
        bool_at_path(masked_share_input, &["proofBytesVerified"])?,
        "rank refresh PartDec split same-witness masked-share proof-byte flag",
    )?;
    compare_string_value(
        string_at_path(binding, &["publicKeyShareWitnessBoundStatus"])?,
        string_at_path(public_key_share_input, &["proofBackendWitnessBoundStatus"])?,
        "rank refresh PartDec split same-witness public key-share witness-bound status",
    )?;
    compare_string_value(
        string_at_path(binding, &["maskedShareWitnessBoundStatus"])?,
        string_at_path(masked_share_input, &["proofBackendWitnessBoundStatus"])?,
        "rank refresh PartDec split same-witness masked-share witness-bound status",
    )?;
    compare_string_value(
        string_at_path(binding, &["publicKeyShareWitnessL2BoundSquared"])?,
        string_at_path(public_key_share_input, &["witnessL2BoundSquared"])?,
        "rank refresh PartDec split same-witness public key-share witness bound",
    )?;
    compare_string_value(
        string_at_path(binding, &["maskedShareWitnessL2BoundSquared"])?,
        string_at_path(masked_share_input, &["witnessL2BoundSquared"])?,
        "rank refresh PartDec split same-witness masked-share witness bound",
    )?;

    Ok(())
}

fn validate_part_dec_masked_share_linear_proof_backend_capacity(
    backend_input: &Value,
    expected_witness_bound: &PartDecMaskedShareWitnessBound,
) -> CanonicalResult<()> {
    require_u64_at_path(
        backend_input,
        &["proofBackendWitnessBoundCapacityBits"],
        PART_DEC_LINEAR_PROOF_BACKEND_WITNESS_BOUND_CAPACITY_BITS,
        "rank refresh PartDec masked-share linear proof backend input witness-bound capacity bits",
    )?;
    require_decimal_string_at_path(
        backend_input,
        &["witnessL2BoundSquared"],
        &expected_witness_bound.witness_l2_bound_squared_decimal,
        "rank refresh PartDec masked-share linear proof backend input witness l2 bound squared",
    )?;
    require_u64_at_path(
        backend_input,
        &["witnessL2BoundSquaredBitLength"],
        expected_witness_bound.witness_l2_bound_squared_bit_length,
        "rank refresh PartDec masked-share linear proof backend input witness l2 bound bit length",
    )?;
    require_bool_at_path(
        backend_input,
        &["witnessL2BoundSquaredFitsProofBackend"],
        expected_witness_bound.witness_l2_bound_squared_fits_current_backend,
        "rank refresh PartDec masked-share linear proof backend input witness l2 bound fits proof backend flag",
    )?;
    require_string_at_path(
        backend_input,
        &["proofBackendWitnessBoundStatus"],
        part_dec_masked_share_linear_proof_backend_witness_bound_status(expected_witness_bound),
        "rank refresh PartDec masked-share linear proof backend input witness-bound status",
    )
}

fn part_dec_masked_share_linear_proof_backend_witness_bound_status(
    expected_witness_bound: &PartDecMaskedShareWitnessBound,
) -> &'static str {
    if expected_witness_bound.witness_l2_bound_squared_fits_current_backend {
        PART_DEC_LINEAR_PROOF_BACKEND_WITNESS_BOUND_FITS_STATUS
    } else {
        PART_DEC_LINEAR_PROOF_BACKEND_WITNESS_BOUND_EXCEEDS_STATUS
    }
}

fn validate_part_dec_masked_share_linear_proof_prime_input(
    proof_input: &Value,
    adapter_table: &Value,
    modulus_index: usize,
    expected_witness_bound: &PartDecMaskedShareWitnessBound,
) -> CanonicalResult<()> {
    require_u64_at_path(
        proof_input,
        &["modulusIndex"],
        modulus_index as u64,
        "rank refresh PartDec masked-share linear proof backend input modulus index",
    )?;
    let modulus = DATA_PRIMES[modulus_index];
    require_u64_at_path(
        proof_input,
        &["modulus"],
        modulus,
        "rank refresh PartDec masked-share linear proof backend input modulus",
    )?;
    compare_required_hash(
        string_at_path(proof_input, &["inputRankCiphertextComponentOneHash512"])?,
        string_at_path(adapter_table, &["inputRankCiphertextComponentOneHash512"])?,
        "rank refresh PartDec masked-share linear proof backend input component-one hash",
    )?;
    compare_required_hash(
        string_at_path(proof_input, &["partialDecryptionShareHash512"])?,
        string_at_path(adapter_table, &["partialDecryptionShareHash512"])?,
        "rank refresh PartDec masked-share linear proof backend input partial-share hash",
    )?;
    compare_required_hash(
        string_at_path(proof_input, &["sourceMatrixHash512"])?,
        string_at_path(adapter_table, &["maskedShareSourceMatrixHash512"])?,
        "rank refresh PartDec masked-share linear proof backend input source matrix hash",
    )?;
    compare_required_hash(
        string_at_path(proof_input, &["targetVectorHash512"])?,
        string_at_path(adapter_table, &["maskedShareTargetVectorHash512"])?,
        "rank refresh PartDec masked-share linear proof backend input target vector hash",
    )?;

    let parameter_binding = value_at_path(proof_input, &["proofParameterBinding"])?;
    require_string_at_path(
        parameter_binding,
        &["parameterProfileStatus"],
        "RankRefreshPartDecMaskedShareParameterProfilePendingBecauseWitnessBoundExceedsCurrentLinearProofBackendCapacity",
        "rank refresh PartDec masked-share linear proof backend input parameter profile status",
    )?;
    require_string_at_path(
        parameter_binding,
        &["relation"],
        "A*w + t = 0",
        "rank refresh PartDec masked-share linear proof backend input parameter relation",
    )?;
    require_string_at_path(
        parameter_binding,
        &["coefficientModulus"],
        &modulus.to_string(),
        "rank refresh PartDec masked-share linear proof backend input parameter modulus",
    )?;
    require_u64_at_path(
        parameter_binding,
        &["sourceRingDegree"],
        POLYNOMIAL_DEGREE as u64,
        "rank refresh PartDec masked-share linear proof backend input parameter source ring degree",
    )?;
    require_u64_at_path(
        parameter_binding,
        &["proofSystemRingDegree"],
        PART_DEC_LINEAR_PROOF_SYSTEM_RING_DEGREE,
        "rank refresh PartDec masked-share linear proof backend input parameter proof-system ring degree",
    )?;
    require_u64_at_path(
        parameter_binding,
        &["statementRows"],
        1,
        "rank refresh PartDec masked-share linear proof backend input parameter statement rows",
    )?;
    require_u64_at_path(
        parameter_binding,
        &["statementColumns"],
        2,
        "rank refresh PartDec masked-share linear proof backend input parameter statement columns",
    )?;
    compare_json_value(
        value_at_path(parameter_binding, &["witnessColumns"])?,
        &json!(["trusteeSecretShare", "smudgingNoise"]),
        "rank refresh PartDec masked-share linear proof backend input parameter witness columns",
    )?;
    require_string_at_path(
        parameter_binding,
        &["witnessBoundSource"],
        "setup-secret-distribution-and-smudging-bound-certificate",
        "rank refresh PartDec masked-share linear proof backend input parameter witness bound source",
    )?;
    require_string_at_path(
        parameter_binding,
        &["witnessBoundComputation"],
        "N*(secretShareCoefficientBound^2+smudgingNoiseCoefficientBound^2)",
        "rank refresh PartDec masked-share linear proof backend input parameter witness bound computation",
    )?;
    require_string_at_path(
        parameter_binding,
        &["secretShareDistribution"],
        "owner-routed-standard-ternary-local-share",
        "rank refresh PartDec masked-share linear proof backend input parameter secret-share distribution",
    )?;
    require_u64_at_path(
        parameter_binding,
        &["secretShareCoefficientBound"],
        expected_witness_bound.secret_share_coefficient_bound,
        "rank refresh PartDec masked-share linear proof backend input parameter secret-share coefficient bound",
    )?;
    require_u64_at_path(
        parameter_binding,
        &["smudgingNoiseCoefficientBoundBits"],
        expected_witness_bound.smudging_noise_coefficient_bound_bits,
        "rank refresh PartDec masked-share linear proof backend input parameter smudging-noise coefficient bound bits",
    )?;
    require_decimal_string_at_path(
        parameter_binding,
        &["smudgingNoiseCoefficientBound"],
        &expected_witness_bound.smudging_noise_coefficient_bound_decimal,
        "rank refresh PartDec masked-share linear proof backend input parameter smudging-noise coefficient bound",
    )?;
    require_decimal_string_at_path(
        parameter_binding,
        &["witnessL2BoundSquared"],
        &expected_witness_bound.witness_l2_bound_squared_decimal,
        "rank refresh PartDec masked-share linear proof backend input parameter witness l2 bound squared",
    )?;
    require_u64_at_path(
        parameter_binding,
        &["witnessL2BoundSquaredBitLength"],
        expected_witness_bound.witness_l2_bound_squared_bit_length,
        "rank refresh PartDec masked-share linear proof backend input parameter witness l2 bound bit length",
    )?;
    require_bool_at_path(
        parameter_binding,
        &["witnessL2BoundSquaredFitsProofBackend"],
        expected_witness_bound.witness_l2_bound_squared_fits_current_backend,
        "rank refresh PartDec masked-share linear proof backend input parameter witness l2 bound fits proof backend flag",
    )?;

    let encoding_binding = value_at_path(proof_input, &["proofEncodingBinding"])?;
    require_string_at_path(
        encoding_binding,
        &["proofEncodingStatus"],
        "RankRefreshPartDecMaskedShareProofEncodingPendingBecauseWitnessBoundExceedsCurrentLinearProofBackendCapacity",
        "rank refresh PartDec masked-share linear proof backend input encoding status",
    )?;
    require_string_at_path(
        encoding_binding,
        &["profileId"],
        "masked-rank-refresh-partdec-masked-share-linear-proof-encoding-v1",
        "rank refresh PartDec masked-share linear proof backend input encoding profile id",
    )?;
    require_string_at_path(
        encoding_binding,
        &["source"],
        "sealed-lattice/linear-proof/masked-rank-refresh-partdec-masked-share-encoding-v1",
        "rank refresh PartDec masked-share linear proof backend input encoding source",
    )?;
    require_u64_at_path(
        encoding_binding,
        &["proofSystemRingDegree"],
        PART_DEC_LINEAR_PROOF_SYSTEM_RING_DEGREE,
        "rank refresh PartDec masked-share linear proof backend input encoding proof-system ring degree",
    )?;
    require_u64_at_path(
        encoding_binding,
        &["sourcePolynomialSplitFactor"],
        PART_DEC_LINEAR_PROOF_SOURCE_POLYNOMIAL_SPLIT_FACTOR,
        "rank refresh PartDec masked-share linear proof backend input encoding source split factor",
    )?;
    require_u64_at_path(
        encoding_binding,
        &["expectedShortResponseVectorLength"],
        PART_DEC_PUBLIC_KEY_SHARE_LINEAR_PROOF_EXPECTED_SHORT_RESPONSE_VECTOR_LENGTH,
        "rank refresh PartDec masked-share linear proof backend input encoding expected short-response length",
    )?;
    require_string_at_path(
        encoding_binding,
        &["matrixCoefficientRepresentation"],
        "canonicalUnsignedSourceModulus",
        "rank refresh PartDec masked-share linear proof backend input encoding matrix representation",
    )?;
    require_string_at_path(
        encoding_binding,
        &["targetCoefficientRepresentation"],
        "canonicalUnsignedSourceModulus",
        "rank refresh PartDec masked-share linear proof backend input encoding target representation",
    )
}

fn validate_part_dec_public_key_share_consistency_linear_proof_backend_capacity(
    backend_input: &Value,
) -> CanonicalResult<()> {
    require_u64_at_path(
        backend_input,
        &["proofBackendWitnessBoundCapacityBits"],
        PART_DEC_LINEAR_PROOF_BACKEND_WITNESS_BOUND_CAPACITY_BITS,
        "rank refresh PartDec public key-share consistency linear proof backend input witness-bound capacity bits",
    )?;
    require_decimal_string_at_path(
        backend_input,
        &["witnessL2BoundSquared"],
        &part_dec_public_key_share_witness_l2_bound_squared().to_string(),
        "rank refresh PartDec public key-share consistency linear proof backend input witness l2 bound squared",
    )?;
    require_u64_at_path(
        backend_input,
        &["witnessL2BoundSquaredBitLength"],
        part_dec_public_key_share_witness_l2_bound_squared_bit_length(),
        "rank refresh PartDec public key-share consistency linear proof backend input witness l2 bound bit length",
    )?;
    require_bool_at_path(
        backend_input,
        &["witnessL2BoundSquaredFitsProofBackend"],
        part_dec_public_key_share_witness_bound_fits_current_backend(),
        "rank refresh PartDec public key-share consistency linear proof backend input witness l2 bound fits proof backend flag",
    )?;
    require_string_at_path(
        backend_input,
        &["proofBackendWitnessBoundStatus"],
        part_dec_public_key_share_witness_bound_status(),
        "rank refresh PartDec public key-share consistency linear proof backend input witness-bound status",
    )
}

fn validate_part_dec_public_key_share_consistency_linear_proof_prime_input(
    proof_input: &Value,
    adapter_table: &Value,
    modulus_index: usize,
) -> CanonicalResult<()> {
    require_u64_at_path(
        proof_input,
        &["modulusIndex"],
        modulus_index as u64,
        "rank refresh PartDec public key-share consistency linear proof backend input modulus index",
    )?;
    let modulus = DATA_PRIMES[modulus_index];
    require_u64_at_path(
        proof_input,
        &["modulus"],
        modulus,
        "rank refresh PartDec public key-share consistency linear proof backend input modulus",
    )?;
    compare_required_hash(
        string_at_path(proof_input, &["publicCommonRandomPolynomialHash512"])?,
        string_at_path(adapter_table, &["publicCommonRandomPolynomialHash512"])?,
        "rank refresh PartDec public key-share consistency linear proof backend input common-random hash",
    )?;
    compare_required_hash(
        string_at_path(proof_input, &["publicKeyShareComponentZeroHash512"])?,
        string_at_path(adapter_table, &["publicKeyShareComponentZeroHash512"])?,
        "rank refresh PartDec public key-share consistency linear proof backend input public key-share hash",
    )?;
    compare_required_hash(
        string_at_path(proof_input, &["negativePlaintextModulusScalarHash512"])?,
        string_at_path(adapter_table, &["negativePlaintextModulusScalarHash512"])?,
        "rank refresh PartDec public key-share consistency linear proof backend input negative plaintext-modulus hash",
    )?;
    compare_required_hash(
        string_at_path(proof_input, &["sourceMatrixHash512"])?,
        string_at_path(
            adapter_table,
            &["publicKeyShareConsistencySourceMatrixHash512"],
        )?,
        "rank refresh PartDec public key-share consistency linear proof backend input source matrix hash",
    )?;
    compare_required_hash(
        string_at_path(proof_input, &["targetVectorHash512"])?,
        string_at_path(
            adapter_table,
            &["publicKeyShareConsistencyTargetVectorHash512"],
        )?,
        "rank refresh PartDec public key-share consistency linear proof backend input target vector hash",
    )?;
    let expected_parameter_set =
        part_dec_public_key_share_consistency_linear_parameter_set(modulus);
    compare_json_value(
        value_at_path(proof_input, &["proofParameterSet"])?,
        &json!(expected_parameter_set),
        "rank refresh PartDec public key-share consistency linear proof backend input parameter set",
    )?;
    let expected_proof_encoding = part_dec_public_key_share_consistency_linear_proof_encoding();
    compare_json_value(
        value_at_path(proof_input, &["proofEncoding"])?,
        &json!(expected_proof_encoding),
        "rank refresh PartDec public key-share consistency linear proof backend input proof encoding",
    )?;

    let parameter_binding = value_at_path(proof_input, &["proofParameterBinding"])?;
    require_string_at_path(
        parameter_binding,
        &["parameterProfileStatus"],
        "RankRefreshPartDecPublicKeyShareConsistencyParameterProfileBound",
        "rank refresh PartDec public key-share consistency linear proof backend input parameter profile status",
    )?;
    require_string_at_path(
        parameter_binding,
        &["relation"],
        "A*w + t = 0",
        "rank refresh PartDec public key-share consistency linear proof backend input parameter relation",
    )?;
    require_string_at_path(
        parameter_binding,
        &["coefficientModulus"],
        &modulus.to_string(),
        "rank refresh PartDec public key-share consistency linear proof backend input parameter modulus",
    )?;
    require_u64_at_path(
        parameter_binding,
        &["sourceRingDegree"],
        POLYNOMIAL_DEGREE as u64,
        "rank refresh PartDec public key-share consistency linear proof backend input parameter source ring degree",
    )?;
    require_u64_at_path(
        parameter_binding,
        &["proofSystemRingDegree"],
        PART_DEC_LINEAR_PROOF_SYSTEM_RING_DEGREE,
        "rank refresh PartDec public key-share consistency linear proof backend input parameter proof-system ring degree",
    )?;
    require_u64_at_path(
        parameter_binding,
        &["statementRows"],
        1,
        "rank refresh PartDec public key-share consistency linear proof backend input parameter statement rows",
    )?;
    require_u64_at_path(
        parameter_binding,
        &["statementColumns"],
        2,
        "rank refresh PartDec public key-share consistency linear proof backend input parameter statement columns",
    )?;
    compare_json_value(
        value_at_path(parameter_binding, &["witnessColumns"])?,
        &json!(["trusteeSecretShare", "trusteeErrorShare"]),
        "rank refresh PartDec public key-share consistency linear proof backend input parameter witness columns",
    )?;
    require_string_at_path(
        parameter_binding,
        &["witnessBoundSource"],
        PART_DEC_PUBLIC_KEY_SHARE_WITNESS_BOUND_SOURCE,
        "rank refresh PartDec public key-share consistency linear proof backend input parameter witness bound source",
    )?;
    require_string_at_path(
        parameter_binding,
        &["witnessBoundComputation"],
        PART_DEC_PUBLIC_KEY_SHARE_WITNESS_BOUND_COMPUTATION,
        "rank refresh PartDec public key-share consistency linear proof backend input parameter witness bound computation",
    )?;
    require_string_at_path(
        parameter_binding,
        &["secretShareDistribution"],
        "owner-routed-standard-ternary-local-share",
        "rank refresh PartDec public key-share consistency linear proof backend input parameter secret-share distribution",
    )?;
    require_u64_at_path(
        parameter_binding,
        &["secretShareCoefficientBound"],
        PART_DEC_SECRET_SHARE_COEFFICIENT_BOUND,
        "rank refresh PartDec public key-share consistency linear proof backend input parameter secret-share coefficient bound",
    )?;
    require_string_at_path(
        parameter_binding,
        &["errorShareDistribution"],
        "owner-routed-centered-binomial-eta2-collective-error",
        "rank refresh PartDec public key-share consistency linear proof backend input parameter error-share distribution",
    )?;
    require_u64_at_path(
        parameter_binding,
        &["errorShareCoefficientBound"],
        PART_DEC_ERROR_SHARE_COEFFICIENT_BOUND,
        "rank refresh PartDec public key-share consistency linear proof backend input parameter error-share coefficient bound",
    )?;
    require_decimal_string_at_path(
        parameter_binding,
        &["witnessL2BoundSquared"],
        &part_dec_public_key_share_witness_l2_bound_squared().to_string(),
        "rank refresh PartDec public key-share consistency linear proof backend input parameter witness l2 bound squared",
    )?;
    require_u64_at_path(
        parameter_binding,
        &["witnessL2BoundSquaredBitLength"],
        part_dec_public_key_share_witness_l2_bound_squared_bit_length(),
        "rank refresh PartDec public key-share consistency linear proof backend input parameter witness l2 bound bit length",
    )?;
    require_bool_at_path(
        parameter_binding,
        &["witnessL2BoundSquaredFitsProofBackend"],
        part_dec_public_key_share_witness_bound_fits_current_backend(),
        "rank refresh PartDec public key-share consistency linear proof backend input parameter witness l2 bound fits proof backend flag",
    )?;

    let encoding_binding = value_at_path(proof_input, &["proofEncodingBinding"])?;
    require_string_at_path(
        encoding_binding,
        &["proofEncodingStatus"],
        "RankRefreshPartDecPublicKeyShareConsistencyProofEncodingBound",
        "rank refresh PartDec public key-share consistency linear proof backend input encoding status",
    )?;
    require_u64_at_path(
        encoding_binding,
        &["proofSystemRingDegree"],
        PART_DEC_LINEAR_PROOF_SYSTEM_RING_DEGREE,
        "rank refresh PartDec public key-share consistency linear proof backend input encoding proof-system ring degree",
    )?;
    require_u64_at_path(
        encoding_binding,
        &["sourcePolynomialSplitFactor"],
        PART_DEC_LINEAR_PROOF_SOURCE_POLYNOMIAL_SPLIT_FACTOR,
        "rank refresh PartDec public key-share consistency linear proof backend input encoding source split factor",
    )?;
    require_u64_at_path(
        encoding_binding,
        &["expectedShortResponseVectorLength"],
        PART_DEC_PUBLIC_KEY_SHARE_LINEAR_PROOF_EXPECTED_SHORT_RESPONSE_VECTOR_LENGTH,
        "rank refresh PartDec public key-share consistency linear proof backend input encoding expected short-response length",
    )?;
    require_string_at_path(
        encoding_binding,
        &["matrixCoefficientRepresentation"],
        "centeredSignedSourceModulus",
        "rank refresh PartDec public key-share consistency linear proof backend input encoding matrix representation",
    )?;
    require_string_at_path(
        encoding_binding,
        &["targetCoefficientRepresentation"],
        "centeredSignedSourceModulus",
        "rank refresh PartDec public key-share consistency linear proof backend input encoding target representation",
    )
}

fn validate_part_dec_public_key_share_consistency_verified_linear_proofs(
    setup_package: &Value,
    selected_sidecar: &Value,
    backend_input: &Value,
    adapter: &Value,
    proof_inputs: &[Value],
) -> CanonicalResult<()> {
    let adapter_tables = array_at_path(adapter, &["adapterTables"])?;
    for (modulus_index, proof_input) in proof_inputs.iter().enumerate() {
        validate_part_dec_public_key_share_consistency_verified_linear_proof_for_prime(
            setup_package,
            selected_sidecar,
            backend_input,
            &adapter_tables[modulus_index],
            proof_input,
            modulus_index,
        )?;
    }

    Ok(())
}

fn validate_part_dec_public_key_share_consistency_verified_linear_proof_for_prime(
    setup_package: &Value,
    selected_sidecar: &Value,
    backend_input: &Value,
    adapter_table: &Value,
    proof_input: &Value,
    modulus_index: usize,
) -> CanonicalResult<()> {
    let public_randomness_hex = string_at_path(backend_input, &["publicRandomnessHex"])?;
    let modulus = DATA_PRIMES[modulus_index];
    let parameter_set = part_dec_public_key_share_consistency_linear_parameter_set(modulus);
    let proof_encoding = part_dec_public_key_share_consistency_linear_proof_encoding();
    compare_json_value(
        value_at_path(proof_input, &["proofParameterSet"])?,
        &json!(parameter_set),
        "rank refresh PartDec public key-share consistency verified proof parameter set",
    )?;
    compare_json_value(
        value_at_path(proof_input, &["proofEncoding"])?,
        &json!(proof_encoding),
        "rank refresh PartDec public key-share consistency verified proof encoding",
    )?;
    let (proof_hex, proof_size_bytes) = validate_per_prime_linear_proof_bytes(proof_input)?;
    let statement = part_dec_public_key_share_consistency_streamed_statement_for_modulus(
        setup_package,
        selected_sidecar,
        adapter_table,
        modulus_index,
    )?;
    let verification =
        verify_streamed_linear_proof_components(StreamedLinearProofVerificationInput {
            case_name: "rank-refresh-partdec-public-key-share-consistency",
            parameter_set: &parameter_set,
            proof_encoding: &proof_encoding,
            public_randomness_hex,
            statement: &statement,
            matrix_coefficient_representation:
                LinearProofMatrixCoefficientRepresentation::CenteredSignedSourceModulus,
            target_coefficient_representation:
                LinearProofTargetCoefficientRepresentation::CenteredSignedSourceModulus,
            proof_hex,
            expected_proof_size_bytes: Some(proof_size_bytes),
        });
    if verification
        .as_object()
        .and_then(|object| object.get("ok"))
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!(
                "rank refresh PartDec public key-share consistency proof verification failed for data prime {modulus_index}: {}",
                first_linear_proof_refusal_message(&verification)
            ),
        ));
    }

    Ok(())
}

fn validate_per_prime_linear_proof_bytes(proof_input: &Value) -> CanonicalResult<(&str, usize)> {
    let proof_hex = string_at_path(proof_input, &["proofBytesHex"])?;
    let proof_bytes = decode_hex(proof_hex).map_err(|error| {
        CanonicalError::new(
            error.code,
            format!(
                "rank refresh PartDec public key-share consistency proof bytes must use canonical lowercase hexadecimal encoding: {}",
                error.message
            ),
        )
    })?;
    if proof_bytes.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rank refresh PartDec public key-share consistency proof bytes must not be empty",
        ));
    }
    let proof_size_bytes = usize::try_from(u64_at_path(proof_input, &["proofSizeBytes"])?)
        .map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "rank refresh PartDec public key-share consistency proof byte size does not fit usize",
            )
        })?;
    if proof_size_bytes != proof_bytes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rank refresh PartDec public key-share consistency proof byte size does not match proof bytes",
        ));
    }
    let expected_proof_bytes_hash = derive_protocol_hash_for_proof_bytes_payload(
        proof_hex,
        u64::try_from(proof_size_bytes).expect("proof byte length fits u64"),
    )?;
    compare_required_hash(
        hash_at_path(proof_input, &["proofBytesHash"])?,
        &expected_proof_bytes_hash,
        "rank refresh PartDec public key-share consistency proof bytes hash",
    )?;

    Ok((proof_hex, proof_size_bytes))
}

struct RankRefreshPublicKeyShareConsistencyStreamedStatement {
    source_matrix_hash: String,
    target_vector_hash: String,
    source_statement_matrix: SparsePolynomialMatrix,
    target_vector_coefficients: Vec<Vec<u64>>,
}

impl StreamedLinearProofStatement for RankRefreshPublicKeyShareConsistencyStreamedStatement {
    fn source_statement_rows(&self) -> usize {
        self.source_statement_matrix.rows()
    }

    fn source_statement_columns(&self) -> usize {
        self.source_statement_matrix.columns()
    }

    fn target_vector_coefficients(&self) -> &[Vec<u64>] {
        &self.target_vector_coefficients
    }

    fn validate_source_relation(
        &self,
        parameter_set: &LinearProofParameterSet,
        source_witness_vector: &PolynomialVector,
    ) -> CanonicalResult<()> {
        let source_ring =
            PolynomialRing::new(parameter_set.ring_degree, parameter_set.coefficient_modulus)?;
        if source_witness_vector.ring() != source_ring
            || source_witness_vector.len() != parameter_set.statement_columns
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "rank refresh PartDec public key-share consistency witness shape does not match the parameter set",
            ));
        }
        let mut relation_output = self
            .source_statement_matrix
            .multiply_vector(source_witness_vector)?;
        let target_vector =
            PolynomialVector::new(source_ring, self.target_vector_coefficients.clone())?;
        relation_output.add_assign(&target_vector)?;
        if relation_output
            .entries()
            .iter()
            .any(|polynomial| polynomial.iter().any(|coefficient| *coefficient != 0))
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "rank refresh PartDec public key-share consistency witness does not satisfy A*w + t = 0",
            ));
        }

        Ok(())
    }

    fn derive_statement_transcript(
        &self,
        parameter_set: &LinearProofParameterSet,
        proof_encoding: &LinearProofEncoding,
        matrix_coefficient_representation: LinearProofMatrixCoefficientRepresentation,
        target_coefficient_representation: LinearProofTargetCoefficientRepresentation,
        public_randomness: &[u8],
    ) -> CanonicalResult<LinearStatementTranscript> {
        if public_randomness.len() != 32 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "rank refresh PartDec public key-share consistency public randomness must be exactly 32 bytes",
            ));
        }
        let source_polynomial_split_factor =
            source_polynomial_split_factor(parameter_set, proof_encoding)?;
        let transformed_statement_rows = parameter_set
            .statement_rows
            .checked_mul(source_polynomial_split_factor)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "rank refresh PartDec public key-share consistency transformed row count overflowed",
                )
            })?;
        let transformed_statement_columns = parameter_set
            .statement_columns
            .checked_mul(source_polynomial_split_factor)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "rank refresh PartDec public key-share consistency transformed column count overflowed",
                )
            })?;
        let transcript_payload = json!({
            "domain": "sealed-lattice/internal/rank-refresh-partdec-public-key-share-consistency-streamed-linear-statement-v1",
            "sourceMatrixHash512": self.source_matrix_hash,
            "targetVectorHash512": self.target_vector_hash,
            "parameterSet": {
                "profileId": &parameter_set.profile_id,
                "source": &parameter_set.source,
                "relation": &parameter_set.relation,
                "ringDegree": parameter_set.ring_degree,
                "proofSystemRingDegree": parameter_set.proof_system_ring_degree,
                "coefficientModulus": parameter_set.coefficient_modulus,
                "statementRows": parameter_set.statement_rows,
                "statementColumns": parameter_set.statement_columns,
                "witnessL2BoundSquared": parameter_set.witness_l2_bound_squared
            },
            "proofEncoding": {
                "profileId": &proof_encoding.profile_id,
                "ringDegree": proof_encoding.ring_degree,
                "coefficientModulus": proof_encoding.coefficient_modulus,
                "fullSizeCoefficientBitLength": proof_encoding.full_size_coefficient_bit_length,
                "compressedCoefficientBitLength": proof_encoding.compressed_coefficient_bit_length,
                "targetCommitmentVectorLength": proof_encoding.target_commitment_vector_length,
                "hashMaskVectorLength": proof_encoding.hash_mask_vector_length,
                "compressedCommitmentVectorLength": proof_encoding.compressed_commitment_vector_length,
                "challengeCoefficientModulus": proof_encoding.challenge_coefficient_modulus,
                "challengeCoefficientBitLength": proof_encoding.challenge_coefficient_bit_length,
                "hintVectorLength": proof_encoding.hint_vector_length,
                "shortResponseVectorLength": proof_encoding.short_response_vector_length,
                "randomnessResponseVectorLength": proof_encoding.randomness_response_vector_length,
                "euclideanResponseVectorLength": proof_encoding.euclidean_response_vector_length,
                "infinityResponseVectorLength": proof_encoding.infinity_response_vector_length,
                "shortResponseLog2StandardDeviation": proof_encoding.short_response_log2_standard_deviation,
                "randomnessResponseLog2StandardDeviation": proof_encoding.randomness_response_log2_standard_deviation,
                "euclideanResponseLog2StandardDeviation": proof_encoding.euclidean_response_log2_standard_deviation,
                "infinityResponseLog2StandardDeviation": proof_encoding.infinity_response_log2_standard_deviation,
                "source": &proof_encoding.source
            },
            "matrixCoefficientRepresentation": matrix_coefficient_representation,
            "targetCoefficientRepresentation": target_coefficient_representation,
            "transformedStatementRows": transformed_statement_rows,
            "transformedStatementColumns": transformed_statement_columns,
            "transformedTargetVectorLength": transformed_statement_rows
        });
        let encoded_statement = canonical_json(&transcript_payload)?.into_bytes();
        let arithmetic_statement_hash = shake128_32(&[&encoded_statement]);
        let public_parameters_and_statement_hash =
            shake128_32(&[public_randomness, &arithmetic_statement_hash]);

        Ok(LinearStatementTranscript {
            transformed_statement_matrix_rows: transformed_statement_rows,
            transformed_statement_matrix_columns: transformed_statement_columns,
            transformed_target_vector_length: transformed_statement_rows,
            encoded_statement_bytes: encoded_statement.len(),
            arithmetic_statement_hash,
            arithmetic_statement_hash_hex: to_hex(&arithmetic_statement_hash),
            public_parameters_and_statement_hash,
            public_parameters_and_statement_hash_hex: to_hex(&public_parameters_and_statement_hash),
        })
    }

    fn transformed_target_vector(
        &self,
        parameter_set: &LinearProofParameterSet,
        proof_encoding: &LinearProofEncoding,
        target_coefficient_representation: LinearProofTargetCoefficientRepresentation,
    ) -> CanonicalResult<PolynomialVector> {
        let transformed_target_vector = transform_target_vector_to_proof_ring(
            &self.target_vector_coefficients,
            parameter_set,
            proof_encoding,
            target_coefficient_representation,
        )?;

        PolynomialVector::new(
            PolynomialRing::new(
                proof_encoding.ring_degree,
                proof_encoding.coefficient_modulus,
            )?,
            transformed_target_vector,
        )
    }

    fn transformed_relation_output(
        &self,
        parameter_set: &LinearProofParameterSet,
        proof_encoding: &LinearProofEncoding,
        matrix_coefficient_representation: LinearProofMatrixCoefficientRepresentation,
        transformed_relation_witness: &PolynomialVector,
        transformed_target_vector: &PolynomialVector,
    ) -> CanonicalResult<PolynomialVector> {
        let proof_ring = PolynomialRing::new(
            proof_encoding.ring_degree,
            proof_encoding.coefficient_modulus,
        )?;
        if transformed_relation_witness.ring() != proof_ring
            || transformed_target_vector.ring() != proof_ring
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "rank refresh PartDec public key-share consistency transformed relation uses inconsistent rings",
            ));
        }
        let source_polynomial_split_factor =
            source_polynomial_split_factor(parameter_set, proof_encoding)?;
        let transformed_columns = parameter_set
            .statement_columns
            .checked_mul(source_polynomial_split_factor)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "rank refresh PartDec public key-share consistency transformed column count overflowed",
                )
            })?;
        if transformed_relation_witness.len() != transformed_columns {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "rank refresh PartDec public key-share consistency transformed witness length does not match the statement",
            ));
        }

        let mut relation_output_entries = transformed_target_vector.entries().to_vec();
        for_each_transformed_rank_refresh_public_key_share_source_entry(
            self,
            parameter_set,
            proof_encoding,
            matrix_coefficient_representation,
            |transformed_row, transformed_column, transformed_coefficients| {
                proof_ring.mul_negacyclic_accumulate(
                    &mut relation_output_entries[transformed_row],
                    transformed_coefficients,
                    &transformed_relation_witness.entries()[transformed_column],
                )
            },
        )?;

        PolynomialVector::new(proof_ring, relation_output_entries)
    }

    fn build_z4_statement_products(
        &self,
        proof_ring: PolynomialRing,
        parameter_set: &LinearProofParameterSet,
        proof_encoding: &LinearProofEncoding,
        matrix_coefficient_representation: LinearProofMatrixCoefficientRepresentation,
        shifted_rotation_polynomial_matrix: &[Vec<Vec<u64>>],
    ) -> CanonicalResult<Vec<Vec<Vec<u64>>>> {
        if proof_ring.degree() != proof_encoding.ring_degree
            || proof_ring.modulus() != proof_encoding.coefficient_modulus
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "rank refresh PartDec public key-share consistency proof ring does not match the proof encoding",
            ));
        }
        let source_polynomial_split_factor =
            source_polynomial_split_factor(parameter_set, proof_encoding)?;
        let transformed_rows = parameter_set
            .statement_rows
            .checked_mul(source_polynomial_split_factor)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "rank refresh PartDec public key-share consistency z4 product row count overflowed",
                )
            })?;
        let transformed_columns = parameter_set
            .statement_columns
            .checked_mul(source_polynomial_split_factor)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "rank refresh PartDec public key-share consistency z4 product column count overflowed",
                )
            })?;

        if shifted_rotation_polynomial_matrix
            .iter()
            .any(|row| row.len() != transformed_rows)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "rank refresh PartDec public key-share consistency z4 rotation rows do not match the transformed statement",
            ));
        }

        let mut output_rows = vec![
            vec![vec![0_u64; proof_ring.degree()]; transformed_columns];
            shifted_rotation_polynomial_matrix.len()
        ];
        for_each_transformed_rank_refresh_public_key_share_source_entry(
            self,
            parameter_set,
            proof_encoding,
            matrix_coefficient_representation,
            |transformed_row, transformed_column, transformed_coefficients| {
                let automorphic_coefficients = proof_ring.automorphism(transformed_coefficients)?;
                for (output_row, shifted_rotation_row) in output_rows
                    .iter_mut()
                    .zip(shifted_rotation_polynomial_matrix)
                {
                    proof_ring.mul_negacyclic_accumulate(
                        &mut output_row[transformed_column],
                        &shifted_rotation_row[transformed_row],
                        &automorphic_coefficients,
                    )?;
                }

                Ok(())
            },
        )?;

        Ok(output_rows)
    }
}

fn for_each_transformed_rank_refresh_public_key_share_source_entry(
    statement: &RankRefreshPublicKeyShareConsistencyStreamedStatement,
    parameter_set: &LinearProofParameterSet,
    proof_encoding: &LinearProofEncoding,
    matrix_coefficient_representation: LinearProofMatrixCoefficientRepresentation,
    mut visit: impl FnMut(usize, usize, &[u64]) -> CanonicalResult<()>,
) -> CanonicalResult<()> {
    let source_polynomial_split_factor =
        source_polynomial_split_factor(parameter_set, proof_encoding)?;
    let source_modulus_inverse = source_modulus_inverse_mod_proof_modulus(
        parameter_set.coefficient_modulus,
        proof_encoding.coefficient_modulus,
    )?;
    for source_entry in statement.source_statement_matrix.entries() {
        let split_polynomials =
            split_source_polynomial_into_proof_ring_with_coefficient_representation(
                source_entry.coefficients(),
                parameter_set.coefficient_modulus,
                source_polynomial_split_factor,
                matrix_coefficient_representation,
            )?;
        let rotated_split_polynomials = split_polynomials
            .iter()
            .map(|polynomial| rotate_left_negacyclic_signed_polynomial(polynomial))
            .collect::<Vec<_>>();

        for output_row_offset in 0..source_polynomial_split_factor {
            for output_column_offset in 0..source_polynomial_split_factor {
                let split_index = output_row_offset as isize - output_column_offset as isize;
                let signed_polynomial = if split_index >= 0 {
                    &split_polynomials[usize::try_from(split_index).map_err(|_| {
                        CanonicalError::new(
                            CanonicalErrorCode::MalformedLength,
                            "rank refresh PartDec public key-share consistency split index overflowed",
                        )
                    })?]
                } else {
                    &rotated_split_polynomials[usize::try_from(
                        source_polynomial_split_factor as isize + split_index,
                    )
                    .map_err(|_| {
                        CanonicalError::new(
                            CanonicalErrorCode::MalformedLength,
                            "rank refresh PartDec public key-share consistency rotated split index overflowed",
                        )
                    })?]
                };
                let transformed_coefficients =
                    scale_rank_refresh_signed_polynomial_by_source_modulus_inverse(
                        signed_polynomial,
                        source_modulus_inverse,
                        proof_encoding.coefficient_modulus,
                    )?;
                if transformed_coefficients
                    .iter()
                    .any(|coefficient| *coefficient != 0)
                {
                    visit(
                        source_entry.row_index() * source_polynomial_split_factor
                            + output_row_offset,
                        source_entry.column_index() * source_polynomial_split_factor
                            + output_column_offset,
                        &transformed_coefficients,
                    )?;
                }
            }
        }
    }

    Ok(())
}

fn scale_rank_refresh_signed_polynomial_by_source_modulus_inverse(
    signed_polynomial: &[i128],
    source_modulus_inverse: i128,
    proof_modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    signed_polynomial
        .iter()
        .map(|coefficient| {
            let scaled = coefficient.checked_mul(source_modulus_inverse).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "rank refresh PartDec public key-share consistency coefficient scaling overflowed",
                )
            })?;
            let proof_modulus = i128::from(proof_modulus);
            let mut reduced = scaled % proof_modulus;
            if reduced < 0 {
                reduced += proof_modulus;
            }

            u64::try_from(reduced).map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "rank refresh PartDec public key-share consistency coefficient does not fit u64",
                )
            })
        })
        .collect()
}

fn part_dec_public_key_share_consistency_streamed_statement_for_modulus(
    setup_package: &Value,
    selected_sidecar: &Value,
    adapter_table: &Value,
    modulus_index: usize,
) -> CanonicalResult<RankRefreshPublicKeyShareConsistencyStreamedStatement> {
    let modulus = DATA_PRIMES[modulus_index];
    let public_common_random_coefficients =
        setup_public_common_random_coefficients_for_modulus(setup_package, modulus_index, modulus)?;
    let sidecar_tables = array_at_path(selected_sidecar, &["coefficientTables"])?;
    let public_key_share_component_zero_coefficients = coefficient_vector_from_le_hex(
        string_at_path(&sidecar_tables[modulus_index], &["componentZeroBLeHex"])?,
        "rank refresh PartDec public key-share consistency proof public key-share component-zero coefficients",
    )?;
    let negative_plaintext_modulus_coefficients =
        scalar_polynomial_coefficients(sub_mod(0, PLAINTEXT_MODULUS % modulus, modulus)?, modulus);
    compare_required_hash(
        string_at_path(adapter_table, &["publicCommonRandomPolynomialHash512"])?,
        &setup_public_key_coefficient_hash(&public_common_random_coefficients),
        "rank refresh PartDec public key-share consistency verified proof common-random hash",
    )?;
    compare_required_hash(
        string_at_path(adapter_table, &["publicKeyShareComponentZeroHash512"])?,
        &setup_public_key_coefficient_hash(&public_key_share_component_zero_coefficients),
        "rank refresh PartDec public key-share consistency verified proof public key-share component-zero hash",
    )?;
    compare_required_hash(
        string_at_path(adapter_table, &["negativePlaintextModulusScalarHash512"])?,
        &part_dec_linear_proof_coefficient_hash(&negative_plaintext_modulus_coefficients),
        "rank refresh PartDec public key-share consistency verified proof negative plaintext-modulus hash",
    )?;
    let source_matrix_hash = part_dec_public_key_share_consistency_source_matrix_hash(
        modulus,
        &public_common_random_coefficients,
        &negative_plaintext_modulus_coefficients,
    );
    compare_required_hash(
        string_at_path(
            adapter_table,
            &["publicKeyShareConsistencySourceMatrixHash512"],
        )?,
        &source_matrix_hash,
        "rank refresh PartDec public key-share consistency verified proof source matrix hash",
    )?;
    let target_vector_hash = part_dec_public_key_share_consistency_target_vector_hash(
        modulus,
        &public_key_share_component_zero_coefficients,
    );
    compare_required_hash(
        string_at_path(
            adapter_table,
            &["publicKeyShareConsistencyTargetVectorHash512"],
        )?,
        &target_vector_hash,
        "rank refresh PartDec public key-share consistency verified proof target vector hash",
    )?;
    let source_ring = PolynomialRing::new(POLYNOMIAL_DEGREE, modulus)?;
    let source_statement_matrix = SparsePolynomialMatrix::new(
        source_ring,
        1,
        2,
        vec![
            SparsePolynomialMatrixEntry::new(0, 0, public_common_random_coefficients),
            SparsePolynomialMatrixEntry::new(0, 1, negative_plaintext_modulus_coefficients),
        ],
    )?;

    Ok(RankRefreshPublicKeyShareConsistencyStreamedStatement {
        source_matrix_hash,
        target_vector_hash,
        source_statement_matrix,
        target_vector_coefficients: vec![public_key_share_component_zero_coefficients],
    })
}

fn part_dec_public_key_share_consistency_linear_parameter_set(
    modulus: u64,
) -> LinearProofParameterSet {
    LinearProofParameterSet {
        profile_id: PART_DEC_PUBLIC_KEY_SHARE_LINEAR_PROOF_PARAMETER_PROFILE_ID.to_string(),
        source: "sealed-lattice/linear-proof/masked-rank-refresh-partdec-public-key-share-consistency-parameters-v1".to_string(),
        relation: "A*w + t = 0".to_string(),
        ring_degree: POLYNOMIAL_DEGREE,
        proof_system_ring_degree: PART_DEC_LINEAR_PROOF_SYSTEM_RING_DEGREE as usize,
        coefficient_modulus: modulus,
        statement_rows: 1,
        statement_columns: 2,
        witness_l2_bound_squared: u128::from(part_dec_public_key_share_witness_l2_bound_squared()),
        expected_proof_size_bytes: None,
    }
}

fn part_dec_public_key_share_consistency_linear_proof_encoding() -> LinearProofEncoding {
    LinearProofEncoding {
        profile_id: PART_DEC_PUBLIC_KEY_SHARE_LINEAR_PROOF_ENCODING_PROFILE_ID.to_string(),
        ring_degree: PART_DEC_LINEAR_PROOF_SYSTEM_RING_DEGREE as usize,
        coefficient_modulus: 70_368_744_177_829,
        full_size_coefficient_bit_length: 47,
        compressed_coefficient_bit_length: 35,
        target_commitment_vector_length: 12,
        hash_mask_vector_length: 2,
        compressed_commitment_vector_length: 18,
        challenge_coefficient_modulus: 17,
        challenge_coefficient_bit_length: 5,
        hint_vector_length: 18,
        short_response_vector_length:
            PART_DEC_PUBLIC_KEY_SHARE_LINEAR_PROOF_EXPECTED_SHORT_RESPONSE_VECTOR_LENGTH as usize,
        randomness_response_vector_length: 41,
        euclidean_response_vector_length: 4,
        infinity_response_vector_length: 4,
        short_response_log2_standard_deviation: 18,
        randomness_response_log2_standard_deviation: 12,
        euclidean_response_log2_standard_deviation: 14,
        infinity_response_log2_standard_deviation: 22,
        source: "sealed-lattice/linear-proof/masked-rank-refresh-partdec-public-key-share-consistency-encoding-v1".to_string(),
        expected_proof_size_bytes: None,
    }
}

fn first_linear_proof_refusal_message(verification: &Value) -> String {
    verification
        .as_object()
        .and_then(|object| object.get("refusedObjects"))
        .and_then(Value::as_array)
        .and_then(|refusals| refusals.first())
        .and_then(Value::as_object)
        .and_then(|object| object.get("message"))
        .and_then(Value::as_str)
        .unwrap_or("linear proof verifier rejected without a structured refusal")
        .to_string()
}

fn validate_part_dec_linear_proof_backend_capacity(
    backend_input: &Value,
    expected_witness_bound: &PartDecWitnessBound,
) -> CanonicalResult<()> {
    require_u64_at_path(
        backend_input,
        &["proofBackendWitnessBoundCapacityBits"],
        PART_DEC_LINEAR_PROOF_BACKEND_WITNESS_BOUND_CAPACITY_BITS,
        "rank refresh PartDec linear proof backend input witness-bound capacity bits",
    )?;
    require_u64_at_path(
        backend_input,
        &["witnessL2BoundSquaredBitLength"],
        expected_witness_bound.witness_l2_bound_squared_bit_length,
        "rank refresh PartDec linear proof backend input witness l2 bound bit length",
    )?;
    require_bool_at_path(
        backend_input,
        &["witnessL2BoundSquaredFitsProofBackend"],
        expected_witness_bound.witness_l2_bound_squared_fits_current_backend,
        "rank refresh PartDec linear proof backend input witness l2 bound fits proof backend flag",
    )?;
    require_string_at_path(
        backend_input,
        &["proofBackendWitnessBoundStatus"],
        part_dec_linear_proof_backend_witness_bound_status(expected_witness_bound),
        "rank refresh PartDec linear proof backend input witness-bound status",
    )
}

fn part_dec_linear_proof_backend_witness_bound_status(
    expected_witness_bound: &PartDecWitnessBound,
) -> &'static str {
    if expected_witness_bound.witness_l2_bound_squared_fits_current_backend {
        PART_DEC_LINEAR_PROOF_BACKEND_WITNESS_BOUND_FITS_STATUS
    } else {
        PART_DEC_LINEAR_PROOF_BACKEND_WITNESS_BOUND_EXCEEDS_STATUS
    }
}

fn validate_part_dec_linear_proof_backend_prime_input(
    proof_input: &Value,
    adapter_table: &Value,
    modulus_index: usize,
    expected_witness_bound: &PartDecWitnessBound,
) -> CanonicalResult<()> {
    require_u64_at_path(
        proof_input,
        &["modulusIndex"],
        modulus_index as u64,
        "rank refresh PartDec linear proof backend input modulus index",
    )?;
    let modulus = DATA_PRIMES[modulus_index];
    require_u64_at_path(
        proof_input,
        &["modulus"],
        modulus,
        "rank refresh PartDec linear proof backend input modulus",
    )?;
    compare_required_hash(
        string_at_path(proof_input, &["publicCommonRandomPolynomialHash512"])?,
        string_at_path(adapter_table, &["publicCommonRandomPolynomialHash512"])?,
        "rank refresh PartDec linear proof backend input common-random hash",
    )?;
    compare_required_hash(
        string_at_path(proof_input, &["publicKeyShareComponentZeroHash512"])?,
        string_at_path(adapter_table, &["publicKeyShareComponentZeroHash512"])?,
        "rank refresh PartDec linear proof backend input public key-share hash",
    )?;
    compare_required_hash(
        string_at_path(proof_input, &["inputRankCiphertextComponentOneHash512"])?,
        string_at_path(adapter_table, &["inputRankCiphertextComponentOneHash512"])?,
        "rank refresh PartDec linear proof backend input component-one hash",
    )?;
    compare_required_hash(
        string_at_path(proof_input, &["partialDecryptionShareHash512"])?,
        string_at_path(adapter_table, &["partialDecryptionShareHash512"])?,
        "rank refresh PartDec linear proof backend input partial-share hash",
    )?;
    compare_required_hash(
        string_at_path(proof_input, &["sourceMatrixHash512"])?,
        string_at_path(adapter_table, &["sourceMatrixHash512"])?,
        "rank refresh PartDec linear proof backend input source matrix hash",
    )?;
    compare_required_hash(
        string_at_path(proof_input, &["targetVectorHash512"])?,
        string_at_path(adapter_table, &["targetVectorHash512"])?,
        "rank refresh PartDec linear proof backend input target vector hash",
    )?;

    let parameter_binding = value_at_path(proof_input, &["proofParameterBinding"])?;
    require_string_at_path(
        parameter_binding,
        &["parameterProfileStatus"],
        "RankRefreshPartDecParameterProfilePending",
        "rank refresh PartDec linear proof backend input parameter profile status",
    )?;
    require_string_at_path(
        parameter_binding,
        &["relation"],
        "A*w + t = 0",
        "rank refresh PartDec linear proof backend input parameter relation",
    )?;
    require_string_at_path(
        parameter_binding,
        &["coefficientModulus"],
        &modulus.to_string(),
        "rank refresh PartDec linear proof backend input parameter modulus",
    )?;
    require_u64_at_path(
        parameter_binding,
        &["sourceRingDegree"],
        POLYNOMIAL_DEGREE as u64,
        "rank refresh PartDec linear proof backend input parameter source ring degree",
    )?;
    require_u64_at_path(
        parameter_binding,
        &["proofSystemRingDegree"],
        PART_DEC_LINEAR_PROOF_SYSTEM_RING_DEGREE,
        "rank refresh PartDec linear proof backend input parameter proof-system ring degree",
    )?;
    require_u64_at_path(
        parameter_binding,
        &["statementRows"],
        2,
        "rank refresh PartDec linear proof backend input parameter statement rows",
    )?;
    require_u64_at_path(
        parameter_binding,
        &["statementColumns"],
        3,
        "rank refresh PartDec linear proof backend input parameter statement columns",
    )?;
    require_string_at_path(
        parameter_binding,
        &["witnessBoundSource"],
        PART_DEC_WITNESS_BOUND_SOURCE,
        "rank refresh PartDec linear proof backend input parameter witness bound source",
    )?;
    require_string_at_path(
        parameter_binding,
        &["witnessBoundComputation"],
        PART_DEC_WITNESS_BOUND_COMPUTATION,
        "rank refresh PartDec linear proof backend input parameter witness bound computation",
    )?;
    require_string_at_path(
        parameter_binding,
        &["secretShareDistribution"],
        "owner-routed-standard-ternary-local-share",
        "rank refresh PartDec linear proof backend input parameter secret-share distribution",
    )?;
    require_u64_at_path(
        parameter_binding,
        &["secretShareCoefficientBound"],
        expected_witness_bound.secret_share_coefficient_bound,
        "rank refresh PartDec linear proof backend input parameter secret-share coefficient bound",
    )?;
    require_string_at_path(
        parameter_binding,
        &["errorShareDistribution"],
        "owner-routed-centered-binomial-eta2-collective-error",
        "rank refresh PartDec linear proof backend input parameter error-share distribution",
    )?;
    require_u64_at_path(
        parameter_binding,
        &["errorShareCoefficientBound"],
        expected_witness_bound.error_share_coefficient_bound,
        "rank refresh PartDec linear proof backend input parameter error-share coefficient bound",
    )?;
    require_u64_at_path(
        parameter_binding,
        &["smudgingNoiseCoefficientBoundBits"],
        expected_witness_bound.smudging_noise_coefficient_bound_bits,
        "rank refresh PartDec linear proof backend input parameter smudging-noise coefficient bound bits",
    )?;
    require_decimal_string_at_path(
        parameter_binding,
        &["smudgingNoiseCoefficientBound"],
        &expected_witness_bound.smudging_noise_coefficient_bound_decimal,
        "rank refresh PartDec linear proof backend input parameter smudging-noise coefficient bound",
    )?;
    require_decimal_string_at_path(
        parameter_binding,
        &["witnessL2BoundSquared"],
        &expected_witness_bound.witness_l2_bound_squared_decimal,
        "rank refresh PartDec linear proof backend input parameter witness l2 bound squared",
    )?;

    let encoding_binding = value_at_path(proof_input, &["proofEncodingBinding"])?;
    require_string_at_path(
        encoding_binding,
        &["proofEncodingStatus"],
        "RankRefreshPartDecProofEncodingPending",
        "rank refresh PartDec linear proof backend input encoding status",
    )?;
    require_u64_at_path(
        encoding_binding,
        &["proofSystemRingDegree"],
        PART_DEC_LINEAR_PROOF_SYSTEM_RING_DEGREE,
        "rank refresh PartDec linear proof backend input encoding proof-system ring degree",
    )?;
    require_u64_at_path(
        encoding_binding,
        &["sourcePolynomialSplitFactor"],
        PART_DEC_LINEAR_PROOF_SOURCE_POLYNOMIAL_SPLIT_FACTOR,
        "rank refresh PartDec linear proof backend input encoding source split factor",
    )?;
    require_u64_at_path(
        encoding_binding,
        &["expectedShortResponseVectorLength"],
        PART_DEC_LINEAR_PROOF_EXPECTED_SHORT_RESPONSE_VECTOR_LENGTH,
        "rank refresh PartDec linear proof backend input encoding expected short-response length",
    )?;
    require_string_at_path(
        encoding_binding,
        &["matrixCoefficientRepresentation"],
        "canonicalUnsignedSourceModulus",
        "rank refresh PartDec linear proof backend input encoding matrix representation",
    )?;
    require_string_at_path(
        encoding_binding,
        &["targetCoefficientRepresentation"],
        "canonicalUnsignedSourceModulus",
        "rank refresh PartDec linear proof backend input encoding target representation",
    )
}

fn validate_smudging_bound_certificate(transcript: &Value) -> CanonicalResult<()> {
    let certificate = value_at_path(transcript, &["smudgingBoundCertificate"])?;
    compare_derived_hash(
        "MaskedRankRefreshSmudgingBoundCertificateHash",
        certificate,
        hash_at_path(transcript, &["smudgingBoundCertificateHash"])?,
        "rank refresh smudging-bound certificate hash",
    )?;
    require_string_at_path(
        certificate,
        &["objectType"],
        SMUDGING_BOUND_CERTIFICATE_OBJECT_TYPE,
        "rank refresh smudging-bound certificate object type",
    )?;
    require_u64_at_path(
        certificate,
        &["objectVersion"],
        1,
        "rank refresh smudging-bound certificate version",
    )?;
    require_string_at_path(
        certificate,
        &["profileId"],
        MASKED_RANK_REFRESH_PROFILE_ID,
        "rank refresh smudging-bound certificate profile id",
    )?;
    require_string_at_path(
        certificate,
        &["boundProfileId"],
        "masked-rank-refresh-smudging-bound-v1",
        "rank refresh smudging-bound profile id",
    )?;
    require_string_at_path(
        certificate,
        &["boundStatementStatus"],
        "SmudgingNoiseBoundStatementBound",
        "rank refresh smudging-bound statement status",
    )?;
    require_string_at_path(
        certificate,
        &["boundProofVerificationStatus"],
        "SmudgingNoiseBoundProofPending",
        "rank refresh smudging-bound proof status",
    )?;
    require_bool_at_path(
        certificate,
        &["boundProofBytesVerified"],
        false,
        "rank refresh smudging-bound proof-byte verification flag",
    )?;
    validate_proof_bytes_binding(
        certificate,
        &ProofBytesBinding {
            proof_bytes_hex_field: "boundProofBytesHex",
            proof_size_bytes_field: "boundProofSizeBytes",
            proof_bytes_hash_field: "boundProofBytesHash",
            proof_statement_hash_field: "boundProofStatementHash",
            statement_hash_namespace: "MaskedRankRefreshSmudgingBoundStatementHash",
            statement_metadata_fields: &SMUDGING_BOUND_PROOF_METADATA_FIELDS,
            label: "rank refresh smudging-bound",
        },
    )?;
    require_bool_at_path(
        certificate,
        &["appendixBBoundRequired"],
        true,
        "rank refresh Appendix B bound requirement",
    )?;
    require_string_at_path(
        certificate,
        &["correctnessInequality"],
        "B_final < Q_data/(2*p)",
        "rank refresh smudging-bound correctness inequality",
    )?;
    require_string_at_path(
        certificate,
        &["smudgingDistributionStatus"],
        "AppendixBSmudgingDistributionPending",
        "rank refresh smudging distribution status",
    )?;
    require_u64_at_path(
        certificate,
        &["minimumCorrectnessFailureProbabilityBits"],
        128,
        "rank refresh smudging-bound minimum failure probability bits",
    )?;
    validate_smudging_bound_bit_budget(transcript, certificate)?;
    require_u64_at_path(
        certificate,
        &["polynomialDegree"],
        POLYNOMIAL_DEGREE as u64,
        "rank refresh smudging-bound polynomial degree",
    )?;
    require_u64_at_path(
        certificate,
        &["dataPrimeCount"],
        DATA_PRIMES.len() as u64,
        "rank refresh smudging-bound data-prime count",
    )?;
    require_u64_at_path(
        certificate,
        &["plaintextModulus"],
        PLAINTEXT_MODULUS,
        "rank refresh smudging-bound plaintext modulus",
    )?;
    compare_required_hash(
        hash_at_path(certificate, &["setupPackageHash"])?,
        hash_at_path(transcript, &["setupPackageHash"])?,
        "rank refresh smudging-bound setup package hash",
    )?;
    compare_required_hash(
        hash_at_path(certificate, &["evaluationContextHash"])?,
        hash_at_path(transcript, &["evaluationContextHash"])?,
        "rank refresh smudging-bound evaluation context hash",
    )?;
    compare_required_hash(
        hash_at_path(certificate, &["inputRankCiphertextRoot"])?,
        hash_at_path(transcript, &["inputRankCiphertextRoot"])?,
        "rank refresh smudging-bound input rank root",
    )?;
    compare_required_hash(
        hash_at_path(certificate, &["finDecLagrangeCoefficientAuditRoot"])?,
        hash_at_path(transcript, &["finDecLagrangeCoefficientAuditRoot"])?,
        "rank refresh smudging-bound FinDec Lagrange coefficient audit root",
    )?;
    compare_required_hash(
        hash_at_path(certificate, &["shareSelectionRuleHash"])?,
        hash_at_path(transcript, &["shareSelectionRuleHash"])?,
        "rank refresh smudging-bound share-selection hash",
    )?;
    compare_required_hash(
        hash_at_path(certificate, &["thresholdShareVerificationKeyHash"])?,
        hash_at_path(transcript, &["thresholdShareVerificationKeyHash"])?,
        "rank refresh smudging-bound threshold verification-key hash",
    )?;
    compare_required_hash(
        hash_at_path(certificate, &["algebraicShareVerificationKeyHash"])?,
        hash_at_path(transcript, &["algebraicShareVerificationKeyHash"])?,
        "rank refresh smudging-bound algebraic verification-key hash",
    )?;

    Ok(())
}

fn validate_smudging_bound_bit_budget(
    transcript: &Value,
    certificate: &Value,
) -> CanonicalResult<()> {
    require_string_at_path(
        certificate,
        &["boundArithmetic"],
        "ceil-log2-bit-budget",
        "rank refresh smudging-bound arithmetic",
    )?;
    let data_modulus_bits =
        u64::try_from(data_basis_modulus_bits()).expect("data basis bit accounting fits u64");
    require_u64_at_path(
        certificate,
        &["dataModulusBits"],
        data_modulus_bits,
        "rank refresh smudging-bound data modulus bits",
    )?;
    let plaintext_modulus_bits = u64::from(modulus_bit_length(PLAINTEXT_MODULUS));
    require_u64_at_path(
        certificate,
        &["plaintextModulusBits"],
        plaintext_modulus_bits,
        "rank refresh smudging-bound plaintext modulus bits",
    )?;
    let share_records = array_at_path(transcript, &["rankRefreshShareRecords"])?;
    let selected_share_count = u64::try_from(share_records.len()).expect("share count fits u64");
    require_u64_at_path(
        certificate,
        &["selectedShareCount"],
        selected_share_count,
        "rank refresh smudging-bound selected share count",
    )?;
    let lagrange_coefficient_audit =
        value_at_path(transcript, &["finDecLagrangeCoefficientAudit"])?;
    let maximum_lagrange_coefficient_bits = u64_at_path(
        lagrange_coefficient_audit,
        &["maximumLagrangeCoefficientBits"],
    )?;
    require_u64_at_path(
        certificate,
        &["maximumLagrangeCoefficientBits"],
        maximum_lagrange_coefficient_bits,
        "rank refresh smudging-bound maximum Lagrange coefficient bits",
    )?;
    let partial_decryption_share_noise_bound_bits =
        u64_at_path(certificate, &["partialDecryptionShareNoiseBoundBits"])?;
    let expected_share_combination_bound_bits = partial_decryption_share_noise_bound_bits
        .checked_add(maximum_lagrange_coefficient_bits)
        .and_then(|value| value.checked_add(ceil_log2_u64(selected_share_count)))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "rank refresh smudging-bound share-combination bit budget overflowed",
            )
        })?;
    require_u64_at_path(
        certificate,
        &["selectedShareCombinationBoundBits"],
        expected_share_combination_bound_bits,
        "rank refresh smudging-bound selected share-combination bound bits",
    )?;
    let input_component_zero_noise_bound_bits =
        u64_at_path(certificate, &["inputCiphertextComponentZeroNoiseBoundBits"])?;
    let expected_final_noise_bound_bits = input_component_zero_noise_bound_bits
        .max(expected_share_combination_bound_bits)
        .checked_add(1)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "rank refresh smudging-bound final-noise bit budget overflowed",
            )
        })?;
    let final_noise_bound_bits = u64_at_path(certificate, &["finalNoiseBoundBits"])?;
    if final_noise_bound_bits == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "rank refresh smudging-bound final noise bound bits must be nonzero",
        ));
    }
    let required_modulus_bits = final_noise_bound_bits
        .checked_add(plaintext_modulus_bits)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "rank refresh smudging-bound bit budget overflowed",
            )
        })?;
    if required_modulus_bits >= data_modulus_bits {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "rank refresh smudging-bound final noise budget does not satisfy B_final < Q_data/(2*p)",
        ));
    }
    if final_noise_bound_bits != expected_final_noise_bound_bits {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "rank refresh smudging-bound final noise bound does not match selected-share and input-component bounds",
        ));
    }
    let expected_margin_bits = data_modulus_bits - required_modulus_bits;
    require_u64_at_path(
        certificate,
        &["correctnessMarginBits"],
        expected_margin_bits,
        "rank refresh smudging-bound correctness margin bits",
    )?;

    Ok(())
}

fn ceil_log2_u64(value: u64) -> u64 {
    if value <= 1 {
        0
    } else {
        u64::from(u64::BITS - (value - 1).leading_zeros())
    }
}

fn u64_bit_length(value: u64) -> u64 {
    if value == 0 {
        0
    } else {
        u64::from(u64::BITS - value.leading_zeros())
    }
}

fn part_dec_public_key_share_witness_l2_bound_squared() -> u64 {
    let coefficient_bound_square_sum = PART_DEC_SECRET_SHARE_COEFFICIENT_BOUND
        .checked_mul(PART_DEC_SECRET_SHARE_COEFFICIENT_BOUND)
        .and_then(|secret_share_square| {
            PART_DEC_ERROR_SHARE_COEFFICIENT_BOUND
                .checked_mul(PART_DEC_ERROR_SHARE_COEFFICIENT_BOUND)
                .and_then(|error_share_square| secret_share_square.checked_add(error_share_square))
        })
        .expect("public key-share witness coefficient bounds fit u64");
    (POLYNOMIAL_DEGREE as u64)
        .checked_mul(coefficient_bound_square_sum)
        .expect("public key-share witness l2 bound fits u64")
}

fn part_dec_public_key_share_witness_l2_bound_squared_bit_length() -> u64 {
    u64_bit_length(part_dec_public_key_share_witness_l2_bound_squared())
}

fn part_dec_public_key_share_witness_bound_fits_current_backend() -> bool {
    part_dec_public_key_share_witness_l2_bound_squared_bit_length()
        <= PART_DEC_LINEAR_PROOF_BACKEND_WITNESS_BOUND_CAPACITY_BITS
}

fn part_dec_public_key_share_witness_bound_status() -> &'static str {
    if part_dec_public_key_share_witness_bound_fits_current_backend() {
        PART_DEC_LINEAR_PROOF_BACKEND_WITNESS_BOUND_FITS_STATUS
    } else {
        PART_DEC_LINEAR_PROOF_BACKEND_WITNESS_BOUND_EXCEEDS_STATUS
    }
}

fn validate_fin_dec_lagrange_coefficient_audit(transcript: &Value) -> CanonicalResult<()> {
    let audit = value_at_path(transcript, &["finDecLagrangeCoefficientAudit"])?;
    compare_derived_hash(
        "MaskedRankRefreshFinDecLagrangeCoefficientAuditRoot",
        audit,
        hash_at_path(transcript, &["finDecLagrangeCoefficientAuditRoot"])?,
        "rank refresh FinDec Lagrange coefficient audit root",
    )?;
    require_string_at_path(
        audit,
        &["objectType"],
        FIN_DEC_LAGRANGE_COEFFICIENT_AUDIT_OBJECT_TYPE,
        "rank refresh FinDec Lagrange coefficient audit object type",
    )?;
    require_u64_at_path(
        audit,
        &["objectVersion"],
        1,
        "rank refresh FinDec Lagrange coefficient audit version",
    )?;
    require_string_at_path(
        audit,
        &["profileId"],
        MASKED_RANK_REFRESH_PROFILE_ID,
        "rank refresh FinDec Lagrange coefficient audit profile id",
    )?;
    require_string_at_path(
        audit,
        &["auditStatus"],
        "SelectedShareLagrangeCoefficientAuditBound",
        "rank refresh FinDec Lagrange coefficient audit status",
    )?;
    require_string_at_path(
        audit,
        &["combinationRule"],
        "LagrangeInterpolationOverSelectedShares",
        "rank refresh FinDec Lagrange coefficient audit combination rule",
    )?;
    require_string_at_path(
        audit,
        &["interpolationPointKind"],
        "roster-position-plus-one",
        "rank refresh FinDec Lagrange coefficient audit interpolation point kind",
    )?;
    require_string_at_path(
        audit,
        &["lagrangeCoefficientDomain"],
        "per-data-prime-canonical-residue",
        "rank refresh FinDec Lagrange coefficient audit coefficient domain",
    )?;
    require_string_at_path(
        audit,
        &["coefficientEncoding"],
        "u64-canonical-residue-by-data-prime",
        "rank refresh FinDec Lagrange coefficient audit coefficient encoding",
    )?;
    require_string_at_path(
        audit,
        &["basisId"],
        "data",
        "rank refresh FinDec Lagrange coefficient audit basis",
    )?;
    require_u64_at_path(
        audit,
        &["polynomialDegree"],
        POLYNOMIAL_DEGREE as u64,
        "rank refresh FinDec Lagrange coefficient audit polynomial degree",
    )?;
    require_u64_at_path(
        audit,
        &["dataPrimeCount"],
        DATA_PRIMES.len() as u64,
        "rank refresh FinDec Lagrange coefficient audit data-prime count",
    )?;
    require_u64_at_path(
        audit,
        &["coefficientTableCount"],
        DATA_PRIMES.len() as u64,
        "rank refresh FinDec Lagrange coefficient audit table count",
    )?;
    require_u64_at_path(
        audit,
        &["plaintextModulus"],
        PLAINTEXT_MODULUS,
        "rank refresh FinDec Lagrange coefficient audit plaintext modulus",
    )?;
    compare_required_hash(
        hash_at_path(audit, &["setupPackageHash"])?,
        hash_at_path(transcript, &["setupPackageHash"])?,
        "rank refresh FinDec Lagrange coefficient audit setup package hash",
    )?;
    compare_required_hash(
        hash_at_path(audit, &["evaluationContextHash"])?,
        hash_at_path(transcript, &["evaluationContextHash"])?,
        "rank refresh FinDec Lagrange coefficient audit evaluation context hash",
    )?;
    compare_required_hash(
        hash_at_path(audit, &["inputRankCiphertextRoot"])?,
        hash_at_path(transcript, &["inputRankCiphertextRoot"])?,
        "rank refresh FinDec Lagrange coefficient audit input rank root",
    )?;
    compare_required_hash(
        hash_at_path(audit, &["shareSelectionRuleHash"])?,
        hash_at_path(transcript, &["shareSelectionRuleHash"])?,
        "rank refresh FinDec Lagrange coefficient audit share-selection hash",
    )?;
    compare_required_hash(
        hash_at_path(audit, &["thresholdShareVerificationKeyHash"])?,
        hash_at_path(transcript, &["thresholdShareVerificationKeyHash"])?,
        "rank refresh FinDec Lagrange coefficient audit threshold verification-key hash",
    )?;
    compare_required_hash(
        hash_at_path(audit, &["algebraicShareVerificationKeyHash"])?,
        hash_at_path(transcript, &["algebraicShareVerificationKeyHash"])?,
        "rank refresh FinDec Lagrange coefficient audit algebraic verification-key hash",
    )?;

    let share_records = array_at_path(transcript, &["rankRefreshShareRecords"])?;
    require_u64_at_path(
        audit,
        &["selectedShareCount"],
        u64::try_from(share_records.len()).expect("share count fits u64"),
        "rank refresh FinDec Lagrange coefficient audit selected share count",
    )?;
    compare_array_to_share_records(
        audit,
        &["selectedTrusteeIdentities"],
        share_records,
        &["trusteeIdentity"],
        "rank refresh FinDec Lagrange coefficient audit selected trustee identities",
    )?;
    compare_array_to_share_records(
        audit,
        &["selectedRosterPositions"],
        share_records,
        &["rosterPosition"],
        "rank refresh FinDec Lagrange coefficient audit selected roster positions",
    )?;
    compare_array_to_share_records(
        audit,
        &["selectedAlgebraicShareVerificationKeyBindingRoots"],
        share_records,
        &["selectedAlgebraicShareVerificationKeyBindingRoot"],
        "rank refresh FinDec Lagrange coefficient audit selected algebraic share-verification key binding roots",
    )?;

    let coefficient_tables = array_at_path(audit, &["coefficientTables"])?;
    if coefficient_tables.len() != DATA_PRIMES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rank refresh FinDec Lagrange coefficient audit must include one coefficient table per data prime",
        ));
    }
    let mut maximum_lagrange_coefficient_bits = 0_u64;
    for (modulus_index, table) in coefficient_tables.iter().enumerate() {
        require_u64_at_path(
            table,
            &["modulusIndex"],
            modulus_index as u64,
            "rank refresh FinDec Lagrange coefficient audit modulus index",
        )?;
        let modulus = DATA_PRIMES[modulus_index];
        require_u64_at_path(
            table,
            &["modulus"],
            modulus,
            "rank refresh FinDec Lagrange coefficient audit modulus",
        )?;
        require_string_at_path(
            table,
            &["coefficientEncoding"],
            "u64-canonical-residue",
            "rank refresh FinDec Lagrange coefficient audit table encoding",
        )?;
        let lagrange_coefficients =
            lagrange_coefficients_for_selected_share_records(share_records, modulus)?;
        validate_lagrange_coefficient_entries(table, share_records, &lagrange_coefficients)?;
        let table_maximum_lagrange_coefficient_bits = lagrange_coefficients
            .iter()
            .copied()
            .map(modulus_bit_length)
            .max()
            .map(u64::from)
            .unwrap_or(0);
        require_u64_at_path(
            table,
            &["maximumLagrangeCoefficientBits"],
            table_maximum_lagrange_coefficient_bits,
            "rank refresh FinDec Lagrange coefficient audit table maximum coefficient bits",
        )?;
        maximum_lagrange_coefficient_bits =
            maximum_lagrange_coefficient_bits.max(table_maximum_lagrange_coefficient_bits);
    }
    require_u64_at_path(
        audit,
        &["maximumLagrangeCoefficientBits"],
        maximum_lagrange_coefficient_bits,
        "rank refresh FinDec Lagrange coefficient audit maximum coefficient bits",
    )
}

fn validate_fin_dec_masked_opening(transcript: &Value) -> CanonicalResult<()> {
    let opening = value_at_path(transcript, &["maskedOpening"])?;
    compare_derived_hash(
        "MaskedRankRefreshFinDecMaskedOpeningRoot",
        opening,
        hash_at_path(transcript, &["maskedOpeningRoot"])?,
        "rank refresh FinDec masked-opening root",
    )?;
    require_string_at_path(
        opening,
        &["objectType"],
        FIN_DEC_MASKED_OPENING_OBJECT_TYPE,
        "rank refresh FinDec masked-opening object type",
    )?;
    require_u64_at_path(
        opening,
        &["objectVersion"],
        1,
        "rank refresh FinDec masked-opening version",
    )?;
    require_string_at_path(
        opening,
        &["profileId"],
        MASKED_RANK_REFRESH_PROFILE_ID,
        "rank refresh FinDec masked-opening profile id",
    )?;
    require_string_at_path(
        opening,
        &["finDecStatus"],
        "FinDecMaskedOpeningStatementBound",
        "rank refresh FinDec status",
    )?;
    require_string_at_path(
        opening,
        &["combinationRule"],
        "LagrangeInterpolationOverSelectedShares",
        "rank refresh FinDec share-combination rule",
    )?;
    require_string_at_path(
        opening,
        &["invalidShareFilteringMode"],
        "ProofVerifiedSharesOnly",
        "rank refresh FinDec invalid-share filtering mode",
    )?;
    require_string_at_path(
        opening,
        &["finDecProofVerificationStatus"],
        "FinDecMaskedOpeningVerifierPending",
        "rank refresh FinDec proof verification status",
    )?;
    require_bool_at_path(
        opening,
        &["finDecProofBytesVerified"],
        false,
        "rank refresh FinDec proof-byte verification flag",
    )?;
    validate_proof_bytes_binding(
        opening,
        &ProofBytesBinding {
            proof_bytes_hex_field: "proofBytesHex",
            proof_size_bytes_field: "proofSizeBytes",
            proof_bytes_hash_field: "proofBytesHash",
            proof_statement_hash_field: "proofStatementHash",
            statement_hash_namespace: "MaskedRankRefreshFinDecMaskedOpeningStatementHash",
            statement_metadata_fields: &FIN_DEC_PROOF_METADATA_FIELDS,
            label: "rank refresh FinDec masked-opening",
        },
    )?;
    require_bool_at_path(
        opening,
        &["semanticRankOpeningAllowed"],
        false,
        "rank refresh FinDec semantic opening flag",
    )?;
    require_bool_at_path(
        opening,
        &["plaintextRankExported"],
        false,
        "rank refresh FinDec plaintext rank export flag",
    )?;
    require_bool_at_path(
        opening,
        &["maskedOpeningOnly"],
        true,
        "rank refresh FinDec masked-opening flag",
    )?;
    compare_required_hash(
        hash_at_path(opening, &["setupPackageHash"])?,
        hash_at_path(transcript, &["setupPackageHash"])?,
        "rank refresh FinDec setup package hash",
    )?;
    compare_required_hash(
        hash_at_path(opening, &["evaluationContextHash"])?,
        hash_at_path(transcript, &["evaluationContextHash"])?,
        "rank refresh FinDec evaluation context hash",
    )?;
    compare_required_hash(
        hash_at_path(opening, &["inputRankCiphertextRoot"])?,
        hash_at_path(transcript, &["inputRankCiphertextRoot"])?,
        "rank refresh FinDec input rank root",
    )?;
    compare_required_hash(
        hash_at_path(opening, &["shareSelectionRuleHash"])?,
        hash_at_path(transcript, &["shareSelectionRuleHash"])?,
        "rank refresh FinDec share-selection hash",
    )?;
    compare_required_hash(
        hash_at_path(opening, &["smudgingBoundCertificateHash"])?,
        hash_at_path(transcript, &["smudgingBoundCertificateHash"])?,
        "rank refresh FinDec smudging-bound certificate hash",
    )?;
    compare_required_hash(
        hash_at_path(opening, &["finDecLagrangeCoefficientAuditRoot"])?,
        hash_at_path(transcript, &["finDecLagrangeCoefficientAuditRoot"])?,
        "rank refresh FinDec Lagrange coefficient audit root",
    )?;
    compare_required_hash(
        hash_at_path(opening, &["maskedOpeningPayloadRoot"])?,
        hash_at_path(transcript, &["maskedOpeningPayloadRoot"])?,
        "rank refresh FinDec masked-opening payload root",
    )?;
    let share_records = array_at_path(transcript, &["rankRefreshShareRecords"])?;
    require_u64_at_path(
        opening,
        &["selectedShareCount"],
        u64::try_from(share_records.len()).expect("share count fits u64"),
        "rank refresh FinDec selected share count",
    )?;
    compare_array_to_share_records(
        opening,
        &["selectedTrusteeIdentities"],
        share_records,
        &["trusteeIdentity"],
        "rank refresh FinDec selected trustee identities",
    )?;
    compare_array_to_share_records(
        opening,
        &["selectedRosterPositions"],
        share_records,
        &["rosterPosition"],
        "rank refresh FinDec selected roster positions",
    )?;
    compare_array_to_share_records(
        opening,
        &["partialDecryptionShareRoots"],
        share_records,
        &["partialDecryptionShareRoot"],
        "rank refresh FinDec partial-decryption share roots",
    )?;
    compare_array_to_share_records(
        opening,
        &["selectedAlgebraicShareVerificationKeyBindingRoots"],
        share_records,
        &["selectedAlgebraicShareVerificationKeyBindingRoot"],
        "rank refresh FinDec selected algebraic share-verification key binding roots",
    )?;
    compare_array_to_share_records(
        opening,
        &["shareEquationProofRoots"],
        share_records,
        &["shareEquationProofRoot"],
        "rank refresh FinDec share-equation proof roots",
    )?;
    compare_array_to_share_records(
        opening,
        &["shareFreshnessHashes"],
        share_records,
        &["shareFreshnessHash"],
        "rank refresh FinDec share freshness hashes",
    )?;
    validate_fin_dec_masked_opening_payload(transcript, opening)?;

    Ok(())
}

fn validate_fin_dec_masked_opening_payload(
    transcript: &Value,
    opening: &Value,
) -> CanonicalResult<()> {
    let payload = value_at_path(transcript, &["maskedOpeningPayload"])?;
    let payload_root = hash_at_path(transcript, &["maskedOpeningPayloadRoot"])?;
    compare_derived_hash(
        "MaskedRankRefreshFinDecMaskedOpeningPayloadRoot",
        payload,
        payload_root,
        "rank refresh FinDec masked-opening payload root",
    )?;
    compare_required_hash(
        hash_at_path(opening, &["maskedOpeningPayloadRoot"])?,
        payload_root,
        "rank refresh FinDec masked-opening payload root",
    )?;
    require_string_at_path(
        payload,
        &["objectType"],
        FIN_DEC_MASKED_OPENING_PAYLOAD_OBJECT_TYPE,
        "rank refresh FinDec masked-opening payload object type",
    )?;
    require_u64_at_path(
        payload,
        &["objectVersion"],
        1,
        "rank refresh FinDec masked-opening payload version",
    )?;
    require_string_at_path(
        payload,
        &["profileId"],
        MASKED_RANK_REFRESH_PROFILE_ID,
        "rank refresh FinDec masked-opening payload profile id",
    )?;
    require_string_at_path(
        payload,
        &["payloadStatus"],
        "PublicFinDecMaskedOpeningPayloadBound",
        "rank refresh FinDec masked-opening payload status",
    )?;
    require_string_at_path(
        payload,
        &["payloadKind"],
        "selected-share-lagrange-combination-polynomial",
        "rank refresh FinDec masked-opening payload kind",
    )?;
    require_string_at_path(
        payload,
        &["combinationRule"],
        "LagrangeInterpolationOverSelectedShares",
        "rank refresh FinDec masked-opening payload combination rule",
    )?;
    require_string_at_path(
        payload,
        &["combinationEquation"],
        "maskedOpeningPayload = inputCiphertextComponentZero + sum(lagrangeCoefficient_i * partialDecryptionShare_i) mod q",
        "rank refresh FinDec masked-opening payload equation",
    )?;
    require_bool_at_path(
        payload,
        &["inputCiphertextComponentZeroApplied"],
        true,
        "rank refresh FinDec masked-opening payload input component-zero flag",
    )?;
    require_string_at_path(
        payload,
        &["invalidShareFilteringMode"],
        "ProofVerifiedSharesOnly",
        "rank refresh FinDec masked-opening payload invalid-share filtering mode",
    )?;
    require_string_at_path(
        payload,
        &["interpolationPointKind"],
        "roster-position-plus-one",
        "rank refresh FinDec masked-opening payload interpolation point kind",
    )?;
    require_string_at_path(
        payload,
        &["lagrangeCoefficientDomain"],
        "per-data-prime-canonical-residue",
        "rank refresh FinDec masked-opening payload Lagrange coefficient domain",
    )?;
    require_string_at_path(
        payload,
        &["basisId"],
        "data",
        "rank refresh FinDec masked-opening payload basis",
    )?;
    require_string_at_path(
        payload,
        &["coefficientDomain"],
        "coefficient",
        "rank refresh FinDec masked-opening payload coefficient domain",
    )?;
    require_string_at_path(
        payload,
        &["coefficientEncoding"],
        "little-endian-u64-coefficient-vectors-by-data-prime",
        "rank refresh FinDec masked-opening payload coefficient encoding",
    )?;
    require_u64_at_path(
        payload,
        &["componentCount"],
        1,
        "rank refresh FinDec masked-opening payload component count",
    )?;
    require_u64_at_path(
        payload,
        &["polynomialDegree"],
        POLYNOMIAL_DEGREE as u64,
        "rank refresh FinDec masked-opening payload polynomial degree",
    )?;
    require_u64_at_path(
        payload,
        &["dataPrimeCount"],
        DATA_PRIMES.len() as u64,
        "rank refresh FinDec masked-opening payload data-prime count",
    )?;
    require_u64_at_path(
        payload,
        &["plaintextModulus"],
        PLAINTEXT_MODULUS,
        "rank refresh FinDec masked-opening payload plaintext modulus",
    )?;
    require_bool_at_path(
        payload,
        &["maskedOpeningOnly"],
        true,
        "rank refresh FinDec masked-opening payload masked-opening flag",
    )?;
    require_bool_at_path(
        payload,
        &["semanticRankOpeningAllowed"],
        false,
        "rank refresh FinDec masked-opening payload semantic opening flag",
    )?;
    require_bool_at_path(
        payload,
        &["plaintextRankExported"],
        false,
        "rank refresh FinDec masked-opening payload plaintext rank export flag",
    )?;
    compare_required_hash(
        hash_at_path(payload, &["setupPackageHash"])?,
        hash_at_path(transcript, &["setupPackageHash"])?,
        "rank refresh FinDec masked-opening payload setup package hash",
    )?;
    compare_required_hash(
        hash_at_path(payload, &["evaluationContextHash"])?,
        hash_at_path(transcript, &["evaluationContextHash"])?,
        "rank refresh FinDec masked-opening payload evaluation context hash",
    )?;
    compare_required_hash(
        hash_at_path(payload, &["inputRankCiphertextRoot"])?,
        hash_at_path(transcript, &["inputRankCiphertextRoot"])?,
        "rank refresh FinDec masked-opening payload input rank root",
    )?;
    compare_required_hash(
        hash_at_path(payload, &["shareSelectionRuleHash"])?,
        hash_at_path(transcript, &["shareSelectionRuleHash"])?,
        "rank refresh FinDec masked-opening payload share-selection hash",
    )?;
    compare_required_hash(
        hash_at_path(payload, &["smudgingBoundCertificateHash"])?,
        hash_at_path(transcript, &["smudgingBoundCertificateHash"])?,
        "rank refresh FinDec masked-opening payload smudging-bound certificate hash",
    )?;
    compare_required_hash(
        hash_at_path(payload, &["finDecLagrangeCoefficientAuditRoot"])?,
        hash_at_path(transcript, &["finDecLagrangeCoefficientAuditRoot"])?,
        "rank refresh FinDec masked-opening payload Lagrange coefficient audit root",
    )?;
    let share_records = array_at_path(transcript, &["rankRefreshShareRecords"])?;
    require_u64_at_path(
        payload,
        &["selectedShareCount"],
        u64::try_from(share_records.len()).expect("share count fits u64"),
        "rank refresh FinDec masked-opening payload selected share count",
    )?;
    compare_array_to_share_records(
        payload,
        &["selectedTrusteeIdentities"],
        share_records,
        &["trusteeIdentity"],
        "rank refresh FinDec masked-opening payload selected trustee identities",
    )?;
    compare_array_to_share_records(
        payload,
        &["selectedRosterPositions"],
        share_records,
        &["rosterPosition"],
        "rank refresh FinDec masked-opening payload selected roster positions",
    )?;
    compare_array_to_share_records(
        payload,
        &["partialDecryptionShareRoots"],
        share_records,
        &["partialDecryptionShareRoot"],
        "rank refresh FinDec masked-opening payload partial-decryption share roots",
    )?;
    compare_array_to_share_records(
        payload,
        &["selectedAlgebraicShareVerificationKeyBindingRoots"],
        share_records,
        &["selectedAlgebraicShareVerificationKeyBindingRoot"],
        "rank refresh FinDec masked-opening payload selected algebraic share-verification key binding roots",
    )?;
    let input_rank_ciphertext_components = parse_input_rank_ciphertext_components(transcript)?;
    validate_fin_dec_masked_opening_payload_coefficient_tables(
        payload,
        value_at_path(transcript, &["finDecLagrangeCoefficientAudit"])?,
        share_records,
        &input_rank_ciphertext_components[0],
    )
}

fn validate_fin_dec_masked_opening_payload_coefficient_tables(
    payload: &Value,
    lagrange_coefficient_audit: &Value,
    share_records: &[Value],
    input_rank_ciphertext_component_zero: &RnsPolynomial,
) -> CanonicalResult<()> {
    let coefficient_tables = array_at_path(payload, &["coefficientTables"])?;
    if coefficient_tables.len() != DATA_PRIMES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rank refresh FinDec masked-opening payload must include one coefficient table per data prime",
        ));
    }

    for (modulus_index, table) in coefficient_tables.iter().enumerate() {
        let audit_table = array_at_path(lagrange_coefficient_audit, &["coefficientTables"])?
            .get(modulus_index)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "rank refresh FinDec Lagrange coefficient audit table is missing for masked-opening payload",
                )
            })?;
        require_u64_at_path(
            table,
            &["modulusIndex"],
            modulus_index as u64,
            "rank refresh FinDec masked-opening payload modulus index",
        )?;
        let modulus = DATA_PRIMES[modulus_index];
        require_u64_at_path(
            table,
            &["modulus"],
            modulus,
            "rank refresh FinDec masked-opening payload modulus",
        )?;
        require_u64_at_path(
            table,
            &["coefficientByteLength"],
            (POLYNOMIAL_DEGREE * 8) as u64,
            "rank refresh FinDec masked-opening payload coefficient byte length",
        )?;
        require_string_at_path(
            table,
            &["coefficientEncoding"],
            "little-endian-u64",
            "rank refresh FinDec masked-opening payload coefficient table encoding",
        )?;
        let lagrange_coefficients =
            lagrange_coefficients_for_selected_share_records(share_records, modulus)?;
        validate_lagrange_coefficient_entries(table, share_records, &lagrange_coefficients)?;
        compare_lagrange_coefficient_entries_to_audit(table, audit_table)?;
        let actual_coefficients = coefficient_vector_from_le_hex(
            string_at_path(table, &["maskedOpeningCoefficientsLeHex"])?,
            "rank refresh FinDec masked-opening payload coefficient vector",
        )?;
        if actual_coefficients
            .iter()
            .any(|coefficient| *coefficient >= modulus)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "rank refresh FinDec masked-opening payload coefficient is outside its modulus",
            ));
        }
        let expected_partial_share_combination = combine_partial_decryption_share_coefficients(
            share_records,
            modulus_index,
            modulus,
            &lagrange_coefficients,
        )?;
        let component_zero_coefficients = input_ciphertext_component_zero_coefficients_for_modulus(
            input_rank_ciphertext_component_zero,
            modulus_index,
            modulus,
        )?;
        let expected_coefficients = component_zero_coefficients
            .iter()
            .zip(expected_partial_share_combination)
            .map(
                |(component_zero_coefficient, partial_share_combination_coefficient)| {
                    add_mod(
                        *component_zero_coefficient,
                        partial_share_combination_coefficient,
                        modulus,
                    )
                },
            )
            .collect::<CanonicalResult<Vec<_>>>()?;
        if actual_coefficients != expected_coefficients {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "rank refresh FinDec masked-opening payload coefficients do not match input component-zero plus selected-share Lagrange combination",
            ));
        }
        compare_required_hash(
            string_at_path(table, &["maskedOpeningCoefficientHash512"])?,
            &hash512_hex(
                "sealed-lattice-bgv-rns/masked-rank-refresh-fin-dec-masked-opening-coefficient-vector-v1",
                &[&coefficient_vector_bytes(&actual_coefficients)],
            ),
            "rank refresh FinDec masked-opening payload coefficient hash",
        )?;
    }

    Ok(())
}

fn validate_lagrange_coefficient_entries(
    table: &Value,
    share_records: &[Value],
    lagrange_coefficients: &[u64],
) -> CanonicalResult<()> {
    let entries = array_at_path(table, &["lagrangeCoefficientEntries"])?;
    if entries.len() != share_records.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rank refresh FinDec masked-opening Lagrange coefficient entries must match selected shares",
        ));
    }
    for (share_index, (entry, share_record)) in entries.iter().zip(share_records).enumerate() {
        compare_string_value(
            string_at_path(entry, &["trusteeIdentity"])?,
            string_at_path(share_record, &["trusteeIdentity"])?,
            "rank refresh FinDec masked-opening Lagrange coefficient trustee identity",
        )?;
        let roster_position = u64_at_path(share_record, &["rosterPosition"])?;
        require_u64_at_path(
            entry,
            &["rosterPosition"],
            roster_position,
            "rank refresh FinDec masked-opening Lagrange coefficient roster position",
        )?;
        require_u64_at_path(
            entry,
            &["interpolationPoint"],
            roster_position.checked_add(1).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "rank refresh FinDec masked-opening interpolation point overflowed",
                )
            })?,
            "rank refresh FinDec masked-opening Lagrange coefficient interpolation point",
        )?;
        require_u64_at_path(
            entry,
            &["coefficient"],
            lagrange_coefficients[share_index],
            "rank refresh FinDec masked-opening Lagrange coefficient",
        )?;
    }

    Ok(())
}

fn compare_lagrange_coefficient_entries_to_audit(
    table: &Value,
    audit_table: &Value,
) -> CanonicalResult<()> {
    let entries = array_at_path(table, &["lagrangeCoefficientEntries"])?;
    let audit_entries = array_at_path(audit_table, &["lagrangeCoefficientEntries"])?;
    if entries == audit_entries {
        Ok(())
    } else {
        Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "rank refresh FinDec masked-opening payload Lagrange coefficient entries do not match the coefficient audit",
        ))
    }
}

fn combine_partial_decryption_share_coefficients(
    share_records: &[Value],
    modulus_index: usize,
    modulus: u64,
    lagrange_coefficients: &[u64],
) -> CanonicalResult<Vec<u64>> {
    let mut combined_coefficients = vec![0_u64; POLYNOMIAL_DEGREE];
    for (share_index, share_record) in share_records.iter().enumerate() {
        let share_coefficients = partial_decryption_share_coefficients_for_modulus(
            share_record,
            modulus_index,
            modulus,
        )?;
        for (combined_coefficient, share_coefficient) in
            combined_coefficients.iter_mut().zip(share_coefficients)
        {
            *combined_coefficient = add_mod(
                *combined_coefficient,
                mul_mod(
                    share_coefficient,
                    lagrange_coefficients[share_index],
                    modulus,
                )?,
                modulus,
            )?;
        }
    }

    Ok(combined_coefficients)
}

fn partial_decryption_share_coefficients_for_modulus(
    share_record: &Value,
    modulus_index: usize,
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    let payload = value_at_path(share_record, &["partialDecryptionSharePayload"])?;
    let coefficient_tables = array_at_path(payload, &["coefficientTables"])?;
    let table = coefficient_tables.get(modulus_index).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rank refresh partial-decryption share coefficient table is missing for FinDec combination",
        )
    })?;
    require_u64_at_path(
        table,
        &["modulusIndex"],
        modulus_index as u64,
        "rank refresh partial-decryption share FinDec modulus index",
    )?;
    require_u64_at_path(
        table,
        &["modulus"],
        modulus,
        "rank refresh partial-decryption share FinDec modulus",
    )?;
    coefficient_vector_from_le_hex(
        string_at_path(table, &["shareCoefficientsLeHex"])?,
        "rank refresh partial-decryption share FinDec coefficient vector",
    )
}

fn parse_input_rank_ciphertext_components(
    transcript: &Value,
) -> CanonicalResult<Vec<RnsPolynomial>> {
    let payload = value_at_path(transcript, &["inputRankCiphertextComponentOnePayload"])?;
    let canonical_bytes_hex = string_at_path(payload, &["canonicalBytesHex"])?;
    let parsed = parse_bgv_object_hex(canonical_bytes_hex)?;
    if parsed.object_kind != BgvObjectKind::Ciphertext || parsed.components.len() != 2 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "rank refresh input rank payload must be a two-component BGV ciphertext",
        ));
    }

    Ok(parsed.components)
}

fn input_ciphertext_component_zero_coefficients_for_modulus(
    component_zero: &RnsPolynomial,
    modulus_index: usize,
    modulus: u64,
) -> CanonicalResult<&[u64]> {
    let actual_modulus = component_zero.moduli.get(modulus_index).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rank refresh input ciphertext component-zero modulus is missing for FinDec masked opening",
        )
    })?;
    if *actual_modulus != modulus {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "rank refresh input ciphertext component-zero modulus does not match FinDec masked opening",
        ));
    }
    let coefficients = component_zero
        .residues_by_modulus
        .get(modulus_index)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "rank refresh input ciphertext component-zero coefficients are missing for FinDec masked opening",
            )
        })?;
    if coefficients.len() != POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rank refresh input ciphertext component-zero coefficients do not match the selected BGV profile",
        ));
    }

    Ok(coefficients)
}

fn lagrange_coefficients_for_selected_share_records(
    share_records: &[Value],
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    let interpolation_points = share_records
        .iter()
        .map(|share_record| {
            u64_at_path(share_record, &["rosterPosition"])?
                .checked_add(1)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "rank refresh FinDec interpolation point overflowed",
                    )
                })
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let mut coefficients = Vec::with_capacity(interpolation_points.len());
    for (selected_index, selected_point) in interpolation_points.iter().enumerate() {
        if *selected_point == 0 || *selected_point >= modulus {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "rank refresh FinDec interpolation point is outside the data-prime field",
            ));
        }
        let mut coefficient = 1_u64;
        for (other_index, other_point) in interpolation_points.iter().enumerate() {
            if selected_index == other_index {
                continue;
            }
            if *other_point == 0 || *other_point >= modulus {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "rank refresh FinDec interpolation point is outside the data-prime field",
                ));
            }
            let denominator = sub_mod(*selected_point, *other_point, modulus)?;
            coefficient = mul_mod(coefficient, sub_mod(0, *other_point, modulus)?, modulus)?;
            coefficient = mul_mod(coefficient, inverse_mod(denominator, modulus)?, modulus)?;
        }
        coefficients.push(coefficient);
    }

    Ok(coefficients)
}

fn validate_refresh_share_records(transcript: &Value) -> CanonicalResult<()> {
    let records = array_at_path(transcript, &["rankRefreshShareRecords"])?;
    if records.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rank refresh transcript requires at least one share record",
        ));
    }
    let input_rank_ciphertext_root = hash_at_path(transcript, &["inputRankCiphertextRoot"])?;
    let evaluation_context_hash = hash_at_path(transcript, &["evaluationContextHash"])?;
    let smudging_bound_certificate_hash =
        hash_at_path(transcript, &["smudgingBoundCertificateHash"])?;
    let mut trustee_identities = BTreeSet::new();
    for record in records {
        require_string_at_path(
            record,
            &["objectType"],
            MASKED_RANK_REFRESH_SHARE_OBJECT_TYPE,
            "rank refresh share object type",
        )?;
        require_u64_at_path(record, &["objectVersion"], 1, "rank refresh share version")?;
        require_string_at_path(
            record,
            &["profileId"],
            MASKED_RANK_REFRESH_PROFILE_ID,
            "rank refresh share profile id",
        )?;
        let trustee_identity = string_at_path(record, &["trusteeIdentity"])?;
        if trustee_identity.trim().is_empty() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "rank refresh share trustee identity must not be empty",
            ));
        }
        if !trustee_identities.insert(trustee_identity.to_string()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "rank refresh transcript must not contain duplicate trustee share records",
            ));
        }
        u64_at_path(record, &["rosterPosition"])?;
        compare_required_hash(
            hash_at_path(record, &["inputRankCiphertextRoot"])?,
            input_rank_ciphertext_root,
            "rank refresh share input rank root",
        )?;
        compare_required_hash(
            hash_at_path(record, &["evaluationContextHash"])?,
            evaluation_context_hash,
            "rank refresh share evaluation context hash",
        )?;
        hash_at_path(record, &["participantSetupRecordHash"])?;
        hash_at_path(
            record,
            &["selectedAlgebraicShareVerificationKeyBindingRoot"],
        )?;
        hash_at_path(record, &["publicKeyShareCoefficientMaterialRoot"])?;
        hash_at_path(record, &["publicKeyShareCoefficientMaterialHash"])?;
        hash_at_path(record, &["trusteeThresholdVerificationKeyHash"])?;
        hash_at_path(record, &["thresholdShareVerificationKeyRoot"])?;
        hash_at_path(record, &["thresholdShareVerificationKeyHash"])?;
        hash_at_path(record, &["algebraicShareVerificationKeyHash"])?;
        hash_at_path(record, &["partialDecryptionShareRoot"])?;
        value_at_path(record, &["partialDecryptionSharePayload"])?;
        validate_partial_decryption_share_payload(transcript, record)?;
        hash_at_path(record, &["shareEquationProofRoot"])?;
        value_at_path(record, &["shareEquationProof"])?;
        hash_at_path(record, &["shareFreshnessHash"])?;
        compare_required_hash(
            hash_at_path(record, &["smudgingBoundCertificateHash"])?,
            smudging_bound_certificate_hash,
            "rank refresh share smudging-bound certificate hash",
        )?;
        require_string_at_path(
            record,
            &["shareProofStatus"],
            "AlgebraicPartDecShareEquationProofStatementBound",
            "rank refresh share proof status",
        )?;
        require_bool_at_path(
            record,
            &["rawShareMaterialExported"],
            false,
            "rank refresh raw share material export flag",
        )?;
    }

    Ok(())
}

fn validate_partial_decryption_share_payload(
    transcript: &Value,
    record: &Value,
) -> CanonicalResult<()> {
    let payload = value_at_path(record, &["partialDecryptionSharePayload"])?;
    compare_derived_hash(
        "MaskedRankRefreshPartialDecryptionShareRoot",
        payload,
        hash_at_path(record, &["partialDecryptionShareRoot"])?,
        "rank refresh partial-decryption share payload root",
    )?;
    require_string_at_path(
        payload,
        &["objectType"],
        PARTIAL_DECRYPTION_SHARE_PAYLOAD_OBJECT_TYPE,
        "rank refresh partial-decryption share payload object type",
    )?;
    require_u64_at_path(
        payload,
        &["objectVersion"],
        1,
        "rank refresh partial-decryption share payload version",
    )?;
    require_string_at_path(
        payload,
        &["profileId"],
        MASKED_RANK_REFRESH_PROFILE_ID,
        "rank refresh partial-decryption share payload profile id",
    )?;
    require_string_at_path(
        payload,
        &["payloadStatus"],
        "PublicMaskedPartialDecryptionSharePayloadBound",
        "rank refresh partial-decryption share payload status",
    )?;
    require_string_at_path(
        payload,
        &["sharePayloadKind"],
        "masked-partial-decryption-share-polynomial",
        "rank refresh partial-decryption share payload kind",
    )?;
    require_string_at_path(
        payload,
        &["partDecShareEquation"],
        "partialDecryptionShare = ciphertextComponentOne * trusteeSecretShare + smudgingNoise mod q",
        "rank refresh partial-decryption share payload equation",
    )?;
    require_string_at_path(
        payload,
        &["basisId"],
        "data",
        "rank refresh partial-decryption share payload basis",
    )?;
    require_string_at_path(
        payload,
        &["coefficientDomain"],
        "coefficient",
        "rank refresh partial-decryption share payload coefficient domain",
    )?;
    require_string_at_path(
        payload,
        &["coefficientEncoding"],
        "little-endian-u64-coefficient-vectors-by-data-prime",
        "rank refresh partial-decryption share payload coefficient encoding",
    )?;
    require_u64_at_path(
        payload,
        &["componentCount"],
        1,
        "rank refresh partial-decryption share payload component count",
    )?;
    require_u64_at_path(
        payload,
        &["polynomialDegree"],
        POLYNOMIAL_DEGREE as u64,
        "rank refresh partial-decryption share payload polynomial degree",
    )?;
    require_u64_at_path(
        payload,
        &["dataPrimeCount"],
        DATA_PRIMES.len() as u64,
        "rank refresh partial-decryption share payload data-prime count",
    )?;
    require_u64_at_path(
        payload,
        &["plaintextModulus"],
        PLAINTEXT_MODULUS,
        "rank refresh partial-decryption share payload plaintext modulus",
    )?;
    require_bool_at_path(
        payload,
        &["partialDecryptionShareIsMasked"],
        true,
        "rank refresh partial-decryption share masked flag",
    )?;
    require_bool_at_path(
        payload,
        &["semanticRankOpeningAllowed"],
        false,
        "rank refresh partial-decryption share semantic opening flag",
    )?;
    require_bool_at_path(
        payload,
        &["plaintextRankExported"],
        false,
        "rank refresh partial-decryption share plaintext rank export flag",
    )?;
    require_bool_at_path(
        payload,
        &["rawSecretShareExported"],
        false,
        "rank refresh partial-decryption share secret export flag",
    )?;
    require_bool_at_path(
        payload,
        &["smudgingNoiseExported"],
        false,
        "rank refresh partial-decryption share smudging-noise export flag",
    )?;
    compare_required_hash(
        hash_at_path(payload, &["setupPackageHash"])?,
        hash_at_path(transcript, &["setupPackageHash"])?,
        "rank refresh partial-decryption share setup package hash",
    )?;
    compare_required_hash(
        hash_at_path(payload, &["evaluationContextHash"])?,
        hash_at_path(transcript, &["evaluationContextHash"])?,
        "rank refresh partial-decryption share evaluation context hash",
    )?;
    compare_required_hash(
        hash_at_path(payload, &["inputRankCiphertextRoot"])?,
        hash_at_path(transcript, &["inputRankCiphertextRoot"])?,
        "rank refresh partial-decryption share input rank root",
    )?;
    compare_required_hash(
        hash_at_path(payload, &["inputRankCiphertextComponentOnePayloadHash"])?,
        hash_at_path(transcript, &["inputRankCiphertextComponentOnePayloadHash"])?,
        "rank refresh partial-decryption share input rank component-one payload hash",
    )?;
    compare_required_hash(
        hash_at_path(payload, &["smudgingBoundCertificateHash"])?,
        hash_at_path(transcript, &["smudgingBoundCertificateHash"])?,
        "rank refresh partial-decryption share smudging-bound certificate hash",
    )?;
    compare_required_hash(
        hash_at_path(payload, &["participantSetupRecordHash"])?,
        hash_at_path(record, &["participantSetupRecordHash"])?,
        "rank refresh partial-decryption share participant setup hash",
    )?;
    compare_required_hash(
        hash_at_path(payload, &["publicKeyShareCoefficientMaterialRoot"])?,
        hash_at_path(record, &["publicKeyShareCoefficientMaterialRoot"])?,
        "rank refresh partial-decryption share public key-share coefficient material root",
    )?;
    compare_required_hash(
        hash_at_path(payload, &["publicKeyShareCoefficientMaterialHash"])?,
        hash_at_path(record, &["publicKeyShareCoefficientMaterialHash"])?,
        "rank refresh partial-decryption share public key-share coefficient material hash",
    )?;
    compare_required_hash(
        hash_at_path(payload, &["trusteeThresholdVerificationKeyHash"])?,
        hash_at_path(record, &["trusteeThresholdVerificationKeyHash"])?,
        "rank refresh partial-decryption share trustee verification-key hash",
    )?;
    compare_required_hash(
        hash_at_path(payload, &["shareFreshnessHash"])?,
        hash_at_path(record, &["shareFreshnessHash"])?,
        "rank refresh partial-decryption share freshness hash",
    )?;
    compare_string_value(
        string_at_path(payload, &["trusteeIdentity"])?,
        string_at_path(record, &["trusteeIdentity"])?,
        "rank refresh partial-decryption share trustee identity",
    )?;
    if u64_at_path(payload, &["rosterPosition"])? != u64_at_path(record, &["rosterPosition"])? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "rank refresh partial-decryption share roster position does not match share record",
        ));
    }

    validate_partial_decryption_share_coefficient_tables(payload)
}

fn validate_partial_decryption_share_coefficient_tables(payload: &Value) -> CanonicalResult<()> {
    let coefficient_tables = array_at_path(payload, &["coefficientTables"])?;
    if coefficient_tables.len() != DATA_PRIMES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rank refresh partial-decryption share payload must include one coefficient table per data prime",
        ));
    }
    for (modulus_index, table) in coefficient_tables.iter().enumerate() {
        require_u64_at_path(
            table,
            &["modulusIndex"],
            modulus_index as u64,
            "rank refresh partial-decryption share modulus index",
        )?;
        let modulus = DATA_PRIMES[modulus_index];
        require_u64_at_path(
            table,
            &["modulus"],
            modulus,
            "rank refresh partial-decryption share modulus",
        )?;
        require_u64_at_path(
            table,
            &["coefficientByteLength"],
            (POLYNOMIAL_DEGREE * 8) as u64,
            "rank refresh partial-decryption share coefficient byte length",
        )?;
        require_string_at_path(
            table,
            &["coefficientEncoding"],
            "little-endian-u64",
            "rank refresh partial-decryption share coefficient table encoding",
        )?;
        let coefficients = coefficient_vector_from_le_hex(
            string_at_path(table, &["shareCoefficientsLeHex"])?,
            "rank refresh partial-decryption share coefficient vector",
        )?;
        if coefficients
            .iter()
            .any(|coefficient| *coefficient >= modulus)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "rank refresh partial-decryption share coefficient is outside its modulus",
            ));
        }
        compare_required_hash(
            string_at_path(table, &["shareCoefficientHash512"])?,
            &hash512_hex(
                "sealed-lattice-bgv-rns/masked-rank-refresh-partial-decryption-share-coefficient-vector-v1",
                &[&coefficient_vector_bytes(&coefficients)],
            ),
            "rank refresh partial-decryption share coefficient hash",
        )?;
    }

    Ok(())
}

fn validate_mask_re_encryption_proof_records(transcript: &Value) -> CanonicalResult<()> {
    let records = array_at_path(transcript, &["maskReEncryptionProofRecords"])?;
    if records.len() != 1 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rank refresh transcript requires exactly one mask re-encryption proof record",
        ));
    }
    let setup_package_hash = hash_at_path(transcript, &["setupPackageHash"])?;
    let collective_public_key_root = hash_at_path(transcript, &["collectivePublicKeyRoot"])?;
    let bgv_public_key_root = hash_at_path(transcript, &["bgvPublicKeyRoot"])?;
    let target_layout_hash = hash_at_path(transcript, &["targetLayoutHash"])?;
    let masked_opening_root = hash_at_path(transcript, &["maskedOpeningRoot"])?;
    let masked_opening_payload_root = hash_at_path(transcript, &["maskedOpeningPayloadRoot"])?;
    let smudging_bound_certificate_hash =
        hash_at_path(transcript, &["smudgingBoundCertificateHash"])?;
    let share_selection_rule_hash = hash_at_path(transcript, &["shareSelectionRuleHash"])?;
    let mask_commitment_root = hash_at_path(transcript, &["maskCommitmentRoot"])?;
    let mask_encryption_randomness_evidence_hash =
        hash_at_path(transcript, &["maskEncryptionRandomnessEvidenceHash"])?;
    let encrypted_mask_ciphertext_root =
        hash_at_path(transcript, &["encryptedMaskCiphertextRoot"])?;
    let encrypted_mask_ciphertext_payload_hash =
        hash_at_path(transcript, &["encryptedMaskCiphertextPayloadHash"])?;
    let refreshed_rank_ciphertext_root =
        hash_at_path(transcript, &["refreshedRankCiphertextRoot"])?;
    let refreshed_rank_ciphertext_payload_hash =
        hash_at_path(transcript, &["refreshedRankCiphertextPayloadHash"])?;
    let input_rank_ciphertext_root = hash_at_path(transcript, &["inputRankCiphertextRoot"])?;
    let evaluation_context_hash = hash_at_path(transcript, &["evaluationContextHash"])?;
    for record in records {
        require_string_at_path(
            record,
            &["objectType"],
            MASK_RE_ENCRYPTION_PROOF_RECORD_OBJECT_TYPE,
            "rank refresh mask re-encryption proof object type",
        )?;
        require_u64_at_path(
            record,
            &["objectVersion"],
            1,
            "rank refresh mask re-encryption proof version",
        )?;
        require_string_at_path(
            record,
            &["profileId"],
            MASKED_RANK_REFRESH_PROFILE_ID,
            "rank refresh mask re-encryption proof profile id",
        )?;
        require_string_at_path(
            record,
            &["proofRecordStatus"],
            "MaskReEncryptionProofStatementBound",
            "rank refresh mask re-encryption proof record status",
        )?;
        require_bool_at_path(
            record,
            &["proofBytesVerified"],
            false,
            "rank refresh mask re-encryption proof-byte flag",
        )?;
        require_bool_at_path(
            record,
            &["rawWitnessExported"],
            false,
            "rank refresh mask re-encryption raw witness export flag",
        )?;
        require_bool_at_path(
            record,
            &["maskPlaintextExported"],
            false,
            "rank refresh mask plaintext export flag",
        )?;
        compare_required_hash(
            hash_at_path(record, &["encryptedMaskCiphertextPayloadHash"])?,
            encrypted_mask_ciphertext_payload_hash,
            "rank refresh mask re-encryption record encrypted mask ciphertext payload hash",
        )?;
        compare_required_hash(
            hash_at_path(record, &["refreshedRankCiphertextPayloadHash"])?,
            refreshed_rank_ciphertext_payload_hash,
            "rank refresh mask re-encryption record refreshed rank ciphertext payload hash",
        )?;
        compare_required_hash(
            hash_at_path(record, &["maskCommitmentRoot"])?,
            mask_commitment_root,
            "rank refresh mask re-encryption record mask commitment root",
        )?;
        compare_required_hash(
            hash_at_path(record, &["maskEncryptionRandomnessEvidenceHash"])?,
            mask_encryption_randomness_evidence_hash,
            "rank refresh mask re-encryption record mask encryption randomness evidence hash",
        )?;
        let statement = value_at_path(record, &["maskReEncryptionProofStatement"])?;
        compare_derived_hash(
            "MaskedRankRefreshMaskReEncryptionProofRoot",
            statement,
            hash_at_path(record, &["maskReEncryptionProofRoot"])?,
            "rank refresh mask re-encryption proof root",
        )?;
        require_string_at_path(
            statement,
            &["objectType"],
            MASK_RE_ENCRYPTION_PROOF_STATEMENT_OBJECT_TYPE,
            "rank refresh mask re-encryption proof statement object type",
        )?;
        require_u64_at_path(
            statement,
            &["objectVersion"],
            1,
            "rank refresh mask re-encryption proof statement version",
        )?;
        require_string_at_path(
            statement,
            &["profileId"],
            MASKED_RANK_REFRESH_PROFILE_ID,
            "rank refresh mask re-encryption proof statement profile id",
        )?;
        require_string_at_path(
            statement,
            &["proofStatementFormat"],
            "masked-rank-refresh-mask-re-encryption-v1",
            "rank refresh mask re-encryption proof statement format",
        )?;
        require_string_at_path(
            statement,
            &["proofVerificationStatus"],
            "MaskReEncryptionVerifierPending",
            "rank refresh mask re-encryption proof verification status",
        )?;
        require_bool_at_path(
            statement,
            &["proofBytesVerified"],
            false,
            "rank refresh mask re-encryption statement proof-byte flag",
        )?;
        validate_proof_bytes_binding(
            statement,
            &ProofBytesBinding {
                proof_bytes_hex_field: "proofBytesHex",
                proof_size_bytes_field: "proofSizeBytes",
                proof_bytes_hash_field: "proofBytesHash",
                proof_statement_hash_field: "proofStatementHash",
                statement_hash_namespace: "MaskedRankRefreshMaskReEncryptionProofStatementHash",
                statement_metadata_fields: &MASK_RE_ENCRYPTION_PROOF_METADATA_FIELDS,
                label: "rank refresh mask re-encryption",
            },
        )?;
        require_bool_at_path(
            statement,
            &["rawWitnessExported"],
            false,
            "rank refresh mask re-encryption statement raw witness export flag",
        )?;
        require_bool_at_path(
            statement,
            &["maskPlaintextExported"],
            false,
            "rank refresh mask re-encryption statement mask plaintext export flag",
        )?;
        require_bool_at_path(
            statement,
            &["semanticRankOpeningAllowed"],
            false,
            "rank refresh mask re-encryption semantic rank opening flag",
        )?;
        require_string_at_path(
            statement,
            &["maskCiphertextRelation"],
            "encryptedMaskCiphertextRoot encrypts the committed mask under the setup collective public key",
            "rank refresh mask ciphertext relation",
        )?;
        require_string_at_path(
            statement,
            &["refreshedCiphertextRelation"],
            "refreshedRankCiphertextRoot re-encrypts maskedOpeningPayloadRoot minus encryptedMaskCiphertextRoot",
            "rank refresh refreshed ciphertext relation",
        )?;
        compare_required_hash(
            hash_at_path(statement, &["setupPackageHash"])?,
            setup_package_hash,
            "rank refresh mask re-encryption setup package hash",
        )?;
        compare_required_hash(
            hash_at_path(statement, &["collectivePublicKeyRoot"])?,
            collective_public_key_root,
            "rank refresh mask re-encryption collective public key root",
        )?;
        compare_required_hash(
            hash_at_path(statement, &["bgvPublicKeyRoot"])?,
            bgv_public_key_root,
            "rank refresh mask re-encryption BGV public key root",
        )?;
        compare_required_hash(
            hash_at_path(statement, &["targetLayoutHash"])?,
            target_layout_hash,
            "rank refresh mask re-encryption target layout hash",
        )?;
        compare_required_hash(
            hash_at_path(statement, &["evaluationContextHash"])?,
            evaluation_context_hash,
            "rank refresh mask re-encryption evaluation context hash",
        )?;
        compare_required_hash(
            hash_at_path(statement, &["inputRankCiphertextRoot"])?,
            input_rank_ciphertext_root,
            "rank refresh mask re-encryption input rank root",
        )?;
        compare_required_hash(
            hash_at_path(statement, &["maskedOpeningRoot"])?,
            masked_opening_root,
            "rank refresh mask re-encryption masked-opening root",
        )?;
        compare_required_hash(
            hash_at_path(statement, &["maskedOpeningPayloadRoot"])?,
            masked_opening_payload_root,
            "rank refresh mask re-encryption masked-opening payload root",
        )?;
        compare_required_hash(
            hash_at_path(statement, &["smudgingBoundCertificateHash"])?,
            smudging_bound_certificate_hash,
            "rank refresh mask re-encryption smudging-bound certificate hash",
        )?;
        compare_required_hash(
            hash_at_path(statement, &["shareSelectionRuleHash"])?,
            share_selection_rule_hash,
            "rank refresh mask re-encryption share-selection rule hash",
        )?;
        compare_required_hash(
            hash_at_path(statement, &["encryptedMaskCiphertextRoot"])?,
            encrypted_mask_ciphertext_root,
            "rank refresh mask re-encryption encrypted mask root",
        )?;
        compare_required_hash(
            hash_at_path(statement, &["encryptedMaskCiphertextPayloadHash"])?,
            encrypted_mask_ciphertext_payload_hash,
            "rank refresh mask re-encryption encrypted mask ciphertext payload hash",
        )?;
        compare_required_hash(
            hash_at_path(statement, &["refreshedRankCiphertextRoot"])?,
            refreshed_rank_ciphertext_root,
            "rank refresh mask re-encryption refreshed rank root",
        )?;
        compare_required_hash(
            hash_at_path(statement, &["refreshedRankCiphertextPayloadHash"])?,
            refreshed_rank_ciphertext_payload_hash,
            "rank refresh mask re-encryption refreshed rank ciphertext payload hash",
        )?;
        compare_required_hash(
            hash_at_path(statement, &["maskCommitmentRoot"])?,
            mask_commitment_root,
            "rank refresh mask re-encryption mask commitment root",
        )?;
        compare_required_hash(
            hash_at_path(statement, &["maskEncryptionRandomnessEvidenceHash"])?,
            mask_encryption_randomness_evidence_hash,
            "rank refresh mask re-encryption mask encryption randomness evidence hash",
        )?;
        let challenge_domain_hash =
            mask_re_encryption_proof_statement_challenge_domain_hash(statement)?;
        compare_required_hash(
            hash_at_path(statement, &["challengeDomainHash"])?,
            &challenge_domain_hash,
            "rank refresh mask re-encryption challenge-domain hash",
        )?;
        require_string_at_path(
            statement,
            &["publicRandomnessSource"],
            "challenge-domain-hash-prefix-32-bytes",
            "rank refresh mask re-encryption public randomness source",
        )?;
        let expected_public_randomness_hex = challenge_domain_hash.get(..64).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "rank refresh mask re-encryption challenge-domain hash is too short",
            )
        })?;
        compare_required_hash(
            string_at_path(statement, &["publicRandomnessHex"])?,
            expected_public_randomness_hex,
            "rank refresh mask re-encryption public randomness",
        )?;
        compare_required_hash(
            hash_at_path(statement, &["canonicalCiphertextConventionHash"])?,
            &canonical_ciphertext_convention_hash()?,
            "rank refresh mask re-encryption ciphertext convention hash",
        )?;
        require_u64_at_path(
            statement,
            &["polynomialDegree"],
            POLYNOMIAL_DEGREE as u64,
            "rank refresh mask re-encryption polynomial degree",
        )?;
        require_u64_at_path(
            statement,
            &["dataPrimeCount"],
            DATA_PRIMES.len() as u64,
            "rank refresh mask re-encryption data prime count",
        )?;
        require_u64_at_path(
            statement,
            &["plaintextModulus"],
            PLAINTEXT_MODULUS,
            "rank refresh mask re-encryption plaintext modulus",
        )?;
    }

    Ok(())
}

fn validate_rank_refresh_transcript_root(transcript: &Value) -> CanonicalResult<()> {
    let transcript_root = hash_at_path(transcript, &["rankRefreshTranscriptRoot"])?;
    let mut transcript_without_root = transcript.clone();
    transcript_without_root
        .as_object_mut()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "rankRefreshTranscript must be a JSON object",
            )
        })?
        .remove("rankRefreshTranscriptRoot");
    let expected_root =
        derive_protocol_hash("MaskedRankRefreshTranscriptRoot", &transcript_without_root)?;
    compare_required_hash(
        transcript_root,
        &expected_root,
        "rank refresh transcript root",
    )
}

fn compare_hash_at_request_field(
    request: &Value,
    transcript: &Value,
    request_field_name: &str,
    transcript_path: &[&str],
    label: &str,
) -> CanonicalResult<()> {
    if request.get(request_field_name).is_none() {
        return Ok(());
    }
    let expected = hash_at_path(request, &[request_field_name])?;
    let actual = hash_at_path(transcript, transcript_path)?;

    compare_required_hash(actual, expected, label)
}

fn compare_required_hash(actual: &str, expected: &str, label: &str) -> CanonicalResult<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("{label} does not match"),
        ))
    }
}

fn compare_derived_hash(
    namespace: &str,
    value: &Value,
    actual: &str,
    label: &str,
) -> CanonicalResult<()> {
    let expected = derive_protocol_hash(namespace, value)?;
    compare_required_hash(actual, &expected, label)
}

fn validate_proof_bytes_binding(
    value: &Value,
    binding: &ProofBytesBinding<'_>,
) -> CanonicalResult<()> {
    let proof_bytes_hex = string_at_path(value, &[binding.proof_bytes_hex_field])?;
    let proof_bytes = decode_hex(proof_bytes_hex).map_err(|error| {
        CanonicalError::new(
            error.code,
            format!(
                "{} proof bytes must use canonical lowercase hexadecimal encoding: {}",
                binding.label, error.message
            ),
        )
    })?;
    if proof_bytes.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{} proof bytes must not be empty", binding.label),
        ));
    }
    let proof_size_bytes = u64_at_path(value, &[binding.proof_size_bytes_field])?;
    if proof_size_bytes != u64::try_from(proof_bytes.len()).expect("proof byte length fits u64") {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!(
                "{} proof byte size does not match proof bytes",
                binding.label
            ),
        ));
    }
    let expected_proof_bytes_hash =
        derive_protocol_hash_for_proof_bytes_payload(proof_bytes_hex, proof_size_bytes)?;
    compare_required_hash(
        hash_at_path(value, &[binding.proof_bytes_hash_field])?,
        &expected_proof_bytes_hash,
        &format!("{} proof bytes hash", binding.label),
    )?;

    let public_statement =
        public_statement_without_proof_metadata(value, binding.statement_metadata_fields)?;
    let expected_statement_hash =
        derive_protocol_hash(binding.statement_hash_namespace, &public_statement)?;
    compare_required_hash(
        hash_at_path(value, &[binding.proof_statement_hash_field])?,
        &expected_statement_hash,
        &format!("{} public statement hash", binding.label),
    )
}

fn public_statement_without_proof_metadata(
    value: &Value,
    metadata_fields: &[&str],
) -> CanonicalResult<Value> {
    let mut statement = value.clone();
    let statement_object = statement.as_object_mut().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "rank refresh proof statement must be a JSON object",
        )
    })?;
    for metadata_field in metadata_fields {
        statement_object.remove(*metadata_field);
    }

    Ok(statement)
}

fn compare_string_value(actual: &str, expected: &str, label: &str) -> CanonicalResult<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("{label} does not match"),
        ))
    }
}

fn compare_json_value(actual: &Value, expected: &Value, label: &str) -> CanonicalResult<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("{label} does not match"),
        ))
    }
}

fn compare_array_to_share_records(
    value: &Value,
    value_path: &[&str],
    share_records: &[Value],
    share_record_path: &[&str],
    label: &str,
) -> CanonicalResult<()> {
    let values = array_at_path(value, value_path)?;
    if values.len() != share_records.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{label} length does not match share records"),
        ));
    }
    for (record_index, (actual, share_record)) in
        values.iter().zip(share_records.iter()).enumerate()
    {
        let expected = value_at_path(share_record, share_record_path)?;
        if actual != expected {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!("{label} entry {record_index} does not match share records"),
            ));
        }
    }

    Ok(())
}

fn require_string_at_path(
    value: &Value,
    path: &[&str],
    expected: &str,
    label: &str,
) -> CanonicalResult<()> {
    let actual = string_at_path(value, path)?;
    if actual == expected {
        Ok(())
    } else {
        Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("{label} does not match"),
        ))
    }
}

fn require_bool_at_path(
    value: &Value,
    path: &[&str],
    expected: bool,
    label: &str,
) -> CanonicalResult<()> {
    let actual = bool_at_path(value, path)?;
    if actual == expected {
        Ok(())
    } else {
        Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("{label} does not match"),
        ))
    }
}

fn require_u64_at_path(
    value: &Value,
    path: &[&str],
    expected: u64,
    label: &str,
) -> CanonicalResult<()> {
    let actual = u64_at_path(value, path)?;
    if actual == expected {
        Ok(())
    } else {
        Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("{label} does not match"),
        ))
    }
}

fn require_decimal_string_at_path(
    value: &Value,
    path: &[&str],
    expected: &str,
    label: &str,
) -> CanonicalResult<()> {
    let actual = string_at_path(value, path)?;
    validate_unsigned_decimal_string(actual, label)?;
    if actual == expected {
        Ok(())
    } else {
        Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("{label} does not match"),
        ))
    }
}

fn u64_at_path(value: &Value, path: &[&str]) -> CanonicalResult<u64> {
    value_at_path(value, path)?.as_u64().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{} must be a non-negative integer", path.join(".")),
        )
    })
}

fn validate_unsigned_decimal_string(value: &str, label: &str) -> CanonicalResult<()> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{label} must be a canonical unsigned decimal string"),
        ));
    }

    Ok(())
}

fn part_dec_witness_bound_from_smudging_certificate(
    certificate: &Value,
) -> CanonicalResult<PartDecWitnessBound> {
    let smudging_noise_coefficient_bound_bits =
        u64_at_path(certificate, &["partialDecryptionShareNoiseBoundBits"])?;
    let data_modulus_bits = u64::try_from(data_basis_modulus_bits()).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rank refresh PartDec witness bound data modulus bit count does not fit u64",
        )
    })?;
    if smudging_noise_coefficient_bound_bits > data_modulus_bits {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rank refresh PartDec witness smudging-noise coefficient bound exceeds the data modulus bit budget",
        ));
    }
    let squared_smudging_bound_exponent = smudging_noise_coefficient_bound_bits
        .checked_mul(2)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "rank refresh PartDec witness smudging-noise squared bit budget overflowed",
            )
        })?;
    let coefficient_bound_square_sum = PART_DEC_SECRET_SHARE_COEFFICIENT_BOUND
        .checked_mul(PART_DEC_SECRET_SHARE_COEFFICIENT_BOUND)
        .and_then(|secret_square| {
            PART_DEC_ERROR_SHARE_COEFFICIENT_BOUND
                .checked_mul(PART_DEC_ERROR_SHARE_COEFFICIENT_BOUND)
                .and_then(|error_square| secret_square.checked_add(error_square))
        })
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "rank refresh PartDec witness setup-distribution bound overflowed",
            )
        })?;
    let smudging_noise_coefficient_bound_decimal =
        decimal_power_of_two(smudging_noise_coefficient_bound_bits)?;
    let mut witness_l2_bound_digits = decimal_power_of_two_digits(squared_smudging_bound_exponent)?;
    decimal_digits_add_small(&mut witness_l2_bound_digits, coefficient_bound_square_sum);
    let polynomial_degree_multiplier = u32::try_from(POLYNOMIAL_DEGREE).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rank refresh PartDec witness polynomial degree does not fit decimal multiplier",
        )
    })?;
    decimal_digits_multiply_small(&mut witness_l2_bound_digits, polynomial_degree_multiplier);
    let witness_l2_bound_squared_bit_length = decimal_digits_bit_length(&witness_l2_bound_digits);

    Ok(PartDecWitnessBound {
        secret_share_coefficient_bound: PART_DEC_SECRET_SHARE_COEFFICIENT_BOUND,
        error_share_coefficient_bound: PART_DEC_ERROR_SHARE_COEFFICIENT_BOUND,
        smudging_noise_coefficient_bound_bits,
        smudging_noise_coefficient_bound_decimal,
        witness_l2_bound_squared_decimal: decimal_digits_to_string(&witness_l2_bound_digits),
        witness_l2_bound_squared_bit_length,
        witness_l2_bound_squared_fits_current_backend: witness_l2_bound_squared_bit_length
            <= PART_DEC_LINEAR_PROOF_BACKEND_WITNESS_BOUND_CAPACITY_BITS,
    })
}

fn part_dec_masked_share_witness_bound_from_smudging_certificate(
    certificate: &Value,
) -> CanonicalResult<PartDecMaskedShareWitnessBound> {
    let smudging_noise_coefficient_bound_bits =
        u64_at_path(certificate, &["partialDecryptionShareNoiseBoundBits"])?;
    let data_modulus_bits = u64::try_from(data_basis_modulus_bits()).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rank refresh PartDec masked-share witness bound data modulus bit count does not fit u64",
        )
    })?;
    if smudging_noise_coefficient_bound_bits > data_modulus_bits {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rank refresh PartDec masked-share witness smudging-noise coefficient bound exceeds the data modulus bit budget",
        ));
    }
    let squared_smudging_bound_exponent = smudging_noise_coefficient_bound_bits
        .checked_mul(2)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "rank refresh PartDec masked-share smudging-noise squared bit budget overflowed",
            )
        })?;
    let smudging_noise_coefficient_bound_decimal =
        decimal_power_of_two(smudging_noise_coefficient_bound_bits)?;
    let mut witness_l2_bound_digits = decimal_power_of_two_digits(squared_smudging_bound_exponent)?;
    decimal_digits_add_small(
        &mut witness_l2_bound_digits,
        PART_DEC_SECRET_SHARE_COEFFICIENT_BOUND * PART_DEC_SECRET_SHARE_COEFFICIENT_BOUND,
    );
    let polynomial_degree_multiplier = u32::try_from(POLYNOMIAL_DEGREE).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rank refresh PartDec masked-share witness polynomial degree does not fit decimal multiplier",
        )
    })?;
    decimal_digits_multiply_small(&mut witness_l2_bound_digits, polynomial_degree_multiplier);
    let witness_l2_bound_squared_bit_length = decimal_digits_bit_length(&witness_l2_bound_digits);

    Ok(PartDecMaskedShareWitnessBound {
        secret_share_coefficient_bound: PART_DEC_SECRET_SHARE_COEFFICIENT_BOUND,
        smudging_noise_coefficient_bound_bits,
        smudging_noise_coefficient_bound_decimal,
        witness_l2_bound_squared_decimal: decimal_digits_to_string(&witness_l2_bound_digits),
        witness_l2_bound_squared_bit_length,
        witness_l2_bound_squared_fits_current_backend: witness_l2_bound_squared_bit_length
            <= PART_DEC_LINEAR_PROOF_BACKEND_WITNESS_BOUND_CAPACITY_BITS,
    })
}

fn decimal_power_of_two(exponent: u64) -> CanonicalResult<String> {
    let digits = decimal_power_of_two_digits(exponent)?;

    Ok(decimal_digits_to_string(&digits))
}

fn decimal_power_of_two_digits(exponent: u64) -> CanonicalResult<Vec<u8>> {
    let exponent = usize::try_from(exponent).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rank refresh PartDec witness decimal exponent does not fit usize",
        )
    })?;
    let mut digits = vec![1_u8];
    for _ in 0..exponent {
        decimal_digits_multiply_small(&mut digits, 2);
    }

    Ok(digits)
}

fn decimal_digits_add_small(digits: &mut Vec<u8>, addend: u64) {
    let mut carry = addend;
    let mut digit_index = 0;
    while carry > 0 {
        if digit_index == digits.len() {
            digits.push(0);
        }
        let sum = u64::from(digits[digit_index]) + carry;
        digits[digit_index] = (sum % 10) as u8;
        carry = sum / 10;
        digit_index += 1;
    }
}

fn decimal_digits_multiply_small(digits: &mut Vec<u8>, multiplier: u32) {
    let mut carry = 0_u64;
    for digit in digits.iter_mut() {
        let product = u64::from(*digit) * u64::from(multiplier) + carry;
        *digit = (product % 10) as u8;
        carry = product / 10;
    }
    while carry > 0 {
        digits.push((carry % 10) as u8);
        carry /= 10;
    }
}

fn decimal_digits_to_string(digits: &[u8]) -> String {
    digits
        .iter()
        .rev()
        .map(|digit| char::from(b'0' + *digit))
        .collect()
}

fn decimal_digits_bit_length(digits: &[u8]) -> u64 {
    let mut value = digits.to_vec();
    let mut bit_length = 0_u64;
    while !decimal_digits_are_zero(&value) {
        decimal_digits_divide_by_two(&mut value);
        bit_length += 1;
    }

    bit_length
}

fn decimal_digits_are_zero(digits: &[u8]) -> bool {
    digits.iter().all(|digit| *digit == 0)
}

fn decimal_digits_divide_by_two(digits: &mut Vec<u8>) {
    let mut carry = 0_u8;
    for digit_index in (0..digits.len()).rev() {
        let value = carry * 10 + digits[digit_index];
        digits[digit_index] = value / 2;
        carry = value % 2;
    }
    while digits.len() > 1 && digits.last() == Some(&0) {
        digits.pop();
    }
}

fn coefficient_vector_from_le_hex(value: &str, label: &str) -> CanonicalResult<Vec<u64>> {
    let bytes = decode_hex(value)?;
    if bytes.len() != POLYNOMIAL_DEGREE * 8 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{label} byte length does not match the selected BGV profile"),
        ));
    }

    Ok(bytes
        .chunks_exact(8)
        .map(|chunk| {
            let mut coefficient_bytes = [0_u8; 8];
            coefficient_bytes.copy_from_slice(chunk);
            u64::from_le_bytes(coefficient_bytes)
        })
        .collect())
}

fn coefficient_vector_bytes(coefficients: &[u64]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(coefficients.len() * 8);
    for coefficient in coefficients {
        bytes.extend(coefficient.to_le_bytes());
    }

    bytes
}

fn setup_public_key_coefficient_hash(coefficients: &[u64]) -> String {
    hash512_hex(
        "sealed-lattice-bgv-rns/public-key-coefficient-vector-v1",
        &[&coefficient_vector_bytes(coefficients)],
    )
}

fn part_dec_linear_proof_coefficient_hash(coefficients: &[u64]) -> String {
    hash512_hex(
        "sealed-lattice-bgv-rns/masked-rank-refresh-partdec-linear-proof-coefficient-vector-v1",
        &[&coefficient_vector_bytes(coefficients)],
    )
}

fn scalar_polynomial_coefficients(scalar: u64, modulus: u64) -> Vec<u64> {
    let mut coefficients = vec![0_u64; POLYNOMIAL_DEGREE];
    coefficients[0] = scalar % modulus;
    coefficients
}

fn setup_public_common_random_coefficients_for_modulus(
    setup_package: &Value,
    modulus_index: usize,
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    let coefficient_material = value_at_path(
        setup_package,
        &["collectivePublicKey", "coefficientMaterial"],
    )?;
    let coefficient_tables = array_at_path(coefficient_material, &["coefficientTables"])?;
    let table = coefficient_tables.get(modulus_index).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rank refresh PartDec setup common-random coefficient table is missing",
        )
    })?;
    require_u64_at_path(
        table,
        &["modulus"],
        modulus,
        "rank refresh PartDec setup common-random coefficient modulus",
    )?;
    let coefficients = coefficient_vector_from_le_hex(
        string_at_path(table, &["componentOneCoefficientsLeHex"])?,
        "rank refresh PartDec setup common-random coefficients",
    )?;
    compare_required_hash(
        string_at_path(table, &["componentOneCoefficientHash512"])?,
        &setup_public_key_coefficient_hash(&coefficients),
        "rank refresh PartDec setup common-random coefficient hash",
    )?;

    Ok(coefficients)
}

fn part_dec_source_matrix_hash(
    modulus: u64,
    public_common_random_coefficients: &[u64],
    negative_plaintext_modulus_coefficients: &[u64],
    zero_polynomial_coefficients: &[u64],
    input_rank_component_one_coefficients: &[u64],
    one_scalar_coefficients: &[u64],
) -> String {
    let modulus_bytes = modulus.to_le_bytes();
    let public_common_random_bytes = coefficient_vector_bytes(public_common_random_coefficients);
    let negative_plaintext_modulus_bytes =
        coefficient_vector_bytes(negative_plaintext_modulus_coefficients);
    let zero_polynomial_bytes = coefficient_vector_bytes(zero_polynomial_coefficients);
    let input_rank_component_one_bytes =
        coefficient_vector_bytes(input_rank_component_one_coefficients);
    let one_scalar_bytes = coefficient_vector_bytes(one_scalar_coefficients);
    hash512_hex(
        "sealed-lattice-bgv-rns/masked-rank-refresh-partdec-linear-proof-source-matrix-v1",
        &[
            &modulus_bytes,
            &public_common_random_bytes,
            &negative_plaintext_modulus_bytes,
            &zero_polynomial_bytes,
            &input_rank_component_one_bytes,
            &zero_polynomial_bytes,
            &one_scalar_bytes,
        ],
    )
}

fn part_dec_target_vector_hash(
    modulus: u64,
    public_key_share_component_zero_coefficients: &[u64],
    negative_partial_decryption_share_coefficients: &[u64],
) -> String {
    let modulus_bytes = modulus.to_le_bytes();
    let public_key_share_component_zero_bytes =
        coefficient_vector_bytes(public_key_share_component_zero_coefficients);
    let negative_partial_decryption_share_bytes =
        coefficient_vector_bytes(negative_partial_decryption_share_coefficients);
    hash512_hex(
        "sealed-lattice-bgv-rns/masked-rank-refresh-partdec-linear-proof-target-vector-v1",
        &[
            &modulus_bytes,
            &public_key_share_component_zero_bytes,
            &negative_partial_decryption_share_bytes,
        ],
    )
}

fn part_dec_public_key_share_consistency_source_matrix_hash(
    modulus: u64,
    public_common_random_coefficients: &[u64],
    negative_plaintext_modulus_coefficients: &[u64],
) -> String {
    let modulus_bytes = modulus.to_le_bytes();
    let public_common_random_bytes = coefficient_vector_bytes(public_common_random_coefficients);
    let negative_plaintext_modulus_bytes =
        coefficient_vector_bytes(negative_plaintext_modulus_coefficients);
    hash512_hex(
        "sealed-lattice-bgv-rns/masked-rank-refresh-partdec-public-key-share-consistency-linear-proof-source-matrix-v1",
        &[
            &modulus_bytes,
            &public_common_random_bytes,
            &negative_plaintext_modulus_bytes,
        ],
    )
}

fn part_dec_public_key_share_consistency_target_vector_hash(
    modulus: u64,
    public_key_share_component_zero_coefficients: &[u64],
) -> String {
    let modulus_bytes = modulus.to_le_bytes();
    let public_key_share_component_zero_bytes =
        coefficient_vector_bytes(public_key_share_component_zero_coefficients);
    hash512_hex(
        "sealed-lattice-bgv-rns/masked-rank-refresh-partdec-public-key-share-consistency-linear-proof-target-vector-v1",
        &[&modulus_bytes, &public_key_share_component_zero_bytes],
    )
}

fn part_dec_masked_share_source_matrix_hash(
    modulus: u64,
    input_rank_component_one_coefficients: &[u64],
    one_scalar_coefficients: &[u64],
) -> String {
    let modulus_bytes = modulus.to_le_bytes();
    let input_rank_component_one_bytes =
        coefficient_vector_bytes(input_rank_component_one_coefficients);
    let one_scalar_bytes = coefficient_vector_bytes(one_scalar_coefficients);
    hash512_hex(
        "sealed-lattice-bgv-rns/masked-rank-refresh-partdec-masked-share-linear-proof-source-matrix-v1",
        &[
            &modulus_bytes,
            &input_rank_component_one_bytes,
            &one_scalar_bytes,
        ],
    )
}

fn part_dec_masked_share_target_vector_hash(
    modulus: u64,
    negative_partial_decryption_share_coefficients: &[u64],
) -> String {
    let modulus_bytes = modulus.to_le_bytes();
    let negative_partial_decryption_share_bytes =
        coefficient_vector_bytes(negative_partial_decryption_share_coefficients);
    hash512_hex(
        "sealed-lattice-bgv-rns/masked-rank-refresh-partdec-masked-share-linear-proof-target-vector-v1",
        &[&modulus_bytes, &negative_partial_decryption_share_bytes],
    )
}

fn part_dec_linear_relation_statement_root(statement: &Value) -> CanonicalResult<String> {
    derive_protocol_hash(
        "MaskedRankRefreshPartDecLinearRelationStatementRoot",
        statement,
    )
}

fn part_dec_linear_proof_backend_adapter_root(adapter: &Value) -> CanonicalResult<String> {
    derive_protocol_hash(
        "MaskedRankRefreshPartDecLinearProofBackendAdapterRoot",
        adapter,
    )
}

fn part_dec_linear_proof_backend_input_challenge_domain_hash(
    proof: &Value,
    statement_root: &str,
    adapter_root: &str,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "ChallengeDomainHash",
        &json!({
            "purpose": "masked-rank-refresh-partdec-linear-proof-public-randomness-v1",
            "profileId": MASKED_RANK_REFRESH_PROFILE_ID,
            "proofBackend": "sealed-lattice-linear-proof",
            "proofInputFormat": "masked-rank-refresh-partdec-per-data-prime-linear-proof-input-v1",
            "setupPackageHash": hash_at_path(proof, &["setupPackageHash"])?,
            "evaluationContextHash": hash_at_path(proof, &["evaluationContextHash"])?,
            "inputRankCiphertextComponentOnePayloadHash": hash_at_path(
                proof,
                &["inputRankCiphertextComponentOnePayloadHash"],
            )?,
            "partialDecryptionShareRoot": hash_at_path(proof, &["partialDecryptionShareRoot"])?,
            "selectedAlgebraicShareVerificationKeyBindingRoot": hash_at_path(
                proof,
                &["selectedAlgebraicShareVerificationKeyBindingRoot"],
            )?,
            "smudgingBoundCertificateHash": hash_at_path(
                proof,
                &["smudgingBoundCertificateHash"],
            )?,
            "partDecLinearRelationStatementRoot": statement_root,
            "linearProofBackendAdapterRoot": adapter_root,
        }),
    )
}

fn part_dec_public_key_share_consistency_linear_proof_backend_input_root(
    backend_input: &Value,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "MaskedRankRefreshPartDecPublicKeyShareConsistencyLinearProofBackendInputRoot",
        backend_input,
    )
}

fn part_dec_public_key_share_consistency_linear_proof_backend_input_challenge_domain_hash(
    proof: &Value,
    statement_root: &str,
    adapter_root: &str,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "ChallengeDomainHash",
        &json!({
            "purpose": "masked-rank-refresh-partdec-public-key-share-consistency-linear-proof-public-randomness-v1",
            "profileId": MASKED_RANK_REFRESH_PROFILE_ID,
            "proofBackend": "sealed-lattice-linear-proof",
            "proofInputFormat": "masked-rank-refresh-partdec-public-key-share-consistency-per-data-prime-linear-proof-input-v1",
            "setupPackageHash": hash_at_path(proof, &["setupPackageHash"])?,
            "evaluationContextHash": hash_at_path(proof, &["evaluationContextHash"])?,
            "selectedAlgebraicShareVerificationKeyBindingRoot": hash_at_path(
                proof,
                &["selectedAlgebraicShareVerificationKeyBindingRoot"],
            )?,
            "publicKeyShareCoefficientMaterialRoot": hash_at_path(
                proof,
                &["publicKeyShareCoefficientMaterialRoot"],
            )?,
            "publicKeyShareCoefficientMaterialHash": hash_at_path(
                proof,
                &["publicKeyShareCoefficientMaterialHash"],
            )?,
            "partDecLinearRelationStatementRoot": statement_root,
            "linearProofBackendAdapterRoot": adapter_root,
        }),
    )
}

fn part_dec_masked_share_linear_proof_backend_input_root(
    backend_input: &Value,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "MaskedRankRefreshPartDecMaskedShareLinearProofBackendInputRoot",
        backend_input,
    )
}

fn part_dec_split_same_witness_binding_root(binding: &Value) -> CanonicalResult<String> {
    derive_protocol_hash(
        "MaskedRankRefreshPartDecSplitSameWitnessBindingRoot",
        binding,
    )
}

fn part_dec_masked_share_linear_proof_backend_input_challenge_domain_hash(
    proof: &Value,
    statement_root: &str,
    adapter_root: &str,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "ChallengeDomainHash",
        &json!({
            "purpose": "masked-rank-refresh-partdec-masked-share-linear-proof-public-randomness-v1",
            "profileId": MASKED_RANK_REFRESH_PROFILE_ID,
            "proofBackend": "sealed-lattice-linear-proof",
            "proofInputFormat": "masked-rank-refresh-partdec-masked-share-per-data-prime-linear-proof-input-v1",
            "setupPackageHash": hash_at_path(proof, &["setupPackageHash"])?,
            "evaluationContextHash": hash_at_path(proof, &["evaluationContextHash"])?,
            "inputRankCiphertextComponentOnePayloadHash": hash_at_path(
                proof,
                &["inputRankCiphertextComponentOnePayloadHash"],
            )?,
            "partialDecryptionShareRoot": hash_at_path(proof, &["partialDecryptionShareRoot"])?,
            "selectedAlgebraicShareVerificationKeyBindingRoot": hash_at_path(
                proof,
                &["selectedAlgebraicShareVerificationKeyBindingRoot"],
            )?,
            "smudgingBoundCertificateHash": hash_at_path(
                proof,
                &["smudgingBoundCertificateHash"],
            )?,
            "partDecLinearRelationStatementRoot": statement_root,
            "linearProofBackendAdapterRoot": adapter_root,
        }),
    )
}

fn mask_re_encryption_proof_statement_challenge_domain_hash(
    statement: &Value,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "ChallengeDomainHash",
        &json!({
            "purpose": "masked-rank-refresh-mask-re-encryption-proof-public-randomness-v1",
            "profileId": MASKED_RANK_REFRESH_PROFILE_ID,
            "proofSystem": "sealed-lattice-mask-re-encryption-proof",
            "proofStatementFormat": "masked-rank-refresh-mask-re-encryption-v1",
            "setupPackageHash": hash_at_path(statement, &["setupPackageHash"])?,
            "collectivePublicKeyRoot": hash_at_path(statement, &["collectivePublicKeyRoot"])?,
            "bgvPublicKeyRoot": hash_at_path(statement, &["bgvPublicKeyRoot"])?,
            "targetLayoutHash": hash_at_path(statement, &["targetLayoutHash"])?,
            "evaluationContextHash": hash_at_path(statement, &["evaluationContextHash"])?,
            "inputRankCiphertextRoot": hash_at_path(statement, &["inputRankCiphertextRoot"])?,
            "maskedOpeningRoot": hash_at_path(statement, &["maskedOpeningRoot"])?,
            "maskedOpeningPayloadRoot": hash_at_path(statement, &["maskedOpeningPayloadRoot"])?,
            "smudgingBoundCertificateHash": hash_at_path(statement, &["smudgingBoundCertificateHash"])?,
            "shareSelectionRuleHash": hash_at_path(statement, &["shareSelectionRuleHash"])?,
            "maskCommitmentRoot": hash_at_path(statement, &["maskCommitmentRoot"])?,
            "maskEncryptionRandomnessEvidenceHash": hash_at_path(
                statement,
                &["maskEncryptionRandomnessEvidenceHash"],
            )?,
            "encryptedMaskCiphertextRoot": hash_at_path(
                statement,
                &["encryptedMaskCiphertextRoot"],
            )?,
            "encryptedMaskCiphertextPayloadHash": hash_at_path(
                statement,
                &["encryptedMaskCiphertextPayloadHash"],
            )?,
            "refreshedRankCiphertextRoot": hash_at_path(
                statement,
                &["refreshedRankCiphertextRoot"],
            )?,
            "refreshedRankCiphertextPayloadHash": hash_at_path(
                statement,
                &["refreshedRankCiphertextPayloadHash"],
            )?,
            "canonicalCiphertextConventionHash": hash_at_path(
                statement,
                &["canonicalCiphertextConventionHash"],
            )?,
            "polynomialDegree": u64_at_path(statement, &["polynomialDegree"])?,
            "dataPrimeCount": u64_at_path(statement, &["dataPrimeCount"])?,
            "plaintextModulus": u64_at_path(statement, &["plaintextModulus"])?,
        }),
    )
}

fn reject_forbidden_rank_refresh_fields(value: &Value) -> CanonicalResult<()> {
    fn visit(value: &Value, path: &mut Vec<String>) -> CanonicalResult<()> {
        match value {
            Value::Object(object) => {
                for (field_name, child) in object {
                    if matches!(
                        field_name.as_str(),
                        "setupPrivateWitness"
                            | "privateSetupWitness"
                            | "privateSetupSeed"
                            | "privateSetupSeedHash"
                            | "developmentKeySet"
                            | "developmentSecretKey"
                            | "trustedDealerSecret"
                            | "fullSecretKey"
                            | "collectiveSecretKey"
                            | "secretKeyMaterial"
                            | "rawSecretShares"
                            | "secretShares"
                            | "thresholdSecretShares"
                            | "fullSecretReconstruction"
                            | "trusteeSecretShare"
                            | "smudgingNoise"
                            | "partDecWitness"
                            | "shareEquationWitness"
                            | "proofWitness"
                            | "lsssWitness"
                            | "maskPlaintext"
                            | "maskSlots"
                            | "decodedMask"
                            | "maskEncryptionWitness"
                            | "maskReEncryptionWitness"
                            | "reEncryptionWitness"
                            | "maskEncryptionRandomness"
                            | "reEncryptionRandomness"
                            | "partialDecryptionShare"
                            | "thresholdDecryptionShare"
                            | "targetDecryptionShare"
                            | "plaintextRank"
                            | "plaintextRanks"
                            | "rankSlots"
                            | "decodedRanks"
                            | "decodedPackedRanks"
                            | "maskedRankPlaintext"
                            | "maskedOpeningPlaintext"
                            | "finDecPlaintext"
                            | "openedRank"
                            | "openedRanks"
                            | "unmaskedRank"
                            | "comparisonTruthSlots"
                            | "targetPlaintext"
                            | "plaintextTarget"
                            | "targetSlots"
                            | "decodedTargetIdSlots"
                            | "decodedTargetOrderSlots"
                    ) {
                        let location = if path.is_empty() {
                            field_name.clone()
                        } else {
                            format!("{}.{}", path.join("."), field_name)
                        };
                        return Err(CanonicalError::new(
                            CanonicalErrorCode::InvalidFixture,
                            format!(
                                "masked rank refresh transcript rejects forbidden field {location}"
                            ),
                        ));
                    }
                    path.push(field_name.clone());
                    visit(child, path)?;
                    path.pop();
                }
            }
            Value::Array(items) => {
                for (item_index, child) in items.iter().enumerate() {
                    path.push(item_index.to_string());
                    visit(child, path)?;
                    path.pop();
                }
            }
            _ => {}
        }

        Ok(())
    }

    visit(value, &mut Vec::new())
}

#[cfg(test)]
mod tests {
    use super::{
        FIN_DEC_PROOF_METADATA_FIELDS, MASK_RE_ENCRYPTION_PROOF_METADATA_FIELDS,
        MASKED_RANK_REFRESH_PROFILE_ID, PART_DEC_ERROR_SHARE_COEFFICIENT_BOUND,
        PART_DEC_LINEAR_PROOF_BACKEND_WITNESS_BOUND_CAPACITY_BITS,
        PART_DEC_LINEAR_PROOF_EXPECTED_SHORT_RESPONSE_VECTOR_LENGTH,
        PART_DEC_LINEAR_PROOF_SOURCE_POLYNOMIAL_SPLIT_FACTOR,
        PART_DEC_LINEAR_PROOF_SYSTEM_RING_DEGREE,
        PART_DEC_MASKED_SHARE_LINEAR_PROOF_BACKEND_INPUT_OBJECT_TYPE,
        PART_DEC_MASKED_SHARE_LINEAR_PROOF_VERIFIER_PENDING_STATUS, PART_DEC_PROOF_METADATA_FIELDS,
        PART_DEC_PUBLIC_KEY_SHARE_LINEAR_PROOF_BACKEND_INPUT_OBJECT_TYPE,
        PART_DEC_PUBLIC_KEY_SHARE_LINEAR_PROOF_BACKEND_VERIFIED_STATUS,
        PART_DEC_PUBLIC_KEY_SHARE_LINEAR_PROOF_ENCODING_PROFILE_ID,
        PART_DEC_PUBLIC_KEY_SHARE_LINEAR_PROOF_EXPECTED_SHORT_RESPONSE_VECTOR_LENGTH,
        PART_DEC_PUBLIC_KEY_SHARE_LINEAR_PROOF_PARAMETER_PROFILE_ID,
        PART_DEC_PUBLIC_KEY_SHARE_LINEAR_PROOF_VERIFIED_STATUS,
        PART_DEC_PUBLIC_KEY_SHARE_LINEAR_PROOF_VERIFIER_PENDING_STATUS,
        PART_DEC_PUBLIC_KEY_SHARE_WITNESS_BOUND_COMPUTATION,
        PART_DEC_PUBLIC_KEY_SHARE_WITNESS_BOUND_SOURCE, PART_DEC_SECRET_SHARE_COEFFICIENT_BOUND,
        PART_DEC_SPLIT_SAME_WITNESS_BINDING_OBJECT_TYPE,
        PART_DEC_SPLIT_SAME_WITNESS_BINDING_PENDING_STATUS,
        PART_DEC_SPLIT_SAME_WITNESS_VERIFIER_PENDING_STATUS, PART_DEC_WITNESS_BOUND_COMPUTATION,
        PART_DEC_WITNESS_BOUND_SOURCE, ProofBytesBinding,
        RankRefreshPublicKeyShareConsistencyStreamedStatement,
        SMUDGING_BOUND_PROOF_METADATA_FIELDS, ceil_log2_u64, coefficient_vector_from_le_hex,
        combine_partial_decryption_share_coefficients, describe_masked_rank_refresh_profile,
        input_ciphertext_component_zero_coefficients_for_modulus,
        lagrange_coefficients_for_selected_share_records,
        mask_re_encryption_proof_statement_challenge_domain_hash, masked_rank_refresh_profile_hash,
        part_dec_linear_proof_backend_adapter_root,
        part_dec_linear_proof_backend_input_challenge_domain_hash,
        part_dec_linear_proof_backend_witness_bound_status, part_dec_linear_proof_coefficient_hash,
        part_dec_masked_share_linear_proof_backend_input_challenge_domain_hash,
        part_dec_masked_share_linear_proof_backend_input_root,
        part_dec_masked_share_linear_proof_backend_witness_bound_status,
        part_dec_masked_share_source_matrix_hash, part_dec_masked_share_target_vector_hash,
        part_dec_masked_share_witness_bound_from_smudging_certificate,
        part_dec_public_key_share_consistency_linear_parameter_set,
        part_dec_public_key_share_consistency_linear_proof_backend_input_challenge_domain_hash,
        part_dec_public_key_share_consistency_linear_proof_backend_input_root,
        part_dec_public_key_share_consistency_linear_proof_encoding,
        part_dec_public_key_share_consistency_source_matrix_hash,
        part_dec_public_key_share_consistency_streamed_statement_for_modulus,
        part_dec_public_key_share_consistency_target_vector_hash,
        part_dec_public_key_share_witness_bound_fits_current_backend,
        part_dec_public_key_share_witness_bound_status,
        part_dec_public_key_share_witness_l2_bound_squared,
        part_dec_public_key_share_witness_l2_bound_squared_bit_length, part_dec_source_matrix_hash,
        part_dec_split_same_witness_binding_root, part_dec_target_vector_hash,
        part_dec_witness_bound_from_smudging_certificate, public_statement_without_proof_metadata,
        scalar_polynomial_coefficients, setup_decryption_threshold,
        setup_public_common_random_coefficients_for_modulus, setup_trustee_bindings,
        validate_mask_commitment_and_randomness_evidence,
        validate_mask_re_encryption_proof_records, validate_part_dec_linear_proof_backend_input,
        validate_part_dec_linear_relation_statement,
        validate_part_dec_public_key_share_consistency_linear_proof_prime_input,
        validate_part_dec_public_key_share_consistency_verified_linear_proof_for_prime,
        validate_share_selection_rule, verify_masked_rank_refresh_transcript_from_request,
    };
    use crate::{
        ballot_privacy::linear_proof::{
            parameters::LinearProofParameterSet,
            prover::{StreamedLinearProverProofInput, generate_streamed_linear_proof},
            sparse_matrix::{
                PolynomialRing, PolynomialVector, SparsePolynomialMatrix,
                SparsePolynomialMatrixEntry,
            },
            sparse_statement::transform_sparse_statement_matrix_to_proof_ring_with_coefficient_representation,
            statement::{
                LinearProofMatrixCoefficientRepresentation,
                LinearProofTargetCoefficientRepresentation, StreamedLinearProofStatement,
                source_polynomial_split_factor,
            },
        },
        bgv::{
            modular_arithmetic::{add_mod, sub_mod},
            profile::{
                BgvBasisKind, DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE,
                data_basis_modulus_bits, layout_hash, modulus_bit_length,
            },
            rns::RnsPolynomial,
            serialization::{
                BgvObjectKind, canonical_bytes_hash, ciphertext_root, parse_bgv_object_hex,
                serialize_bgv_object,
            },
            setup::{
                generate_passive_setup_package_from_request,
                trustee_public_key_share_coefficient_material_from_setup_witness,
                trustee_public_key_share_witness_coefficients_from_setup_witness,
            },
        },
        encoding::CanonicalErrorCode,
    };
    use serde_json::{Value, json};
    use std::sync::OnceLock;

    static SETUP_PACKAGE: OnceLock<Value> = OnceLock::new();

    struct MaskReEncryptionProofCiphertextBindings<'a> {
        mask_commitment_root: &'a str,
        mask_encryption_randomness_evidence_hash: &'a str,
        encrypted_mask_ciphertext_root: &'a str,
        encrypted_mask_ciphertext_payload_hash: &'a str,
        refreshed_rank_ciphertext_root: &'a str,
        refreshed_rank_ciphertext_payload_hash: &'a str,
    }

    fn hash(byte: &str) -> String {
        byte.repeat(128)
    }

    fn proof_bytes_hex(label: &str) -> String {
        crate::transcript_core::encode_hex(label.as_bytes())
    }

    fn proof_bytes_hash(proof_bytes_hex: &str) -> String {
        crate::hashing::derive_protocol_hash_for_proof_bytes_payload(
            proof_bytes_hex,
            (proof_bytes_hex.len() / 2) as u64,
        )
        .expect("proof bytes hash")
    }

    fn bind_proof_bytes(value: &mut Value, binding: &ProofBytesBinding<'_>, proof_label: &str) {
        let proof_bytes_hex = proof_bytes_hex(proof_label);
        value[binding.proof_bytes_hex_field] = Value::String(proof_bytes_hex.clone());
        value[binding.proof_size_bytes_field] = json!(proof_bytes_hex.len() / 2);
        value[binding.proof_bytes_hash_field] = Value::String(proof_bytes_hash(&proof_bytes_hex));
        rebind_proof_statement_hash(
            value,
            binding.proof_statement_hash_field,
            binding.statement_hash_namespace,
            binding.statement_metadata_fields,
        );
    }

    fn rebind_proof_statement_hash(
        value: &mut Value,
        proof_statement_hash_field: &str,
        statement_hash_namespace: &str,
        statement_metadata_fields: &[&str],
    ) {
        let public_statement =
            public_statement_without_proof_metadata(value, statement_metadata_fields)
                .expect("public proof statement");
        let statement_hash =
            crate::hashing::derive_protocol_hash(statement_hash_namespace, &public_statement)
                .expect("proof statement hash");
        value[proof_statement_hash_field] = Value::String(statement_hash);
    }

    fn bind_standard_proof_bytes(
        value: &mut Value,
        statement_hash_namespace: &str,
        statement_metadata_fields: &[&str],
        proof_label: &str,
    ) {
        bind_proof_bytes(
            value,
            &ProofBytesBinding {
                proof_bytes_hex_field: "proofBytesHex",
                proof_size_bytes_field: "proofSizeBytes",
                proof_bytes_hash_field: "proofBytesHash",
                proof_statement_hash_field: "proofStatementHash",
                statement_hash_namespace,
                statement_metadata_fields,
                label: "rank refresh fixture proof bytes",
            },
            proof_label,
        );
    }

    fn bind_smudging_bound_proof_bytes(value: &mut Value, proof_label: &str) {
        bind_proof_bytes(
            value,
            &ProofBytesBinding {
                proof_bytes_hex_field: "boundProofBytesHex",
                proof_size_bytes_field: "boundProofSizeBytes",
                proof_bytes_hash_field: "boundProofBytesHash",
                proof_statement_hash_field: "boundProofStatementHash",
                statement_hash_namespace: "MaskedRankRefreshSmudgingBoundStatementHash",
                statement_metadata_fields: &SMUDGING_BOUND_PROOF_METADATA_FIELDS,
                label: "rank refresh fixture smudging proof bytes",
            },
            proof_label,
        );
    }

    fn rebind_part_dec_proof_statement_hash(value: &mut Value) {
        rebind_proof_statement_hash(
            value,
            "proofStatementHash",
            "MaskedRankRefreshPartDecShareEquationProofStatementHash",
            &PART_DEC_PROOF_METADATA_FIELDS,
        );
    }

    fn rebind_fin_dec_proof_statement_hash(value: &mut Value) {
        rebind_proof_statement_hash(
            value,
            "proofStatementHash",
            "MaskedRankRefreshFinDecMaskedOpeningStatementHash",
            &FIN_DEC_PROOF_METADATA_FIELDS,
        );
    }

    fn rebind_mask_re_encryption_proof_statement_hash(value: &mut Value) {
        let challenge_domain_hash = mask_re_encryption_proof_statement_challenge_domain_hash(value)
            .expect("mask re-encryption challenge-domain hash");
        let public_randomness_hex = challenge_domain_hash
            .get(..64)
            .expect("challenge-domain hash has randomness prefix")
            .to_string();
        value["challengeDomainHash"] = Value::String(challenge_domain_hash);
        value["publicRandomnessSource"] =
            Value::String("challenge-domain-hash-prefix-32-bytes".to_string());
        value["publicRandomnessHex"] = Value::String(public_randomness_hex);
        rebind_proof_statement_hash(
            value,
            "proofStatementHash",
            "MaskedRankRefreshMaskReEncryptionProofStatementHash",
            &MASK_RE_ENCRYPTION_PROOF_METADATA_FIELDS,
        );
    }

    fn coefficient_vector_bytes(coefficients: &[u64]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(coefficients.len() * 8);
        for coefficient in coefficients {
            bytes.extend(coefficient.to_le_bytes());
        }

        bytes
    }

    fn coefficient_vector_le_hex(coefficients: &[u64]) -> String {
        crate::transcript_core::encode_hex(&coefficient_vector_bytes(coefficients))
    }

    fn partial_decryption_share_coefficient_hash(coefficients: &[u64]) -> String {
        crate::hashing::hash512_hex(
            "sealed-lattice-bgv-rns/masked-rank-refresh-partial-decryption-share-coefficient-vector-v1",
            &[&coefficient_vector_bytes(coefficients)],
        )
    }

    fn fin_dec_masked_opening_coefficient_hash(coefficients: &[u64]) -> String {
        crate::hashing::hash512_hex(
            "sealed-lattice-bgv-rns/masked-rank-refresh-fin-dec-masked-opening-coefficient-vector-v1",
            &[&coefficient_vector_bytes(coefficients)],
        )
    }

    fn input_rank_ciphertext_component_one_coefficient_hash(coefficients: &[u64]) -> String {
        crate::hashing::hash512_hex(
            "sealed-lattice-bgv-rns/masked-rank-refresh-input-rank-ciphertext-component-one-coefficient-vector-v1",
            &[&coefficient_vector_bytes(coefficients)],
        )
    }

    fn input_rank_ciphertext_component_one_payload(
        setup_package: &Value,
    ) -> (String, String, Value) {
        let level = DATA_PRIMES.len() - 1;
        let component_zero_residues_by_modulus = DATA_PRIMES
            .iter()
            .enumerate()
            .map(|(modulus_index, modulus)| {
                (0..POLYNOMIAL_DEGREE)
                    .map(|coefficient_index| {
                        ((coefficient_index as u64 + 3) * 11 + modulus_index as u64 * 19) % *modulus
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let component_one_residues_by_modulus = DATA_PRIMES
            .iter()
            .enumerate()
            .map(|(modulus_index, modulus)| {
                (0..POLYNOMIAL_DEGREE)
                    .map(|coefficient_index| {
                        ((coefficient_index as u64 + 5) * 7 + modulus_index as u64 * 23) % *modulus
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let component_zero = RnsPolynomial::coefficient_domain(
            BgvBasisKind::Data,
            level,
            layout_hash().expect("layout hash"),
            component_zero_residues_by_modulus,
        )
        .expect("component zero");
        let component_one = RnsPolynomial::coefficient_domain(
            BgvBasisKind::Data,
            level,
            layout_hash().expect("layout hash"),
            component_one_residues_by_modulus.clone(),
        )
        .expect("component one");
        let canonical_bytes =
            serialize_bgv_object(BgvObjectKind::Ciphertext, &[component_zero, component_one])
                .expect("canonical input rank ciphertext");
        let input_rank_ciphertext_root = ciphertext_root(&canonical_bytes);
        let component_one_tables = component_one_residues_by_modulus
            .iter()
            .enumerate()
            .map(|(modulus_index, coefficients)| {
                json!({
                    "modulusIndex": modulus_index,
                    "modulus": DATA_PRIMES[modulus_index],
                    "coefficientEncoding": "little-endian-u64",
                    "componentOneCoefficientsLeHex": coefficient_vector_le_hex(coefficients),
                    "componentOneCoefficientHash512": input_rank_ciphertext_component_one_coefficient_hash(coefficients),
                    "coefficientByteLength": POLYNOMIAL_DEGREE * 8,
                })
            })
            .collect::<Vec<_>>();
        let payload = json!({
            "objectType": "MaskedRankRefreshInputRankCiphertextComponentOnePayload",
            "objectVersion": 1,
            "profileId": MASKED_RANK_REFRESH_PROFILE_ID,
            "payloadStatus": "PublicInputRankCiphertextComponentOnePayloadBound",
            "ciphertextRole": "packed-rank",
            "ciphertextComponentRole": "ciphertext-component-one",
            "componentIndex": 1,
            "componentCount": 2,
            "basisId": "data",
            "coefficientDomain": "coefficient",
            "coefficientEncoding": "little-endian-u64-coefficient-vectors-by-data-prime",
            "level": level,
            "polynomialDegree": POLYNOMIAL_DEGREE,
            "dataPrimeCount": DATA_PRIMES.len(),
            "setupPackageHash": setup_package["setupPackageHash"],
            "evaluationContextHash": hash("1"),
            "inputRankCiphertextRoot": input_rank_ciphertext_root,
            "ciphertextRoot": input_rank_ciphertext_root,
            "canonicalCiphertextConventionHash": crate::bgv::profile::canonical_ciphertext_convention_hash().expect("ciphertext convention hash"),
            "canonicalBytesHex": crate::transcript_core::encode_hex(&canonical_bytes),
            "canonicalBytesHash512": canonical_bytes_hash(&canonical_bytes),
            "canonicalByteLength": canonical_bytes.len(),
            "componentOneCoefficientTables": component_one_tables,
        });
        let payload_hash = crate::hashing::derive_protocol_hash(
            "MaskedRankRefreshInputRankCiphertextComponentOnePayloadHash",
            &payload,
        )
        .expect("input rank component-one payload hash");

        (
            payload["inputRankCiphertextRoot"]
                .as_str()
                .expect("root")
                .to_string(),
            payload_hash,
            payload,
        )
    }

    fn mask_re_encryption_ciphertext_payload(
        setup_package: &Value,
        ciphertext_role: &str,
        root_alias_field: &str,
        hash_namespace: &str,
        coefficient_seed: u64,
    ) -> (String, String, Value) {
        let level = DATA_PRIMES.len() - 1;
        let components = (0..2)
            .map(|component_index| {
                let residues_by_modulus = DATA_PRIMES
                    .iter()
                    .enumerate()
                    .map(|(modulus_index, modulus)| {
                        (0..POLYNOMIAL_DEGREE)
                            .map(|coefficient_index| {
                                (coefficient_seed
                                    + component_index as u64 * 29
                                    + modulus_index as u64 * 31
                                    + coefficient_index as u64 * 37)
                                    % *modulus
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();
                RnsPolynomial::coefficient_domain(
                    BgvBasisKind::Data,
                    level,
                    layout_hash().expect("layout hash"),
                    residues_by_modulus,
                )
                .expect("mask re-encryption ciphertext component")
            })
            .collect::<Vec<_>>();
        let canonical_bytes = serialize_bgv_object(BgvObjectKind::Ciphertext, &components)
            .expect("canonical mask re-encryption ciphertext");
        let ciphertext_root_value = ciphertext_root(&canonical_bytes);
        let mut payload = json!({
            "objectType": "MaskedRankRefreshMaskReEncryptionCiphertextPayload",
            "objectVersion": 1,
            "profileId": MASKED_RANK_REFRESH_PROFILE_ID,
            "payloadStatus": "PublicMaskReEncryptionCiphertextPayloadBound",
            "ciphertextRole": ciphertext_role,
            "basisId": "data",
            "coefficientDomain": "coefficient",
            "coefficientEncoding": "canonical-bgv-rns-ciphertext-bytes",
            "componentCount": 2,
            "level": level,
            "polynomialDegree": POLYNOMIAL_DEGREE,
            "dataPrimeCount": DATA_PRIMES.len(),
            "setupPackageHash": setup_package["setupPackageHash"],
            "collectivePublicKeyRoot": setup_package["collectivePublicKey"]["collectivePublicKeyRoot"],
            "bgvPublicKeyRoot": setup_package["collectivePublicKey"]["bgvPublicKeyRoot"],
            "targetLayoutHash": setup_package["profileBindings"]["targetLayoutHash"],
            "evaluationContextHash": hash("1"),
            "ciphertextRoot": ciphertext_root_value,
            "canonicalCiphertextConventionHash": crate::bgv::profile::canonical_ciphertext_convention_hash().expect("ciphertext convention hash"),
            "canonicalBytesHex": crate::transcript_core::encode_hex(&canonical_bytes),
            "canonicalBytesHash512": canonical_bytes_hash(&canonical_bytes),
            "canonicalByteLength": canonical_bytes.len(),
            "maskPlaintextExported": false,
            "plaintextRankExported": false,
            "semanticRankOpeningAllowed": false,
        });
        payload[root_alias_field] = payload["ciphertextRoot"].clone();
        let payload_hash = crate::hashing::derive_protocol_hash(hash_namespace, &payload)
            .expect("mask re-encryption ciphertext payload hash");

        (
            payload["ciphertextRoot"]
                .as_str()
                .expect("root")
                .to_string(),
            payload_hash,
            payload,
        )
    }

    fn partial_decryption_share_payload(
        setup_package: &Value,
        participant: &Value,
        algebraic_trustee_key: &Value,
        input_rank_ciphertext_root: &str,
        input_rank_ciphertext_component_one_payload_hash: &str,
        smudging_bound_certificate_hash: &str,
        share_freshness_hash: &str,
    ) -> Value {
        let roster_position = participant["rosterPosition"]
            .as_u64()
            .expect("roster position");
        let coefficient_tables = crate::bgv::profile::DATA_PRIMES
            .iter()
            .enumerate()
            .map(|(modulus_index, modulus)| {
                let coefficients = (0..POLYNOMIAL_DEGREE)
                    .map(|coefficient_index| {
                        ((coefficient_index as u64 + 1) * (roster_position + 1)
                            + (modulus_index as u64 * 17))
                            % *modulus
                    })
                    .collect::<Vec<_>>();
                json!({
                    "modulusIndex": modulus_index,
                    "modulus": modulus,
                    "coefficientEncoding": "little-endian-u64",
                    "shareCoefficientsLeHex": coefficient_vector_le_hex(&coefficients),
                    "shareCoefficientHash512": partial_decryption_share_coefficient_hash(&coefficients),
                    "coefficientByteLength": POLYNOMIAL_DEGREE * 8,
                })
            })
            .collect::<Vec<_>>();

        json!({
            "objectType": "MaskedRankRefreshPartialDecryptionSharePayload",
            "objectVersion": 1,
            "profileId": MASKED_RANK_REFRESH_PROFILE_ID,
            "payloadStatus": "PublicMaskedPartialDecryptionSharePayloadBound",
            "sharePayloadKind": "masked-partial-decryption-share-polynomial",
            "partDecShareEquation": "partialDecryptionShare = ciphertextComponentOne * trusteeSecretShare + smudgingNoise mod q",
            "basisId": "data",
            "coefficientDomain": "coefficient",
            "coefficientEncoding": "little-endian-u64-coefficient-vectors-by-data-prime",
            "componentCount": 1,
            "polynomialDegree": POLYNOMIAL_DEGREE,
            "dataPrimeCount": crate::bgv::profile::DATA_PRIMES.len(),
            "plaintextModulus": crate::bgv::profile::PLAINTEXT_MODULUS,
            "partialDecryptionShareIsMasked": true,
            "semanticRankOpeningAllowed": false,
            "plaintextRankExported": false,
            "rawSecretShareExported": false,
            "smudgingNoiseExported": false,
            "setupPackageHash": setup_package["setupPackageHash"],
            "evaluationContextHash": hash("1"),
            "inputRankCiphertextRoot": input_rank_ciphertext_root,
            "inputRankCiphertextComponentOnePayloadHash": input_rank_ciphertext_component_one_payload_hash,
            "smudgingBoundCertificateHash": smudging_bound_certificate_hash,
            "trusteeIdentity": participant["trusteeIdentity"],
            "rosterPosition": participant["rosterPosition"],
            "participantSetupRecordHash": participant["participantSetupRecordHash"],
            "publicKeyShareCoefficientMaterialRoot": algebraic_trustee_key["publicKeyShareCoefficientMaterialRoot"],
            "publicKeyShareCoefficientMaterialHash": algebraic_trustee_key["publicKeyShareCoefficientMaterialHash"],
            "trusteeThresholdVerificationKeyHash": participant["trusteeThresholdVerificationKeyHash"],
            "shareFreshnessHash": share_freshness_hash,
            "coefficientTables": coefficient_tables,
        })
    }

    struct PartDecLinearRelationStatementFixture<'a> {
        setup_package: &'a Value,
        participant: &'a Value,
        algebraic_trustee_key: &'a Value,
        public_key_share_coefficient_material_sidecar: &'a Value,
        input_rank_ciphertext_root: &'a str,
        input_rank_ciphertext_component_one_payload_hash: &'a str,
        input_rank_ciphertext_component_one_payload: &'a Value,
        partial_decryption_share_root: &'a str,
        partial_decryption_share_payload: &'a Value,
        selected_algebraic_share_verification_key_binding_root: &'a str,
        smudging_bound_certificate_hash: &'a str,
        share_freshness_hash: &'a str,
    }

    struct RankRefreshShareRecordFixture<'a> {
        setup_package: &'a Value,
        input_rank_ciphertext_root: &'a str,
        input_rank_ciphertext_component_one_payload_hash: &'a str,
        input_rank_ciphertext_component_one_payload: &'a Value,
        smudging_bound_certificate_hash: &'a str,
        smudging_bound_certificate: &'a Value,
        public_key_share_coefficient_material_sidecars: &'a [Value],
        selected_algebraic_share_verification_key_bindings: &'a [Value],
    }

    fn part_dec_linear_relation_statement(
        inputs: PartDecLinearRelationStatementFixture<'_>,
    ) -> Value {
        let PartDecLinearRelationStatementFixture {
            setup_package,
            participant,
            algebraic_trustee_key,
            public_key_share_coefficient_material_sidecar,
            input_rank_ciphertext_root,
            input_rank_ciphertext_component_one_payload_hash,
            input_rank_ciphertext_component_one_payload,
            partial_decryption_share_root,
            partial_decryption_share_payload,
            selected_algebraic_share_verification_key_binding_root,
            smudging_bound_certificate_hash,
            share_freshness_hash,
        } = inputs;
        let sidecar_tables = public_key_share_coefficient_material_sidecar["coefficientTables"]
            .as_array()
            .expect("public key-share coefficient sidecar tables");
        let input_rank_tables =
            input_rank_ciphertext_component_one_payload["componentOneCoefficientTables"]
                .as_array()
                .expect("input rank component-one tables");
        let partial_share_tables = partial_decryption_share_payload["coefficientTables"]
            .as_array()
            .expect("partial-decryption share coefficient tables");
        let linear_relation_tables = sidecar_tables
            .iter()
            .zip(input_rank_tables)
            .zip(partial_share_tables)
            .enumerate()
            .map(
                |(modulus_index, ((sidecar_table, input_rank_table), partial_share_table))| {
                    json!({
                        "modulusIndex": modulus_index,
                        "modulus": DATA_PRIMES[modulus_index],
                        "publicKeyShareComponentZeroHash512": sidecar_table["componentZeroBHash512"],
                        "publicCommonRandomPolynomialHash512": sidecar_table["componentOneAHash512"],
                        "inputRankCiphertextComponentOneHash512": input_rank_table["componentOneCoefficientHash512"],
                        "partialDecryptionShareHash512": partial_share_table["shareCoefficientHash512"],
                    })
                },
            )
            .collect::<Vec<_>>();
        let linear_proof_adapter_tables = sidecar_tables
            .iter()
            .zip(input_rank_tables)
            .zip(partial_share_tables)
            .enumerate()
            .map(
                |(modulus_index, ((sidecar_table, input_rank_table), partial_share_table))| {
                    let modulus = DATA_PRIMES[modulus_index];
                    let public_common_random_coefficients =
                        setup_public_common_random_coefficients_for_modulus(
                            setup_package,
                            modulus_index,
                            modulus,
                        )
                        .expect("setup common-random coefficients");
                    let public_key_share_component_zero_coefficients =
                        coefficient_vector_from_le_hex(
                            sidecar_table["componentZeroBLeHex"]
                                .as_str()
                                .expect("public key-share component-zero coefficients"),
                            "public key-share component-zero coefficients",
                        )
                        .expect("public key-share component-zero coefficient vector");
                    let input_rank_component_one_coefficients = coefficient_vector_from_le_hex(
                        input_rank_table["componentOneCoefficientsLeHex"]
                            .as_str()
                            .expect("input rank component-one coefficients"),
                        "input rank component-one coefficients",
                    )
                    .expect("input rank component-one coefficient vector");
                    let partial_decryption_share_coefficients = coefficient_vector_from_le_hex(
                        partial_share_table["shareCoefficientsLeHex"]
                            .as_str()
                            .expect("partial-decryption share coefficients"),
                        "partial-decryption share coefficients",
                    )
                    .expect("partial-decryption share coefficient vector");
                    let negative_plaintext_modulus_coefficients =
                        scalar_polynomial_coefficients(
                            sub_mod(0, PLAINTEXT_MODULUS % modulus, modulus)
                                .expect("negative plaintext modulus scalar"),
                            modulus,
                        );
                    let zero_polynomial_coefficients = vec![0_u64; POLYNOMIAL_DEGREE];
                    let one_scalar_coefficients = scalar_polynomial_coefficients(1, modulus);
                    let negative_partial_decryption_share_coefficients =
                        partial_decryption_share_coefficients
                            .iter()
                            .map(|coefficient| {
                                sub_mod(0, *coefficient, modulus)
                                    .expect("negative partial-decryption share coefficient")
                            })
                            .collect::<Vec<_>>();

                    json!({
                        "modulusIndex": modulus_index,
                        "modulus": modulus,
                        "publicKeyShareEquationRowIndex": 0,
                        "partDecShareEquationRowIndex": 1,
                        "publicCommonRandomPolynomialHash512": sidecar_table["componentOneAHash512"],
                        "publicKeyShareComponentZeroHash512": sidecar_table["componentZeroBHash512"],
                        "inputRankCiphertextComponentOneHash512": input_rank_table["componentOneCoefficientHash512"],
                        "partialDecryptionShareHash512": partial_share_table["shareCoefficientHash512"],
                        "negativePlaintextModulusScalarHash512": part_dec_linear_proof_coefficient_hash(&negative_plaintext_modulus_coefficients),
                        "zeroPolynomialHash512": part_dec_linear_proof_coefficient_hash(&zero_polynomial_coefficients),
                        "oneScalarPolynomialHash512": part_dec_linear_proof_coefficient_hash(&one_scalar_coefficients),
                        "publicKeyShareComponentZeroTargetHash512": part_dec_linear_proof_coefficient_hash(&public_key_share_component_zero_coefficients),
                        "negativePartialDecryptionShareTargetHash512": part_dec_linear_proof_coefficient_hash(&negative_partial_decryption_share_coefficients),
                        "sourceMatrixHash512": part_dec_source_matrix_hash(
                            modulus,
                            &public_common_random_coefficients,
                            &negative_plaintext_modulus_coefficients,
                            &zero_polynomial_coefficients,
                            &input_rank_component_one_coefficients,
                            &one_scalar_coefficients,
                        ),
                        "targetVectorHash512": part_dec_target_vector_hash(
                            modulus,
                            &public_key_share_component_zero_coefficients,
                            &negative_partial_decryption_share_coefficients,
                        ),
                        "publicKeyShareConsistencySourceMatrixHash512": part_dec_public_key_share_consistency_source_matrix_hash(
                            modulus,
                            &public_common_random_coefficients,
                            &negative_plaintext_modulus_coefficients,
                        ),
                        "publicKeyShareConsistencyTargetVectorHash512": part_dec_public_key_share_consistency_target_vector_hash(
                            modulus,
                            &public_key_share_component_zero_coefficients,
                        ),
                        "maskedShareSourceMatrixHash512": part_dec_masked_share_source_matrix_hash(
                            modulus,
                            &input_rank_component_one_coefficients,
                            &one_scalar_coefficients,
                        ),
                        "maskedShareTargetVectorHash512": part_dec_masked_share_target_vector_hash(
                            modulus,
                            &negative_partial_decryption_share_coefficients,
                        ),
                    })
                },
            )
            .collect::<Vec<_>>();

        json!({
            "objectType": "MaskedRankRefreshPartDecLinearRelationStatement",
            "objectVersion": 1,
            "profileId": MASKED_RANK_REFRESH_PROFILE_ID,
            "statementFormat": "masked-rank-refresh-partdec-linear-relation-v1",
            "relationKind": "same-secret-public-key-share-and-masked-partdec-linear-relation",
            "proofBackendRequired": "LinearLatticeRelationOverBgvDataBasis",
            "proofBackendStatus": "VerifierPending",
            "witnessLayout": "trusteeSecretShare,trusteeErrorShare,smudgingNoise",
            "commonWitness": "trusteeSecretShare",
            "publicKeyShareEquation": "publicKeyShareComponentZero + publicCommonRandomPolynomial * trusteeSecretShare = plaintextModulus * trusteeErrorShare mod q",
            "partDecShareEquation": "partialDecryptionShare = inputCiphertextComponentOne * trusteeSecretShare + smudgingNoise mod q",
            "smudgingBoundSource": "smudgingBoundCertificate",
            "rawWitnessExported": false,
            "semanticRankOpeningAllowed": false,
            "setupPackageHash": setup_package["setupPackageHash"],
            "evaluationContextHash": hash("1"),
            "inputRankCiphertextRoot": input_rank_ciphertext_root,
            "inputRankCiphertextComponentOnePayloadHash": input_rank_ciphertext_component_one_payload_hash,
            "partialDecryptionShareRoot": partial_decryption_share_root,
            "selectedAlgebraicShareVerificationKeyBindingRoot": selected_algebraic_share_verification_key_binding_root,
            "publicKeyShareCoefficientMaterialRoot": algebraic_trustee_key["publicKeyShareCoefficientMaterialRoot"],
            "publicKeyShareCoefficientMaterialHash": algebraic_trustee_key["publicKeyShareCoefficientMaterialHash"],
            "participantSetupRecordHash": participant["participantSetupRecordHash"],
            "publicKeyShareRoot": participant["publicKeyShareRoot"],
            "smudgingBoundCertificateHash": smudging_bound_certificate_hash,
            "shareFreshnessHash": share_freshness_hash,
            "trusteeIdentity": participant["trusteeIdentity"],
            "rosterPosition": participant["rosterPosition"],
            "polynomialDegree": POLYNOMIAL_DEGREE,
            "dataPrimeCount": DATA_PRIMES.len(),
            "plaintextModulus": PLAINTEXT_MODULUS,
            "linearProofBackendAdapter": {
                "objectType": "MaskedRankRefreshPartDecLinearProofBackendAdapter",
                "objectVersion": 1,
                "profileId": MASKED_RANK_REFRESH_PROFILE_ID,
                "adapterStatus": "PartDecLinearProofBackendAdapterBound",
                "proofBackend": "sealed-lattice-linear-proof",
                "proofBackendStatus": "VerifierPending",
                "sourceMatrixCoefficientRepresentation": "canonicalUnsignedSourceModulus",
                "targetCoefficientRepresentation": "canonicalUnsignedSourceModulus",
                "publicCommonRandomPolynomialSource": "setup-collective-public-key-coefficient-material",
                "statementRows": 2,
                "witnessColumnCount": 3,
                "witnessColumns": ["trusteeSecretShare", "trusteeErrorShare", "smudgingNoise"],
                "rowEquations": [
                    "publicKeyShareComponentZero + publicCommonRandomPolynomial * trusteeSecretShare = plaintextModulus * trusteeErrorShare mod q",
                    "partialDecryptionShare = inputCiphertextComponentOne * trusteeSecretShare + smudgingNoise mod q"
                ],
                "setupPackageHash": setup_package["setupPackageHash"],
                "collectivePublicKeyRoot": setup_package["collectivePublicKey"]["collectivePublicKeyRoot"],
                "bgvPublicKeyRoot": setup_package["collectivePublicKey"]["bgvPublicKeyRoot"],
                "evaluationContextHash": hash("1"),
                "inputRankCiphertextComponentOnePayloadHash": input_rank_ciphertext_component_one_payload_hash,
                "partialDecryptionShareRoot": partial_decryption_share_root,
                "publicKeyShareCoefficientMaterialRoot": algebraic_trustee_key["publicKeyShareCoefficientMaterialRoot"],
                "selectedAlgebraicShareVerificationKeyBindingRoot": selected_algebraic_share_verification_key_binding_root,
                "polynomialDegree": POLYNOMIAL_DEGREE,
                "dataPrimeCount": DATA_PRIMES.len(),
                "plaintextModulus": PLAINTEXT_MODULUS,
                "adapterTables": linear_proof_adapter_tables,
            },
            "linearRelationTables": linear_relation_tables,
        })
    }

    fn part_dec_public_key_share_consistency_linear_proof_backend_input(
        proof: &Value,
        part_dec_linear_relation_statement_root: &str,
        part_dec_linear_relation_statement: &Value,
    ) -> Value {
        let adapter = &part_dec_linear_relation_statement["linearProofBackendAdapter"];
        let adapter_root = part_dec_linear_proof_backend_adapter_root(adapter)
            .expect("PartDec public key-share adapter root");
        let challenge_domain_hash =
            part_dec_public_key_share_consistency_linear_proof_backend_input_challenge_domain_hash(
                proof,
                part_dec_linear_relation_statement_root,
                &adapter_root,
            )
            .expect("PartDec public key-share backend input challenge-domain hash");
        let public_randomness_hex = challenge_domain_hash
            .get(..64)
            .expect("challenge-domain hash has randomness prefix")
            .to_string();
        let witness_l2_bound_squared =
            part_dec_public_key_share_witness_l2_bound_squared().to_string();
        let data_prime_proof_inputs = adapter["adapterTables"]
            .as_array()
            .expect("adapter tables")
            .iter()
            .enumerate()
            .map(|(modulus_index, adapter_table)| {
                let modulus = DATA_PRIMES[modulus_index];
                json!({
                    "modulusIndex": modulus_index,
                    "modulus": modulus,
                    "publicCommonRandomPolynomialHash512": adapter_table["publicCommonRandomPolynomialHash512"],
                    "publicKeyShareComponentZeroHash512": adapter_table["publicKeyShareComponentZeroHash512"],
                    "negativePlaintextModulusScalarHash512": adapter_table["negativePlaintextModulusScalarHash512"],
                    "sourceMatrixHash512": adapter_table["publicKeyShareConsistencySourceMatrixHash512"],
                    "targetVectorHash512": adapter_table["publicKeyShareConsistencyTargetVectorHash512"],
                    "proofParameterSet": part_dec_public_key_share_consistency_linear_parameter_set(modulus),
                    "proofEncoding": part_dec_public_key_share_consistency_linear_proof_encoding(),
                    "proofParameterBinding": {
                        "parameterProfileStatus": "RankRefreshPartDecPublicKeyShareConsistencyParameterProfileBound",
                        "profileId": PART_DEC_PUBLIC_KEY_SHARE_LINEAR_PROOF_PARAMETER_PROFILE_ID,
                        "source": "sealed-lattice/linear-proof/masked-rank-refresh-partdec-public-key-share-consistency-parameters-v1",
                        "relation": "A*w + t = 0",
                        "coefficientModulus": modulus.to_string(),
                        "sourceRingDegree": POLYNOMIAL_DEGREE,
                        "proofSystemRingDegree": PART_DEC_LINEAR_PROOF_SYSTEM_RING_DEGREE,
                        "statementRows": 1,
                        "statementColumns": 2,
                        "witnessColumns": ["trusteeSecretShare", "trusteeErrorShare"],
                        "witnessBoundSource": PART_DEC_PUBLIC_KEY_SHARE_WITNESS_BOUND_SOURCE,
                        "witnessBoundComputation": PART_DEC_PUBLIC_KEY_SHARE_WITNESS_BOUND_COMPUTATION,
                        "secretShareDistribution": "owner-routed-standard-ternary-local-share",
                        "secretShareCoefficientBound": PART_DEC_SECRET_SHARE_COEFFICIENT_BOUND,
                        "errorShareDistribution": "owner-routed-centered-binomial-eta2-collective-error",
                        "errorShareCoefficientBound": PART_DEC_ERROR_SHARE_COEFFICIENT_BOUND,
                        "witnessL2BoundSquared": witness_l2_bound_squared.as_str(),
                        "witnessL2BoundSquaredBitLength": part_dec_public_key_share_witness_l2_bound_squared_bit_length(),
                        "witnessL2BoundSquaredFitsProofBackend": part_dec_public_key_share_witness_bound_fits_current_backend(),
                    },
                    "proofEncodingBinding": {
                        "proofEncodingStatus": "RankRefreshPartDecPublicKeyShareConsistencyProofEncodingBound",
                        "profileId": PART_DEC_PUBLIC_KEY_SHARE_LINEAR_PROOF_ENCODING_PROFILE_ID,
                        "source": "sealed-lattice/linear-proof/masked-rank-refresh-partdec-public-key-share-consistency-encoding-v1",
                        "proofSystemRingDegree": PART_DEC_LINEAR_PROOF_SYSTEM_RING_DEGREE,
                        "sourcePolynomialSplitFactor": PART_DEC_LINEAR_PROOF_SOURCE_POLYNOMIAL_SPLIT_FACTOR,
                        "expectedShortResponseVectorLength": PART_DEC_PUBLIC_KEY_SHARE_LINEAR_PROOF_EXPECTED_SHORT_RESPONSE_VECTOR_LENGTH,
                        "matrixCoefficientRepresentation": "centeredSignedSourceModulus",
                        "targetCoefficientRepresentation": "centeredSignedSourceModulus",
                    }
                })
            })
            .collect::<Vec<_>>();

        json!({
            "objectType": PART_DEC_PUBLIC_KEY_SHARE_LINEAR_PROOF_BACKEND_INPUT_OBJECT_TYPE,
            "objectVersion": 1,
            "profileId": MASKED_RANK_REFRESH_PROFILE_ID,
            "inputStatus": "PartDecPublicKeyShareConsistencyLinearProofBackendInputBound",
            "proofBackend": "sealed-lattice-linear-proof",
            "proofBackendStatus": "VerifierPending",
            "proofVerificationStatus": PART_DEC_PUBLIC_KEY_SHARE_LINEAR_PROOF_VERIFIER_PENDING_STATUS,
            "proofBytesVerified": false,
            "proofInputFormat": "masked-rank-refresh-partdec-public-key-share-consistency-per-data-prime-linear-proof-input-v1",
            "relationScope": "public-key-share-consistency-only",
            "smudgingWitnessExcluded": true,
            "maskedPartDecShareRelationExcluded": true,
            "statementMaterialMode": "streamed-derived-from-adapter-tables",
            "sameWitnessAcrossDataPrimesRequired": true,
            "sameWitnessBindingStatus": "PublicRootsBoundWitnessProofPending",
            "setupPackageHash": proof["setupPackageHash"],
            "evaluationContextHash": proof["evaluationContextHash"],
            "selectedAlgebraicShareVerificationKeyBindingRoot": proof["selectedAlgebraicShareVerificationKeyBindingRoot"],
            "publicKeyShareCoefficientMaterialRoot": proof["publicKeyShareCoefficientMaterialRoot"],
            "publicKeyShareCoefficientMaterialHash": proof["publicKeyShareCoefficientMaterialHash"],
            "partDecLinearRelationStatementRoot": part_dec_linear_relation_statement_root,
            "linearProofBackendAdapterRoot": adapter_root,
            "proofSystemRingDegree": PART_DEC_LINEAR_PROOF_SYSTEM_RING_DEGREE,
            "sourcePolynomialSplitFactor": PART_DEC_LINEAR_PROOF_SOURCE_POLYNOMIAL_SPLIT_FACTOR,
            "expectedShortResponseVectorLength": PART_DEC_PUBLIC_KEY_SHARE_LINEAR_PROOF_EXPECTED_SHORT_RESPONSE_VECTOR_LENGTH,
            "dataPrimeProofInputCount": DATA_PRIMES.len(),
            "proofBackendWitnessBoundCapacityBits": PART_DEC_LINEAR_PROOF_BACKEND_WITNESS_BOUND_CAPACITY_BITS,
            "witnessL2BoundSquared": witness_l2_bound_squared,
            "witnessL2BoundSquaredBitLength": part_dec_public_key_share_witness_l2_bound_squared_bit_length(),
            "witnessL2BoundSquaredFitsProofBackend": part_dec_public_key_share_witness_bound_fits_current_backend(),
            "proofBackendWitnessBoundStatus": part_dec_public_key_share_witness_bound_status(),
            "challengeDomainHash": challenge_domain_hash,
            "publicRandomnessSource": "challenge-domain-hash-prefix-32-bytes",
            "publicRandomnessHex": public_randomness_hex,
            "dataPrimeProofInputs": data_prime_proof_inputs,
        })
    }

    fn part_dec_masked_share_linear_proof_backend_input(
        proof: &Value,
        part_dec_linear_relation_statement_root: &str,
        part_dec_linear_relation_statement: &Value,
        smudging_bound_certificate: &Value,
    ) -> Value {
        let adapter = &part_dec_linear_relation_statement["linearProofBackendAdapter"];
        let adapter_root =
            part_dec_linear_proof_backend_adapter_root(adapter).expect("PartDec adapter root");
        let challenge_domain_hash =
            part_dec_masked_share_linear_proof_backend_input_challenge_domain_hash(
                proof,
                part_dec_linear_relation_statement_root,
                &adapter_root,
            )
            .expect("PartDec masked-share backend input challenge-domain hash");
        let public_randomness_hex = challenge_domain_hash
            .get(..64)
            .expect("challenge-domain hash has randomness prefix")
            .to_string();
        let witness_bound = part_dec_masked_share_witness_bound_from_smudging_certificate(
            smudging_bound_certificate,
        )
        .expect("PartDec masked-share witness bound");
        let data_prime_proof_inputs = adapter["adapterTables"]
            .as_array()
            .expect("adapter tables")
            .iter()
            .enumerate()
            .map(|(modulus_index, adapter_table)| {
                let modulus = DATA_PRIMES[modulus_index];
                json!({
                    "modulusIndex": modulus_index,
                    "modulus": modulus,
                    "inputRankCiphertextComponentOneHash512": adapter_table["inputRankCiphertextComponentOneHash512"],
                    "partialDecryptionShareHash512": adapter_table["partialDecryptionShareHash512"],
                    "sourceMatrixHash512": adapter_table["maskedShareSourceMatrixHash512"],
                    "targetVectorHash512": adapter_table["maskedShareTargetVectorHash512"],
                    "proofParameterBinding": {
                        "parameterProfileStatus": "RankRefreshPartDecMaskedShareParameterProfilePendingBecauseWitnessBoundExceedsCurrentLinearProofBackendCapacity",
                        "profileId": "masked-rank-refresh-partdec-masked-share-linear-proof-parameter-v1",
                        "source": "sealed-lattice/linear-proof/masked-rank-refresh-partdec-masked-share-parameters-v1",
                        "relation": "A*w + t = 0",
                        "coefficientModulus": modulus.to_string(),
                        "sourceRingDegree": POLYNOMIAL_DEGREE,
                        "proofSystemRingDegree": PART_DEC_LINEAR_PROOF_SYSTEM_RING_DEGREE,
                        "statementRows": 1,
                        "statementColumns": 2,
                        "witnessColumns": ["trusteeSecretShare", "smudgingNoise"],
                        "witnessBoundSource": "setup-secret-distribution-and-smudging-bound-certificate",
                        "witnessBoundComputation": "N*(secretShareCoefficientBound^2+smudgingNoiseCoefficientBound^2)",
                        "secretShareDistribution": "owner-routed-standard-ternary-local-share",
                        "secretShareCoefficientBound": witness_bound.secret_share_coefficient_bound,
                        "smudgingNoiseCoefficientBoundBits": witness_bound.smudging_noise_coefficient_bound_bits,
                        "smudgingNoiseCoefficientBound": witness_bound.smudging_noise_coefficient_bound_decimal.as_str(),
                        "witnessL2BoundSquared": witness_bound.witness_l2_bound_squared_decimal.as_str(),
                        "witnessL2BoundSquaredBitLength": witness_bound.witness_l2_bound_squared_bit_length,
                        "witnessL2BoundSquaredFitsProofBackend": witness_bound.witness_l2_bound_squared_fits_current_backend,
                    },
                    "proofEncodingBinding": {
                        "proofEncodingStatus": "RankRefreshPartDecMaskedShareProofEncodingPendingBecauseWitnessBoundExceedsCurrentLinearProofBackendCapacity",
                        "profileId": "masked-rank-refresh-partdec-masked-share-linear-proof-encoding-v1",
                        "source": "sealed-lattice/linear-proof/masked-rank-refresh-partdec-masked-share-encoding-v1",
                        "proofSystemRingDegree": PART_DEC_LINEAR_PROOF_SYSTEM_RING_DEGREE,
                        "sourcePolynomialSplitFactor": PART_DEC_LINEAR_PROOF_SOURCE_POLYNOMIAL_SPLIT_FACTOR,
                        "expectedShortResponseVectorLength": PART_DEC_PUBLIC_KEY_SHARE_LINEAR_PROOF_EXPECTED_SHORT_RESPONSE_VECTOR_LENGTH,
                        "matrixCoefficientRepresentation": "canonicalUnsignedSourceModulus",
                        "targetCoefficientRepresentation": "canonicalUnsignedSourceModulus",
                    }
                })
            })
            .collect::<Vec<_>>();

        json!({
            "objectType": PART_DEC_MASKED_SHARE_LINEAR_PROOF_BACKEND_INPUT_OBJECT_TYPE,
            "objectVersion": 1,
            "profileId": MASKED_RANK_REFRESH_PROFILE_ID,
            "inputStatus": "PartDecMaskedShareLinearProofBackendInputBound",
            "proofBackend": "sealed-lattice-linear-proof",
            "proofBackendStatus": "VerifierPending",
            "proofVerificationStatus": PART_DEC_MASKED_SHARE_LINEAR_PROOF_VERIFIER_PENDING_STATUS,
            "proofBytesVerified": false,
            "proofInputFormat": "masked-rank-refresh-partdec-masked-share-per-data-prime-linear-proof-input-v1",
            "relationScope": "masked-partdec-share-only",
            "publicKeyShareConsistencyRelationExcluded": true,
            "errorShareWitnessExcluded": true,
            "statementMaterialMode": "streamed-derived-from-adapter-tables",
            "sameSecretShareWitnessAsPublicKeyShareProofRequired": true,
            "sameSecretShareWitnessBindingStatus": "PublicRootsBoundWitnessProofPending",
            "splitProofObligationReason": "smudging-witness-bound-exceeds-current-linear-proof-backend-capacity",
            "setupPackageHash": proof["setupPackageHash"],
            "evaluationContextHash": proof["evaluationContextHash"],
            "inputRankCiphertextComponentOnePayloadHash": proof["inputRankCiphertextComponentOnePayloadHash"],
            "partialDecryptionShareRoot": proof["partialDecryptionShareRoot"],
            "selectedAlgebraicShareVerificationKeyBindingRoot": proof["selectedAlgebraicShareVerificationKeyBindingRoot"],
            "smudgingBoundCertificateHash": proof["smudgingBoundCertificateHash"],
            "partDecLinearRelationStatementRoot": part_dec_linear_relation_statement_root,
            "linearProofBackendAdapterRoot": adapter_root,
            "proofSystemRingDegree": PART_DEC_LINEAR_PROOF_SYSTEM_RING_DEGREE,
            "sourcePolynomialSplitFactor": PART_DEC_LINEAR_PROOF_SOURCE_POLYNOMIAL_SPLIT_FACTOR,
            "expectedShortResponseVectorLength": PART_DEC_PUBLIC_KEY_SHARE_LINEAR_PROOF_EXPECTED_SHORT_RESPONSE_VECTOR_LENGTH,
            "dataPrimeProofInputCount": DATA_PRIMES.len(),
            "proofBackendWitnessBoundCapacityBits": PART_DEC_LINEAR_PROOF_BACKEND_WITNESS_BOUND_CAPACITY_BITS,
            "witnessL2BoundSquared": witness_bound.witness_l2_bound_squared_decimal,
            "witnessL2BoundSquaredBitLength": witness_bound.witness_l2_bound_squared_bit_length,
            "witnessL2BoundSquaredFitsProofBackend": witness_bound.witness_l2_bound_squared_fits_current_backend,
            "proofBackendWitnessBoundStatus": part_dec_masked_share_linear_proof_backend_witness_bound_status(&witness_bound),
            "challengeDomainHash": challenge_domain_hash,
            "publicRandomnessSource": "challenge-domain-hash-prefix-32-bytes",
            "publicRandomnessHex": public_randomness_hex,
            "dataPrimeProofInputs": data_prime_proof_inputs,
        })
    }

    fn part_dec_split_same_witness_binding(
        proof: &Value,
        part_dec_linear_relation_statement_root: &str,
        adapter_root: &str,
        public_key_share_consistency_input_root: &str,
        public_key_share_consistency_input: &Value,
        masked_share_input_root: &str,
        masked_share_input: &Value,
    ) -> Value {
        json!({
            "objectType": PART_DEC_SPLIT_SAME_WITNESS_BINDING_OBJECT_TYPE,
            "objectVersion": 1,
            "profileId": MASKED_RANK_REFRESH_PROFILE_ID,
            "bindingScheme": "masked-rank-refresh-partdec-split-same-witness-binding-v1",
            "bindingStatus": PART_DEC_SPLIT_SAME_WITNESS_BINDING_PENDING_STATUS,
            "proofVerificationStatus": PART_DEC_SPLIT_SAME_WITNESS_VERIFIER_PENDING_STATUS,
            "proofBytesVerified": false,
            "sameSecretShareWitnessRequired": true,
            "sharedWitnessColumn": "trusteeSecretShare",
            "sameWitnessAcrossDataPrimesRequired": true,
            "rawSecretShareWitnessExported": false,
            "publicKeyShareErrorWitnessExcludedFromMaskedShareRelation": true,
            "maskedShareSmudgingWitnessExcludedFromPublicKeyShareRelation": true,
            "publicKeyShareWitnessColumns": ["trusteeSecretShare", "trusteeErrorShare"],
            "maskedShareWitnessColumns": ["trusteeSecretShare", "smudgingNoise"],
            "trusteeIdentity": proof["trusteeIdentity"],
            "rosterPosition": proof["rosterPosition"],
            "setupPackageHash": proof["setupPackageHash"],
            "evaluationContextHash": proof["evaluationContextHash"],
            "selectedAlgebraicShareVerificationKeyBindingRoot": proof["selectedAlgebraicShareVerificationKeyBindingRoot"],
            "partDecLinearRelationStatementRoot": part_dec_linear_relation_statement_root,
            "linearProofBackendAdapterRoot": adapter_root,
            "publicKeyShareConsistencyLinearProofBackendInputRoot": public_key_share_consistency_input_root,
            "maskedShareLinearProofBackendInputRoot": masked_share_input_root,
            "publicKeyShareConsistencyChallengeDomainHash": public_key_share_consistency_input["challengeDomainHash"],
            "maskedShareChallengeDomainHash": masked_share_input["challengeDomainHash"],
            "publicKeyShareConsistencyPublicRandomnessHex": public_key_share_consistency_input["publicRandomnessHex"],
            "maskedSharePublicRandomnessHex": masked_share_input["publicRandomnessHex"],
            "publicKeyShareCoefficientMaterialRoot": public_key_share_consistency_input["publicKeyShareCoefficientMaterialRoot"],
            "publicKeyShareCoefficientMaterialHash": public_key_share_consistency_input["publicKeyShareCoefficientMaterialHash"],
            "inputRankCiphertextComponentOnePayloadHash": masked_share_input["inputRankCiphertextComponentOnePayloadHash"],
            "partialDecryptionShareRoot": masked_share_input["partialDecryptionShareRoot"],
            "smudgingBoundCertificateHash": masked_share_input["smudgingBoundCertificateHash"],
            "publicKeyShareProofBackendStatus": public_key_share_consistency_input["proofBackendStatus"],
            "publicKeyShareProofVerificationStatus": public_key_share_consistency_input["proofVerificationStatus"],
            "publicKeyShareProofBytesVerified": public_key_share_consistency_input["proofBytesVerified"],
            "maskedShareProofBackendStatus": masked_share_input["proofBackendStatus"],
            "maskedShareProofVerificationStatus": masked_share_input["proofVerificationStatus"],
            "maskedShareProofBytesVerified": masked_share_input["proofBytesVerified"],
            "publicKeyShareWitnessBoundStatus": public_key_share_consistency_input["proofBackendWitnessBoundStatus"],
            "maskedShareWitnessBoundStatus": masked_share_input["proofBackendWitnessBoundStatus"],
            "publicKeyShareWitnessL2BoundSquared": public_key_share_consistency_input["witnessL2BoundSquared"],
            "maskedShareWitnessL2BoundSquared": masked_share_input["witnessL2BoundSquared"],
        })
    }

    fn part_dec_linear_proof_backend_input(
        proof: &Value,
        part_dec_linear_relation_statement_root: &str,
        part_dec_linear_relation_statement: &Value,
        smudging_bound_certificate: &Value,
    ) -> Value {
        let adapter = &part_dec_linear_relation_statement["linearProofBackendAdapter"];
        let adapter_root =
            part_dec_linear_proof_backend_adapter_root(adapter).expect("PartDec adapter root");
        let challenge_domain_hash = part_dec_linear_proof_backend_input_challenge_domain_hash(
            proof,
            part_dec_linear_relation_statement_root,
            &adapter_root,
        )
        .expect("PartDec backend input challenge-domain hash");
        let public_randomness_hex = challenge_domain_hash
            .get(..64)
            .expect("challenge-domain hash has randomness prefix")
            .to_string();
        let witness_bound =
            part_dec_witness_bound_from_smudging_certificate(smudging_bound_certificate)
                .expect("PartDec witness bound");
        let public_key_share_consistency_input =
            part_dec_public_key_share_consistency_linear_proof_backend_input(
                proof,
                part_dec_linear_relation_statement_root,
                part_dec_linear_relation_statement,
            );
        let public_key_share_consistency_input_root =
            part_dec_public_key_share_consistency_linear_proof_backend_input_root(
                &public_key_share_consistency_input,
            )
            .expect("PartDec public key-share consistency backend input root");
        let masked_share_input = part_dec_masked_share_linear_proof_backend_input(
            proof,
            part_dec_linear_relation_statement_root,
            part_dec_linear_relation_statement,
            smudging_bound_certificate,
        );
        let masked_share_input_root =
            part_dec_masked_share_linear_proof_backend_input_root(&masked_share_input)
                .expect("PartDec masked-share backend input root");
        let split_same_witness_binding = part_dec_split_same_witness_binding(
            proof,
            part_dec_linear_relation_statement_root,
            &adapter_root,
            &public_key_share_consistency_input_root,
            &public_key_share_consistency_input,
            &masked_share_input_root,
            &masked_share_input,
        );
        let split_same_witness_binding_root =
            part_dec_split_same_witness_binding_root(&split_same_witness_binding)
                .expect("PartDec split same-witness binding root");
        let data_prime_proof_inputs = adapter["adapterTables"]
            .as_array()
            .expect("adapter tables")
            .iter()
            .enumerate()
            .map(|(modulus_index, adapter_table)| {
                let modulus = DATA_PRIMES[modulus_index];
                json!({
                    "modulusIndex": modulus_index,
                    "modulus": modulus,
                    "publicCommonRandomPolynomialHash512": adapter_table["publicCommonRandomPolynomialHash512"],
                    "publicKeyShareComponentZeroHash512": adapter_table["publicKeyShareComponentZeroHash512"],
                    "inputRankCiphertextComponentOneHash512": adapter_table["inputRankCiphertextComponentOneHash512"],
                    "partialDecryptionShareHash512": adapter_table["partialDecryptionShareHash512"],
                    "sourceMatrixHash512": adapter_table["sourceMatrixHash512"],
                    "targetVectorHash512": adapter_table["targetVectorHash512"],
                    "proofParameterBinding": {
                        "parameterProfileStatus": "RankRefreshPartDecParameterProfilePending",
                        "profileId": "masked-rank-refresh-partdec-linear-proof-parameter-v1",
                        "source": "sealed-lattice/linear-proof/masked-rank-refresh-partdec-parameters-v1",
                        "relation": "A*w + t = 0",
                        "coefficientModulus": modulus.to_string(),
                        "sourceRingDegree": POLYNOMIAL_DEGREE,
                        "proofSystemRingDegree": PART_DEC_LINEAR_PROOF_SYSTEM_RING_DEGREE,
                        "statementRows": 2,
                        "statementColumns": 3,
                        "witnessColumns": ["trusteeSecretShare", "trusteeErrorShare", "smudgingNoise"],
                        "witnessBoundSource": PART_DEC_WITNESS_BOUND_SOURCE,
                        "witnessBoundComputation": PART_DEC_WITNESS_BOUND_COMPUTATION,
                        "secretShareDistribution": "owner-routed-standard-ternary-local-share",
                        "secretShareCoefficientBound": witness_bound.secret_share_coefficient_bound,
                        "errorShareDistribution": "owner-routed-centered-binomial-eta2-collective-error",
                        "errorShareCoefficientBound": witness_bound.error_share_coefficient_bound,
                        "smudgingNoiseCoefficientBoundBits": witness_bound.smudging_noise_coefficient_bound_bits,
                        "smudgingNoiseCoefficientBound": witness_bound.smudging_noise_coefficient_bound_decimal.as_str(),
                        "witnessL2BoundSquared": witness_bound.witness_l2_bound_squared_decimal.as_str(),
                    },
                    "proofEncodingBinding": {
                        "proofEncodingStatus": "RankRefreshPartDecProofEncodingPending",
                        "profileId": "masked-rank-refresh-partdec-linear-proof-encoding-v1",
                        "source": "sealed-lattice/linear-proof/masked-rank-refresh-partdec-encoding-v1",
                        "proofSystemRingDegree": PART_DEC_LINEAR_PROOF_SYSTEM_RING_DEGREE,
                        "sourcePolynomialSplitFactor": PART_DEC_LINEAR_PROOF_SOURCE_POLYNOMIAL_SPLIT_FACTOR,
                        "expectedShortResponseVectorLength": PART_DEC_LINEAR_PROOF_EXPECTED_SHORT_RESPONSE_VECTOR_LENGTH,
                        "matrixCoefficientRepresentation": "canonicalUnsignedSourceModulus",
                        "targetCoefficientRepresentation": "canonicalUnsignedSourceModulus",
                    }
                })
            })
            .collect::<Vec<_>>();

        json!({
            "objectType": "MaskedRankRefreshPartDecLinearProofBackendInput",
            "objectVersion": 1,
            "profileId": MASKED_RANK_REFRESH_PROFILE_ID,
            "inputStatus": "PartDecLinearProofBackendInputBound",
            "proofBackend": "sealed-lattice-linear-proof",
            "proofBackendStatus": "VerifierPending",
            "proofInputFormat": "masked-rank-refresh-partdec-per-data-prime-linear-proof-input-v1",
            "proofBytesSource": "partDecShareEquationProof.proofBytesHex",
            "statementMaterialMode": "streamed-derived-from-adapter-tables",
            "sameWitnessAcrossDataPrimesRequired": true,
            "sameWitnessBindingStatus": "PublicRootsBoundWitnessProofPending",
            "splitProofObligationsRequired": true,
            "splitProofObligationReason": "smudging-witness-bound-exceeds-current-linear-proof-backend-capacity",
            "publicKeyShareConsistencyProofInputStatus": "PartDecPublicKeyShareConsistencyLinearProofBackendInputBound",
            "maskedPartDecShareProofInputStatus": "PartDecMaskedShareLinearProofBackendInputBound",
            "setupPackageHash": proof["setupPackageHash"],
            "evaluationContextHash": proof["evaluationContextHash"],
            "inputRankCiphertextComponentOnePayloadHash": proof["inputRankCiphertextComponentOnePayloadHash"],
            "partialDecryptionShareRoot": proof["partialDecryptionShareRoot"],
            "selectedAlgebraicShareVerificationKeyBindingRoot": proof["selectedAlgebraicShareVerificationKeyBindingRoot"],
            "smudgingBoundCertificateHash": proof["smudgingBoundCertificateHash"],
            "partDecLinearRelationStatementRoot": part_dec_linear_relation_statement_root,
            "linearProofBackendAdapterRoot": adapter_root,
            "proofSystemRingDegree": PART_DEC_LINEAR_PROOF_SYSTEM_RING_DEGREE,
            "sourcePolynomialSplitFactor": PART_DEC_LINEAR_PROOF_SOURCE_POLYNOMIAL_SPLIT_FACTOR,
            "expectedShortResponseVectorLength": PART_DEC_LINEAR_PROOF_EXPECTED_SHORT_RESPONSE_VECTOR_LENGTH,
            "dataPrimeProofInputCount": DATA_PRIMES.len(),
            "proofBackendWitnessBoundCapacityBits": PART_DEC_LINEAR_PROOF_BACKEND_WITNESS_BOUND_CAPACITY_BITS,
            "witnessL2BoundSquaredBitLength": witness_bound.witness_l2_bound_squared_bit_length,
            "witnessL2BoundSquaredFitsProofBackend": witness_bound.witness_l2_bound_squared_fits_current_backend,
            "proofBackendWitnessBoundStatus": part_dec_linear_proof_backend_witness_bound_status(&witness_bound),
            "challengeDomainHash": challenge_domain_hash,
            "publicRandomnessSource": "challenge-domain-hash-prefix-32-bytes",
            "publicRandomnessHex": public_randomness_hex,
            "publicKeyShareConsistencyLinearProofBackendInputRoot": public_key_share_consistency_input_root,
            "publicKeyShareConsistencyLinearProofBackendInput": public_key_share_consistency_input,
            "maskedShareLinearProofBackendInputRoot": masked_share_input_root,
            "maskedShareLinearProofBackendInput": masked_share_input,
            "splitSameWitnessBindingRoot": split_same_witness_binding_root,
            "splitSameWitnessBinding": split_same_witness_binding,
            "dataPrimeProofInputs": data_prime_proof_inputs,
        })
    }

    fn generated_setup_package() -> Value {
        SETUP_PACKAGE
            .get_or_init(|| {
                generate_passive_setup_package_from_request(&json!({
                    "ceremonyId": "rank-refresh-ceremony",
                    "manifestHash": hash("a"),
                    "rosterHash": hash("b"),
                    "thresholdProfileHash": hash("c"),
                    "setupSeed": "rank-refresh-setup-seed",
                    "participants": [
                        {
                            "trusteeIdentity": "trustee-1",
                            "rosterPosition": 0,
                            "boardPosition": 3
                        },
                        {
                            "trusteeIdentity": "trustee-2",
                            "rosterPosition": 1,
                            "boardPosition": 4
                        },
                        {
                            "trusteeIdentity": "trustee-3",
                            "rosterPosition": 2,
                            "boardPosition": 5
                        }
                    ]
                }))
                .expect("setup package")
            })
            .clone()
    }

    fn public_key_share_coefficient_material_sidecars(setup_package: &Value) -> Vec<Value> {
        canonical_threshold_participants(setup_package)
            .iter()
            .map(|participant| {
                let trustee_identity = participant["trusteeIdentity"]
                    .as_str()
                    .expect("trustee identity");
                trustee_public_key_share_coefficient_material_from_setup_witness(
                    setup_package,
                    "rank-refresh-setup-seed",
                    trustee_identity,
                )
                .expect("public key-share coefficient material sidecar")
            })
            .collect()
    }

    fn canonical_threshold_participants(setup_package: &Value) -> Vec<Value> {
        let decryption_threshold = usize::try_from(
            setup_decryption_threshold(setup_package).expect("setup decryption threshold"),
        )
        .expect("setup decryption threshold fits usize");
        let mut participants = setup_package["participants"]
            .as_array()
            .expect("participants")
            .to_vec();
        participants.sort_by(|left, right| {
            left["boardPosition"]
                .as_u64()
                .expect("left board position")
                .cmp(
                    &right["boardPosition"]
                        .as_u64()
                        .expect("right board position"),
                )
                .then_with(|| {
                    left["rosterPosition"]
                        .as_u64()
                        .expect("left roster position")
                        .cmp(
                            &right["rosterPosition"]
                                .as_u64()
                                .expect("right roster position"),
                        )
                })
                .then_with(|| {
                    left["trusteeIdentity"]
                        .as_str()
                        .expect("left trustee identity")
                        .cmp(
                            right["trusteeIdentity"]
                                .as_str()
                                .expect("right trustee identity"),
                        )
                })
        });
        participants.truncate(decryption_threshold);

        participants
    }

    fn share_selection_rule(setup_package: &Value) -> Value {
        let selected_participants = canonical_threshold_participants(setup_package);
        let selected_trustee_identities = selected_participants
            .iter()
            .map(|participant| participant["trusteeIdentity"].clone())
            .collect::<Vec<_>>();
        let selected_roster_positions = selected_participants
            .iter()
            .map(|participant| participant["rosterPosition"].clone())
            .collect::<Vec<_>>();
        let participant_count = setup_package["participants"]
            .as_array()
            .expect("participants")
            .len();
        let selected_share_count = selected_trustee_identities.len();

        json!({
            "objectType": "MaskedRankRefreshShareSelectionRule",
            "objectVersion": 1,
            "profileId": MASKED_RANK_REFRESH_PROFILE_ID,
            "setupPackageHash": setup_package["setupPackageHash"],
            "thresholdProfileHash": setup_package["setupInputs"]["thresholdProfileHash"],
            "thresholdShareVerificationKeyHash": setup_package["thresholdVerificationMaterial"]["thresholdShareVerificationKeyHash"],
            "algebraicShareVerificationKeyHash": setup_package["thresholdVerificationMaterial"]["algebraicShareVerificationKeyHash"],
            "selectedShareRule": "FirstValidSharesInCanonicalBoardOrder",
            "invalidShareFilteringMode": "ProofVerifiedSharesOnly",
            "participantCount": participant_count,
            "decryptionThreshold": selected_share_count,
            "selectedShareCount": selected_share_count,
            "minimumSharesForInterpolation": selected_share_count,
            "selectedTrusteeIdentities": selected_trustee_identities,
            "selectedRosterPositions": selected_roster_positions
        })
    }

    fn share_selection_validation_transcript(setup_package: &Value) -> Value {
        let share_records = canonical_threshold_participants(setup_package)
            .iter()
            .map(|participant| {
                json!({
                    "trusteeIdentity": participant["trusteeIdentity"],
                    "rosterPosition": participant["rosterPosition"]
                })
            })
            .collect::<Vec<_>>();

        json!({
            "setupPackageHash": setup_package["setupPackageHash"],
            "thresholdShareVerificationKeyHash": setup_package["thresholdVerificationMaterial"]["thresholdShareVerificationKeyHash"],
            "algebraicShareVerificationKeyHash": setup_package["thresholdVerificationMaterial"]["algebraicShareVerificationKeyHash"],
            "shareSelectionRule": share_selection_rule(setup_package),
            "rankRefreshShareRecords": share_records
        })
    }

    fn smudging_bound_certificate(
        setup_package: &Value,
        share_selection_rule_hash: &str,
        input_rank_ciphertext_root: &str,
        fin_dec_lagrange_coefficient_audit_root: &str,
        fin_dec_lagrange_coefficient_audit: &Value,
    ) -> Value {
        let data_modulus_bits = data_basis_modulus_bits();
        let plaintext_modulus_bits = modulus_bit_length(PLAINTEXT_MODULUS);
        let selected_share_count = fin_dec_lagrange_coefficient_audit["selectedShareCount"]
            .as_u64()
            .expect("selected share count");
        let maximum_lagrange_coefficient_bits =
            fin_dec_lagrange_coefficient_audit["maximumLagrangeCoefficientBits"]
                .as_u64()
                .expect("maximum Lagrange coefficient bits");
        let partial_decryption_share_noise_bound_bits = 590_u64;
        let selected_share_combination_bound_bits = partial_decryption_share_noise_bound_bits
            + maximum_lagrange_coefficient_bits
            + ceil_log2_u64(selected_share_count);
        let input_ciphertext_component_zero_noise_bound_bits = 639_u64;
        let final_noise_bound_bits = input_ciphertext_component_zero_noise_bound_bits
            .max(selected_share_combination_bound_bits)
            + 1;
        let correctness_margin_bits = u64::try_from(data_modulus_bits)
            .expect("data modulus bit accounting fits u64")
            - final_noise_bound_bits
            - u64::from(plaintext_modulus_bits)
            - 1;
        let mut certificate = json!({
            "objectType": "MaskedRankRefreshSmudgingBoundCertificate",
            "objectVersion": 1,
            "profileId": MASKED_RANK_REFRESH_PROFILE_ID,
            "boundProfileId": "masked-rank-refresh-smudging-bound-v1",
            "boundStatementStatus": "SmudgingNoiseBoundStatementBound",
            "boundProofVerificationStatus": "SmudgingNoiseBoundProofPending",
            "boundProofBytesVerified": false,
            "appendixBBoundRequired": true,
            "correctnessInequality": "B_final < Q_data/(2*p)",
            "smudgingDistributionStatus": "AppendixBSmudgingDistributionPending",
            "minimumCorrectnessFailureProbabilityBits": 128,
            "boundArithmetic": "ceil-log2-bit-budget",
            "dataModulusBits": data_modulus_bits,
            "plaintextModulusBits": plaintext_modulus_bits,
            "selectedShareCount": selected_share_count,
            "maximumLagrangeCoefficientBits": maximum_lagrange_coefficient_bits,
            "partialDecryptionShareNoiseBoundBits": partial_decryption_share_noise_bound_bits,
            "selectedShareCombinationBoundBits": selected_share_combination_bound_bits,
            "inputCiphertextComponentZeroNoiseBoundBits": input_ciphertext_component_zero_noise_bound_bits,
            "finalNoiseBoundBits": final_noise_bound_bits,
            "correctnessMarginBits": correctness_margin_bits,
            "polynomialDegree": POLYNOMIAL_DEGREE,
            "dataPrimeCount": crate::bgv::profile::DATA_PRIMES.len(),
            "plaintextModulus": crate::bgv::profile::PLAINTEXT_MODULUS,
            "setupPackageHash": setup_package["setupPackageHash"],
            "evaluationContextHash": hash("1"),
            "inputRankCiphertextRoot": input_rank_ciphertext_root,
            "finDecLagrangeCoefficientAuditRoot": fin_dec_lagrange_coefficient_audit_root,
            "shareSelectionRuleHash": share_selection_rule_hash,
            "thresholdShareVerificationKeyHash": setup_package["thresholdVerificationMaterial"]["thresholdShareVerificationKeyHash"],
            "algebraicShareVerificationKeyHash": setup_package["thresholdVerificationMaterial"]["algebraicShareVerificationKeyHash"],
        });
        bind_smudging_bound_proof_bytes(
            &mut certificate,
            "masked rank refresh smudging proof bytes",
        );

        certificate
    }

    fn selected_algebraic_share_verification_key_bindings(
        setup_package: &Value,
        share_selection_rule_hash: &str,
    ) -> Vec<Value> {
        let algebraic_trustee_keys = setup_package["thresholdVerificationMaterial"]
            ["verificationKeySet"]["algebraicShareVerificationKeySet"]["trusteeVerificationKeys"]
            .as_array()
            .expect("algebraic trustee keys");
        canonical_threshold_participants(setup_package)
            .iter()
            .enumerate()
            .map(|(selected_share_index, participant)| {
                let trustee_identity = participant["trusteeIdentity"]
                    .as_str()
                    .expect("trustee identity");
                let roster_position = participant["rosterPosition"]
                    .as_u64()
                    .expect("roster position");
                let algebraic_trustee_key = algebraic_trustee_keys
                    .iter()
                    .find(|trustee_key| {
                        trustee_key["trusteeIdentity"].as_str() == Some(trustee_identity)
                            && trustee_key["rosterPosition"].as_u64() == Some(roster_position)
                    })
                    .expect("algebraic trustee key");
                json!({
                    "objectType": "MaskedRankRefreshSelectedAlgebraicShareVerificationKeyBinding",
                    "objectVersion": 1,
                    "profileId": MASKED_RANK_REFRESH_PROFILE_ID,
                    "bindingStatus": "SelectedAlgebraicShareVerificationKeyBound",
                    "proofSystemStatus": "ZeroKnowledgeShareEquationProofPending",
                    "selectedShareIndex": selected_share_index,
                    "setupPackageHash": setup_package["setupPackageHash"],
                    "shareSelectionRuleHash": share_selection_rule_hash,
                    "thresholdShareVerificationKeyRoot": setup_package["thresholdVerificationMaterial"]["thresholdShareVerificationKeyRoot"],
                    "thresholdShareVerificationKeyHash": setup_package["thresholdVerificationMaterial"]["thresholdShareVerificationKeyHash"],
                    "algebraicShareVerificationKeyRoot": setup_package["thresholdVerificationMaterial"]["algebraicShareVerificationKeyRoot"],
                    "algebraicShareVerificationKeyHash": setup_package["thresholdVerificationMaterial"]["algebraicShareVerificationKeyHash"],
                    "trusteeIdentity": participant["trusteeIdentity"],
                    "rosterPosition": participant["rosterPosition"],
                    "interpolationPoint": algebraic_trustee_key["interpolationPoint"],
                    "participantSetupRecordHash": participant["participantSetupRecordHash"],
                    "publicKeyShareRoot": participant["publicKeyShareRoot"],
                    "publicKeyShareCoefficientMaterialRoot": algebraic_trustee_key["publicKeyShareCoefficientMaterialRoot"],
                    "publicKeyShareCoefficientMaterialHash": algebraic_trustee_key["publicKeyShareCoefficientMaterialHash"],
                    "publicKeyShareCoefficientMaterialIncluded": false,
                    "publicKeyShareCoefficientMaterialTransport": "root-bound-public-sidecar-required-for-claim-bearing-PartDec-verification",
                    "trusteeThresholdVerificationKeyHash": participant["trusteeThresholdVerificationKeyHash"],
                    "localSecretShareCommitmentHash": participant["localSecretShareCommitmentHash"],
                    "localErrorCommitmentHash": participant["localErrorCommitmentHash"],
                    "thresholdLsssWitnessCommitmentHash": algebraic_trustee_key["thresholdLsssWitnessCommitmentHash"],
                    "publicKeyShareConsistencyEquation": "publicKeyShareComponentZero + publicCommonRandomPolynomial * trusteeSecretShare = plaintextModulus * trusteeErrorShare mod q",
                    "partDecShareEquation": "partialDecryptionShare = ciphertextComponentOne * trusteeSecretShare + smudgingNoise mod q",
                    "shareEquationProofRequired": true,
                    "rawSecretShareExported": false,
                    "thresholdSecretShareExported": false,
                })
            })
            .collect()
    }

    fn selected_algebraic_share_verification_key_binding_root(binding: &Value) -> String {
        crate::hashing::derive_protocol_hash(
            "MaskedRankRefreshSelectedAlgebraicShareVerificationKeyBindingRoot",
            binding,
        )
        .expect("selected algebraic share-verification key binding root")
    }

    fn fin_dec_lagrange_coefficient_audit(
        setup_package: &Value,
        share_selection_rule_hash: &str,
        input_rank_ciphertext_root: &str,
        selected_algebraic_share_verification_key_bindings: &[Value],
    ) -> Value {
        let selected_trustee_identities = selected_algebraic_share_verification_key_bindings
            .iter()
            .map(|binding| binding["trusteeIdentity"].clone())
            .collect::<Vec<_>>();
        let selected_roster_positions = selected_algebraic_share_verification_key_bindings
            .iter()
            .map(|binding| binding["rosterPosition"].clone())
            .collect::<Vec<_>>();
        let selected_algebraic_share_verification_key_binding_roots =
            selected_algebraic_share_verification_key_bindings
                .iter()
                .map(|binding| {
                    Value::String(selected_algebraic_share_verification_key_binding_root(
                        binding,
                    ))
                })
                .collect::<Vec<_>>();
        let mut maximum_lagrange_coefficient_bits = 0_u64;
        let coefficient_tables = crate::bgv::profile::DATA_PRIMES
            .iter()
            .copied()
            .enumerate()
            .map(|(modulus_index, modulus)| {
                let lagrange_coefficients = lagrange_coefficients_for_selected_share_records(
                    selected_algebraic_share_verification_key_bindings,
                    modulus,
                )
                .expect("Lagrange coefficients");
                let table_maximum_lagrange_coefficient_bits = lagrange_coefficients
                    .iter()
                    .copied()
                    .map(modulus_bit_length)
                    .max()
                    .map(u64::from)
                    .unwrap_or(0);
                maximum_lagrange_coefficient_bits =
                    maximum_lagrange_coefficient_bits.max(table_maximum_lagrange_coefficient_bits);
                let lagrange_coefficient_entries =
                    selected_algebraic_share_verification_key_bindings
                        .iter()
                        .zip(lagrange_coefficients)
                        .map(|(binding, coefficient)| {
                            let roster_position =
                                binding["rosterPosition"].as_u64().expect("roster position");
                            json!({
                                "trusteeIdentity": binding["trusteeIdentity"],
                                "rosterPosition": roster_position,
                                "interpolationPoint": roster_position + 1,
                                "coefficient": coefficient,
                            })
                        })
                        .collect::<Vec<_>>();
                json!({
                    "modulusIndex": modulus_index,
                    "modulus": modulus,
                    "coefficientEncoding": "u64-canonical-residue",
                    "maximumLagrangeCoefficientBits": table_maximum_lagrange_coefficient_bits,
                    "lagrangeCoefficientEntries": lagrange_coefficient_entries,
                })
            })
            .collect::<Vec<_>>();

        json!({
            "objectType": "MaskedRankRefreshFinDecLagrangeCoefficientAudit",
            "objectVersion": 1,
            "profileId": MASKED_RANK_REFRESH_PROFILE_ID,
            "auditStatus": "SelectedShareLagrangeCoefficientAuditBound",
            "combinationRule": "LagrangeInterpolationOverSelectedShares",
            "interpolationPointKind": "roster-position-plus-one",
            "lagrangeCoefficientDomain": "per-data-prime-canonical-residue",
            "coefficientEncoding": "u64-canonical-residue-by-data-prime",
            "basisId": "data",
            "polynomialDegree": POLYNOMIAL_DEGREE,
            "dataPrimeCount": crate::bgv::profile::DATA_PRIMES.len(),
            "coefficientTableCount": crate::bgv::profile::DATA_PRIMES.len(),
            "plaintextModulus": crate::bgv::profile::PLAINTEXT_MODULUS,
            "setupPackageHash": setup_package["setupPackageHash"],
            "evaluationContextHash": hash("1"),
            "inputRankCiphertextRoot": input_rank_ciphertext_root,
            "shareSelectionRuleHash": share_selection_rule_hash,
            "thresholdShareVerificationKeyHash": setup_package["thresholdVerificationMaterial"]["thresholdShareVerificationKeyHash"],
            "algebraicShareVerificationKeyHash": setup_package["thresholdVerificationMaterial"]["algebraicShareVerificationKeyHash"],
            "selectedShareCount": selected_algebraic_share_verification_key_bindings.len(),
            "selectedTrusteeIdentities": selected_trustee_identities,
            "selectedRosterPositions": selected_roster_positions,
            "selectedAlgebraicShareVerificationKeyBindingRoots": selected_algebraic_share_verification_key_binding_roots,
            "maximumLagrangeCoefficientBits": maximum_lagrange_coefficient_bits,
            "coefficientTables": coefficient_tables,
        })
    }

    fn rank_refresh_share_records(inputs: RankRefreshShareRecordFixture<'_>) -> Vec<Value> {
        let RankRefreshShareRecordFixture {
            setup_package,
            input_rank_ciphertext_root,
            input_rank_ciphertext_component_one_payload_hash,
            input_rank_ciphertext_component_one_payload,
            smudging_bound_certificate_hash,
            smudging_bound_certificate,
            public_key_share_coefficient_material_sidecars,
            selected_algebraic_share_verification_key_bindings,
        } = inputs;
        let algebraic_trustee_keys = setup_package["thresholdVerificationMaterial"]
            ["verificationKeySet"]["algebraicShareVerificationKeySet"]["trusteeVerificationKeys"]
            .as_array()
            .expect("algebraic trustee keys");
        canonical_threshold_participants(setup_package)
            .iter()
            .map(|participant| {
                let trustee_identity = participant["trusteeIdentity"]
                    .as_str()
                    .expect("trustee identity");
                let roster_position = participant["rosterPosition"]
                    .as_u64()
                    .expect("roster position");
                let public_key_share_coefficient_material_sidecar =
                    public_key_share_coefficient_material_sidecars
                        .iter()
                        .find(|sidecar| {
                            sidecar["trusteeIdentity"].as_str() == Some(trustee_identity)
                                && sidecar["rosterPosition"].as_u64() == Some(roster_position)
                        })
                        .expect("public key-share coefficient material sidecar");
                let algebraic_trustee_key = algebraic_trustee_keys
                    .iter()
                    .find(|trustee_key| {
                        trustee_key["trusteeIdentity"].as_str() == Some(trustee_identity)
                            && trustee_key["rosterPosition"].as_u64() == Some(roster_position)
                })
                .expect("algebraic trustee key");
                let selected_algebraic_share_verification_key_binding =
                    selected_algebraic_share_verification_key_bindings
                        .iter()
                        .find(|binding| {
                            binding["trusteeIdentity"].as_str() == Some(trustee_identity)
                                && binding["rosterPosition"].as_u64() == Some(roster_position)
                        })
                        .expect("selected algebraic share-verification key binding");
                let selected_algebraic_share_verification_key_binding_root =
                    selected_algebraic_share_verification_key_binding_root(
                        selected_algebraic_share_verification_key_binding,
                    );
                let share_freshness_hash = hash("f");
                let partial_decryption_share_payload = partial_decryption_share_payload(
                    setup_package,
                    participant,
                    algebraic_trustee_key,
                    input_rank_ciphertext_root,
                    input_rank_ciphertext_component_one_payload_hash,
                    smudging_bound_certificate_hash,
                    &share_freshness_hash,
                );
                let partial_decryption_share_root = crate::hashing::derive_protocol_hash(
                    "MaskedRankRefreshPartialDecryptionShareRoot",
                    &partial_decryption_share_payload,
                )
                .expect("partial-decryption share root");
                let part_dec_linear_relation_statement = part_dec_linear_relation_statement(
                    PartDecLinearRelationStatementFixture {
                        setup_package,
                        participant,
                        algebraic_trustee_key,
                        public_key_share_coefficient_material_sidecar,
                        input_rank_ciphertext_root,
                        input_rank_ciphertext_component_one_payload_hash,
                        input_rank_ciphertext_component_one_payload,
                        partial_decryption_share_root: &partial_decryption_share_root,
                        partial_decryption_share_payload: &partial_decryption_share_payload,
                        selected_algebraic_share_verification_key_binding_root:
                            &selected_algebraic_share_verification_key_binding_root,
                        smudging_bound_certificate_hash,
                        share_freshness_hash: &share_freshness_hash,
                    },
                );
                let part_dec_linear_relation_statement_root = crate::hashing::derive_protocol_hash(
                    "MaskedRankRefreshPartDecLinearRelationStatementRoot",
                    &part_dec_linear_relation_statement,
                )
                .expect("PartDec linear relation statement root");
                let mut share_equation_proof = json!({
                    "objectType": "MaskedRankRefreshPartDecShareEquationProof",
                    "objectVersion": 1,
                    "profileId": MASKED_RANK_REFRESH_PROFILE_ID,
                    "proofStatementFormat": "masked-rank-refresh-partdec-share-equation-v1",
                    "proofVerificationStatus": "ZeroKnowledgePartDecVerifierPending",
                    "proofBytesVerified": false,
                    "rawWitnessExported": false,
                    "semanticRankOpeningAllowed": false,
                    "smudgingBoundCertificateRequired": true,
                    "ciphertextComponentRole": "ciphertext-component-one",
                    "shareEquation": "partialDecryptionShare = ciphertextComponentOne * trusteeSecretShare + smudgingNoise mod q",
                    "setupPackageHash": setup_package["setupPackageHash"],
                    "evaluationContextHash": hash("1"),
                    "inputRankCiphertextRoot": input_rank_ciphertext_root,
                    "inputRankCiphertextComponentOnePayloadHash": input_rank_ciphertext_component_one_payload_hash,
                    "thresholdShareVerificationKeyHash": setup_package["thresholdVerificationMaterial"]["thresholdShareVerificationKeyHash"],
                    "algebraicShareVerificationKeyRoot": setup_package["thresholdVerificationMaterial"]["algebraicShareVerificationKeyRoot"],
                    "algebraicShareVerificationKeyHash": setup_package["thresholdVerificationMaterial"]["algebraicShareVerificationKeyHash"],
                    "trusteeIdentity": participant["trusteeIdentity"],
                    "rosterPosition": participant["rosterPosition"],
                    "participantSetupRecordHash": participant["participantSetupRecordHash"],
                    "publicKeyShareRoot": participant["publicKeyShareRoot"],
                    "selectedAlgebraicShareVerificationKeyBindingRoot": selected_algebraic_share_verification_key_binding_root,
                    "publicKeyShareCoefficientMaterialRoot": algebraic_trustee_key["publicKeyShareCoefficientMaterialRoot"],
                    "publicKeyShareCoefficientMaterialHash": algebraic_trustee_key["publicKeyShareCoefficientMaterialHash"],
                    "trusteeThresholdVerificationKeyHash": participant["trusteeThresholdVerificationKeyHash"],
                    "localSecretShareCommitmentHash": participant["localSecretShareCommitmentHash"],
                    "localErrorCommitmentHash": participant["localErrorCommitmentHash"],
                    "thresholdLsssWitnessCommitmentHash": algebraic_trustee_key["thresholdLsssWitnessCommitmentHash"],
                    "partialDecryptionShareRoot": partial_decryption_share_root,
                    "shareFreshnessHash": share_freshness_hash,
                    "smudgingBoundCertificateHash": smudging_bound_certificate_hash,
                    "partDecLinearRelationStatementRoot": part_dec_linear_relation_statement_root,
                    "partDecLinearRelationStatement": part_dec_linear_relation_statement,
                });
                bind_standard_proof_bytes(
                    &mut share_equation_proof,
                    "MaskedRankRefreshPartDecShareEquationProofStatementHash",
                    &PART_DEC_PROOF_METADATA_FIELDS,
                    &format!("masked rank refresh PartDec proof bytes {trustee_identity}"),
                );
                let linear_proof_backend_input = part_dec_linear_proof_backend_input(
                    &share_equation_proof,
                    &part_dec_linear_relation_statement_root,
                    &part_dec_linear_relation_statement,
                    smudging_bound_certificate,
                );
                let linear_proof_backend_input_root = crate::hashing::derive_protocol_hash(
                    "MaskedRankRefreshPartDecLinearProofBackendInputRoot",
                    &linear_proof_backend_input,
                )
                .expect("PartDec linear proof backend input root");
                share_equation_proof["linearProofBackendInputRoot"] =
                    Value::String(linear_proof_backend_input_root);
                share_equation_proof["linearProofBackendInput"] = linear_proof_backend_input;
                rebind_part_dec_proof_statement_hash(&mut share_equation_proof);
                let share_equation_proof_root = crate::hashing::derive_protocol_hash(
                    "MaskedRankRefreshPartDecShareEquationProofRoot",
                    &share_equation_proof,
                )
                .expect("share equation proof root");
                json!({
                    "objectType": "MaskedRankRefreshShareRecord",
                    "objectVersion": 1,
                    "profileId": MASKED_RANK_REFRESH_PROFILE_ID,
                    "trusteeIdentity": participant["trusteeIdentity"],
                    "rosterPosition": participant["rosterPosition"],
                    "participantSetupRecordHash": participant["participantSetupRecordHash"],
                    "selectedAlgebraicShareVerificationKeyBindingRoot": selected_algebraic_share_verification_key_binding_root,
                    "publicKeyShareCoefficientMaterialRoot": algebraic_trustee_key["publicKeyShareCoefficientMaterialRoot"],
                    "publicKeyShareCoefficientMaterialHash": algebraic_trustee_key["publicKeyShareCoefficientMaterialHash"],
                    "evaluationContextHash": hash("1"),
                    "inputRankCiphertextRoot": input_rank_ciphertext_root,
                    "trusteeThresholdVerificationKeyHash": participant["trusteeThresholdVerificationKeyHash"],
                    "thresholdShareVerificationKeyRoot": setup_package["thresholdVerificationMaterial"]["thresholdShareVerificationKeyRoot"],
                    "thresholdShareVerificationKeyHash": setup_package["thresholdVerificationMaterial"]["thresholdShareVerificationKeyHash"],
                    "algebraicShareVerificationKeyHash": setup_package["thresholdVerificationMaterial"]["algebraicShareVerificationKeyHash"],
                    "partialDecryptionShareRoot": partial_decryption_share_root,
                    "partialDecryptionSharePayload": partial_decryption_share_payload,
                    "shareEquationProofRoot": share_equation_proof_root,
                    "shareEquationProof": share_equation_proof,
                    "shareFreshnessHash": share_freshness_hash,
                    "smudgingBoundCertificateHash": smudging_bound_certificate_hash,
                    "shareProofStatus": "AlgebraicPartDecShareEquationProofStatementBound",
                    "rawShareMaterialExported": false
                })
            })
            .collect()
    }

    fn fin_dec_masked_opening_payload(
        setup_package: &Value,
        share_selection_rule_hash: &str,
        share_records: &[Value],
        smudging_bound_certificate_hash: &str,
        fin_dec_lagrange_coefficient_audit_root: &str,
        input_rank_ciphertext_root: &str,
        input_rank_ciphertext_component_one_payload: &Value,
    ) -> Value {
        let input_rank_ciphertext = parse_bgv_object_hex(
            input_rank_ciphertext_component_one_payload["canonicalBytesHex"]
                .as_str()
                .expect("input rank canonical bytes"),
        )
        .expect("input rank ciphertext");
        let input_rank_ciphertext_component_zero = &input_rank_ciphertext.components[0];
        let selected_trustee_identities = share_records
            .iter()
            .map(|record| record["trusteeIdentity"].clone())
            .collect::<Vec<_>>();
        let selected_roster_positions = share_records
            .iter()
            .map(|record| record["rosterPosition"].clone())
            .collect::<Vec<_>>();
        let partial_decryption_share_roots = share_records
            .iter()
            .map(|record| record["partialDecryptionShareRoot"].clone())
            .collect::<Vec<_>>();
        let selected_algebraic_share_verification_key_binding_roots = share_records
            .iter()
            .map(|record| record["selectedAlgebraicShareVerificationKeyBindingRoot"].clone())
            .collect::<Vec<_>>();
        let coefficient_tables = crate::bgv::profile::DATA_PRIMES
            .iter()
            .copied()
            .enumerate()
            .map(|(modulus_index, modulus)| {
                let lagrange_coefficients =
                    lagrange_coefficients_for_selected_share_records(share_records, modulus)
                        .expect("Lagrange coefficients");
                let coefficients = combine_partial_decryption_share_coefficients(
                    share_records,
                    modulus_index,
                    modulus,
                    &lagrange_coefficients,
                )
                .expect("combined masked-opening coefficients");
                let component_zero_coefficients =
                    input_ciphertext_component_zero_coefficients_for_modulus(
                        input_rank_ciphertext_component_zero,
                        modulus_index,
                        modulus,
                    )
                    .expect("input ciphertext component zero coefficients");
                let coefficients = component_zero_coefficients
                    .iter()
                    .zip(coefficients)
                    .map(|(component_zero_coefficient, partial_share_combination_coefficient)| {
                        add_mod(
                            *component_zero_coefficient,
                            partial_share_combination_coefficient,
                            modulus,
                        )
                        .expect("masked-opening coefficient")
                    })
                    .collect::<Vec<_>>();
                let lagrange_coefficient_entries = share_records
                    .iter()
                    .zip(lagrange_coefficients)
                    .map(|(record, coefficient)| {
                        let roster_position = record["rosterPosition"]
                            .as_u64()
                            .expect("roster position");
                        json!({
                            "trusteeIdentity": record["trusteeIdentity"],
                            "rosterPosition": roster_position,
                            "interpolationPoint": roster_position + 1,
                            "coefficient": coefficient,
                        })
                    })
                    .collect::<Vec<_>>();
                json!({
                    "modulusIndex": modulus_index,
                    "modulus": modulus,
                    "coefficientEncoding": "little-endian-u64",
                    "maskedOpeningCoefficientsLeHex": coefficient_vector_le_hex(&coefficients),
                    "maskedOpeningCoefficientHash512": fin_dec_masked_opening_coefficient_hash(&coefficients),
                    "coefficientByteLength": POLYNOMIAL_DEGREE * 8,
                    "lagrangeCoefficientEntries": lagrange_coefficient_entries,
                })
            })
            .collect::<Vec<_>>();

        json!({
            "objectType": "MaskedRankRefreshFinDecMaskedOpeningPayload",
            "objectVersion": 1,
            "profileId": MASKED_RANK_REFRESH_PROFILE_ID,
            "payloadStatus": "PublicFinDecMaskedOpeningPayloadBound",
            "payloadKind": "selected-share-lagrange-combination-polynomial",
            "combinationRule": "LagrangeInterpolationOverSelectedShares",
            "combinationEquation": "maskedOpeningPayload = inputCiphertextComponentZero + sum(lagrangeCoefficient_i * partialDecryptionShare_i) mod q",
            "invalidShareFilteringMode": "ProofVerifiedSharesOnly",
            "interpolationPointKind": "roster-position-plus-one",
            "lagrangeCoefficientDomain": "per-data-prime-canonical-residue",
            "basisId": "data",
            "coefficientDomain": "coefficient",
            "coefficientEncoding": "little-endian-u64-coefficient-vectors-by-data-prime",
            "componentCount": 1,
            "polynomialDegree": POLYNOMIAL_DEGREE,
            "dataPrimeCount": crate::bgv::profile::DATA_PRIMES.len(),
            "plaintextModulus": crate::bgv::profile::PLAINTEXT_MODULUS,
            "inputCiphertextComponentZeroApplied": true,
            "maskedOpeningOnly": true,
            "semanticRankOpeningAllowed": false,
            "plaintextRankExported": false,
            "setupPackageHash": setup_package["setupPackageHash"],
            "evaluationContextHash": hash("1"),
            "inputRankCiphertextRoot": input_rank_ciphertext_root,
            "shareSelectionRuleHash": share_selection_rule_hash,
            "smudgingBoundCertificateHash": smudging_bound_certificate_hash,
            "finDecLagrangeCoefficientAuditRoot": fin_dec_lagrange_coefficient_audit_root,
            "selectedShareCount": share_records.len(),
            "selectedTrusteeIdentities": selected_trustee_identities,
            "selectedRosterPositions": selected_roster_positions,
            "partialDecryptionShareRoots": partial_decryption_share_roots,
            "selectedAlgebraicShareVerificationKeyBindingRoots": selected_algebraic_share_verification_key_binding_roots,
            "coefficientTables": coefficient_tables,
        })
    }

    fn fin_dec_masked_opening(
        setup_package: &Value,
        share_selection_rule_hash: &str,
        share_records: &[Value],
        smudging_bound_certificate_hash: &str,
        fin_dec_lagrange_coefficient_audit_root: &str,
        input_rank_ciphertext_root: &str,
        masked_opening_payload_root: &str,
    ) -> Value {
        let selected_trustee_identities = share_records
            .iter()
            .map(|record| record["trusteeIdentity"].clone())
            .collect::<Vec<_>>();
        let selected_roster_positions = share_records
            .iter()
            .map(|record| record["rosterPosition"].clone())
            .collect::<Vec<_>>();
        let partial_decryption_share_roots = share_records
            .iter()
            .map(|record| record["partialDecryptionShareRoot"].clone())
            .collect::<Vec<_>>();
        let selected_algebraic_share_verification_key_binding_roots = share_records
            .iter()
            .map(|record| record["selectedAlgebraicShareVerificationKeyBindingRoot"].clone())
            .collect::<Vec<_>>();
        let share_equation_proof_roots = share_records
            .iter()
            .map(|record| record["shareEquationProofRoot"].clone())
            .collect::<Vec<_>>();
        let share_freshness_hashes = share_records
            .iter()
            .map(|record| record["shareFreshnessHash"].clone())
            .collect::<Vec<_>>();

        let mut opening = json!({
            "objectType": "MaskedRankRefreshFinDecMaskedOpening",
            "objectVersion": 1,
            "profileId": MASKED_RANK_REFRESH_PROFILE_ID,
            "finDecStatus": "FinDecMaskedOpeningStatementBound",
            "combinationRule": "LagrangeInterpolationOverSelectedShares",
            "invalidShareFilteringMode": "ProofVerifiedSharesOnly",
            "finDecProofVerificationStatus": "FinDecMaskedOpeningVerifierPending",
            "finDecProofBytesVerified": false,
            "semanticRankOpeningAllowed": false,
            "plaintextRankExported": false,
            "maskedOpeningOnly": true,
            "setupPackageHash": setup_package["setupPackageHash"],
            "evaluationContextHash": hash("1"),
            "inputRankCiphertextRoot": input_rank_ciphertext_root,
            "shareSelectionRuleHash": share_selection_rule_hash,
            "smudgingBoundCertificateHash": smudging_bound_certificate_hash,
            "finDecLagrangeCoefficientAuditRoot": fin_dec_lagrange_coefficient_audit_root,
            "maskedOpeningPayloadRoot": masked_opening_payload_root,
            "selectedShareCount": share_records.len(),
            "selectedTrusteeIdentities": selected_trustee_identities,
            "selectedRosterPositions": selected_roster_positions,
            "partialDecryptionShareRoots": partial_decryption_share_roots,
            "selectedAlgebraicShareVerificationKeyBindingRoots": selected_algebraic_share_verification_key_binding_roots,
            "shareEquationProofRoots": share_equation_proof_roots,
            "shareFreshnessHashes": share_freshness_hashes,
        });
        bind_standard_proof_bytes(
            &mut opening,
            "MaskedRankRefreshFinDecMaskedOpeningStatementHash",
            &FIN_DEC_PROOF_METADATA_FIELDS,
            "masked rank refresh FinDec proof bytes",
        );

        opening
    }

    fn mask_commitment(
        setup_package: &Value,
        share_selection_rule_hash: &str,
        input_rank_ciphertext_root: &str,
        masked_opening_payload_root: &str,
        smudging_bound_certificate_hash: &str,
        encrypted_mask_ciphertext_root: &str,
        encrypted_mask_ciphertext_payload_hash: &str,
    ) -> Value {
        json!({
            "objectType": "MaskedRankRefreshMaskCommitment",
            "objectVersion": 1,
            "profileId": MASKED_RANK_REFRESH_PROFILE_ID,
            "commitmentStatus": "MaskCommitmentBound",
            "commitmentScheme": "masked-rank-refresh-witness-private-mask-commitment-v1",
            "openingProofStatus": "MaskOpeningProofPending",
            "rawWitnessExported": false,
            "maskPlaintextExported": false,
            "semanticRankOpeningAllowed": false,
            "setupPackageHash": setup_package["setupPackageHash"],
            "evaluationContextHash": hash("1"),
            "inputRankCiphertextRoot": input_rank_ciphertext_root,
            "maskedOpeningPayloadRoot": masked_opening_payload_root,
            "smudgingBoundCertificateHash": smudging_bound_certificate_hash,
            "shareSelectionRuleHash": share_selection_rule_hash,
            "encryptedMaskCiphertextRoot": encrypted_mask_ciphertext_root,
            "encryptedMaskCiphertextPayloadHash": encrypted_mask_ciphertext_payload_hash,
            "maskPlaintextCommitmentHash": hash("d"),
        })
    }

    fn mask_encryption_randomness_evidence(
        setup_package: &Value,
        input_rank_ciphertext_root: &str,
        mask_commitment_root: &str,
        encrypted_mask_ciphertext_root: &str,
        encrypted_mask_ciphertext_payload_hash: &str,
    ) -> Value {
        json!({
            "objectType": "MaskedRankRefreshMaskEncryptionRandomnessEvidence",
            "objectVersion": 1,
            "profileId": MASKED_RANK_REFRESH_PROFILE_ID,
            "evidenceStatus": "MaskEncryptionRandomnessEvidenceBound",
            "freshnessProofStatus": "MaskEncryptionFreshnessProofPending",
            "randomnessSourceKind": "witness-private-mask-encryption-randomness",
            "claimBearingFreshRandomnessEvidence": false,
            "developmentRandomnessAcceptedForClaim": false,
            "rawRandomnessExported": false,
            "setupPackageHash": setup_package["setupPackageHash"],
            "collectivePublicKeyRoot": setup_package["collectivePublicKey"]["collectivePublicKeyRoot"],
            "bgvPublicKeyRoot": setup_package["collectivePublicKey"]["bgvPublicKeyRoot"],
            "evaluationContextHash": hash("1"),
            "inputRankCiphertextRoot": input_rank_ciphertext_root,
            "maskCommitmentRoot": mask_commitment_root,
            "encryptedMaskCiphertextRoot": encrypted_mask_ciphertext_root,
            "encryptedMaskCiphertextPayloadHash": encrypted_mask_ciphertext_payload_hash,
            "canonicalCiphertextConventionHash": crate::bgv::profile::canonical_ciphertext_convention_hash().expect("ciphertext convention hash"),
            "randomnessCommitmentHash": hash("e"),
            "freshnessEvidenceHash": hash("f"),
        })
    }

    fn mask_re_encryption_proof_statement(
        setup_package: &Value,
        share_selection_rule_hash: &str,
        input_rank_ciphertext_root: &str,
        masked_opening_root: &str,
        masked_opening_payload_root: &str,
        smudging_bound_certificate_hash: &str,
        ciphertext_bindings: MaskReEncryptionProofCiphertextBindings<'_>,
    ) -> Value {
        let mut statement = json!({
            "objectType": "MaskedRankRefreshMaskReEncryptionProofStatement",
            "objectVersion": 1,
            "profileId": MASKED_RANK_REFRESH_PROFILE_ID,
            "proofStatementFormat": "masked-rank-refresh-mask-re-encryption-v1",
            "proofVerificationStatus": "MaskReEncryptionVerifierPending",
            "proofBytesVerified": false,
            "rawWitnessExported": false,
            "maskPlaintextExported": false,
            "semanticRankOpeningAllowed": false,
            "maskCiphertextRelation": "encryptedMaskCiphertextRoot encrypts the committed mask under the setup collective public key",
            "refreshedCiphertextRelation": "refreshedRankCiphertextRoot re-encrypts maskedOpeningPayloadRoot minus encryptedMaskCiphertextRoot",
            "setupPackageHash": setup_package["setupPackageHash"],
            "collectivePublicKeyRoot": setup_package["collectivePublicKey"]["collectivePublicKeyRoot"],
            "bgvPublicKeyRoot": setup_package["collectivePublicKey"]["bgvPublicKeyRoot"],
            "targetLayoutHash": setup_package["profileBindings"]["targetLayoutHash"],
            "evaluationContextHash": hash("1"),
            "inputRankCiphertextRoot": input_rank_ciphertext_root,
            "maskedOpeningRoot": masked_opening_root,
            "maskedOpeningPayloadRoot": masked_opening_payload_root,
            "smudgingBoundCertificateHash": smudging_bound_certificate_hash,
            "shareSelectionRuleHash": share_selection_rule_hash,
            "encryptedMaskCiphertextRoot": ciphertext_bindings.encrypted_mask_ciphertext_root,
            "encryptedMaskCiphertextPayloadHash": ciphertext_bindings.encrypted_mask_ciphertext_payload_hash,
            "refreshedRankCiphertextRoot": ciphertext_bindings.refreshed_rank_ciphertext_root,
            "refreshedRankCiphertextPayloadHash": ciphertext_bindings.refreshed_rank_ciphertext_payload_hash,
            "maskCommitmentRoot": ciphertext_bindings.mask_commitment_root,
            "maskEncryptionRandomnessEvidenceHash": ciphertext_bindings.mask_encryption_randomness_evidence_hash,
            "canonicalCiphertextConventionHash": crate::bgv::profile::canonical_ciphertext_convention_hash().expect("ciphertext convention hash"),
            "polynomialDegree": POLYNOMIAL_DEGREE,
            "dataPrimeCount": crate::bgv::profile::DATA_PRIMES.len(),
            "plaintextModulus": crate::bgv::profile::PLAINTEXT_MODULUS,
        });
        let challenge_domain_hash =
            mask_re_encryption_proof_statement_challenge_domain_hash(&statement)
                .expect("mask re-encryption challenge-domain hash");
        let public_randomness_hex = challenge_domain_hash
            .get(..64)
            .expect("challenge-domain hash has randomness prefix")
            .to_string();
        statement["challengeDomainHash"] = Value::String(challenge_domain_hash);
        statement["publicRandomnessSource"] =
            Value::String("challenge-domain-hash-prefix-32-bytes".to_string());
        statement["publicRandomnessHex"] = Value::String(public_randomness_hex);
        bind_standard_proof_bytes(
            &mut statement,
            "MaskedRankRefreshMaskReEncryptionProofStatementHash",
            &MASK_RE_ENCRYPTION_PROOF_METADATA_FIELDS,
            "masked rank refresh mask re-encryption proof bytes",
        );

        statement
    }

    fn transcript_without_root(setup_package: &Value) -> Value {
        let (
            input_rank_ciphertext_root,
            input_rank_ciphertext_component_one_payload_hash,
            input_rank_ciphertext_component_one_payload,
        ) = input_rank_ciphertext_component_one_payload(setup_package);
        let share_selection_rule = share_selection_rule(setup_package);
        let share_selection_rule_hash = crate::hashing::derive_protocol_hash(
            "MaskedRankRefreshShareSelectionRuleHash",
            &share_selection_rule,
        )
        .expect("share-selection rule hash");
        let public_key_share_coefficient_material_sidecars =
            public_key_share_coefficient_material_sidecars(setup_package);
        let selected_algebraic_share_verification_key_bindings =
            selected_algebraic_share_verification_key_bindings(
                setup_package,
                &share_selection_rule_hash,
            );
        let fin_dec_lagrange_coefficient_audit = fin_dec_lagrange_coefficient_audit(
            setup_package,
            &share_selection_rule_hash,
            &input_rank_ciphertext_root,
            &selected_algebraic_share_verification_key_bindings,
        );
        let fin_dec_lagrange_coefficient_audit_root = crate::hashing::derive_protocol_hash(
            "MaskedRankRefreshFinDecLagrangeCoefficientAuditRoot",
            &fin_dec_lagrange_coefficient_audit,
        )
        .expect("FinDec Lagrange coefficient audit root");
        let smudging_bound_certificate = smudging_bound_certificate(
            setup_package,
            &share_selection_rule_hash,
            &input_rank_ciphertext_root,
            &fin_dec_lagrange_coefficient_audit_root,
            &fin_dec_lagrange_coefficient_audit,
        );
        let smudging_bound_certificate_hash = crate::hashing::derive_protocol_hash(
            "MaskedRankRefreshSmudgingBoundCertificateHash",
            &smudging_bound_certificate,
        )
        .expect("smudging-bound certificate hash");
        let share_records = rank_refresh_share_records(RankRefreshShareRecordFixture {
            setup_package,
            input_rank_ciphertext_root: &input_rank_ciphertext_root,
            input_rank_ciphertext_component_one_payload_hash:
                &input_rank_ciphertext_component_one_payload_hash,
            input_rank_ciphertext_component_one_payload:
                &input_rank_ciphertext_component_one_payload,
            smudging_bound_certificate_hash: &smudging_bound_certificate_hash,
            smudging_bound_certificate: &smudging_bound_certificate,
            public_key_share_coefficient_material_sidecars:
                &public_key_share_coefficient_material_sidecars,
            selected_algebraic_share_verification_key_bindings:
                &selected_algebraic_share_verification_key_bindings,
        });
        let masked_opening_payload = fin_dec_masked_opening_payload(
            setup_package,
            &share_selection_rule_hash,
            &share_records,
            &smudging_bound_certificate_hash,
            &fin_dec_lagrange_coefficient_audit_root,
            &input_rank_ciphertext_root,
            &input_rank_ciphertext_component_one_payload,
        );
        let masked_opening_payload_root = crate::hashing::derive_protocol_hash(
            "MaskedRankRefreshFinDecMaskedOpeningPayloadRoot",
            &masked_opening_payload,
        )
        .expect("masked opening payload root");
        let masked_opening = fin_dec_masked_opening(
            setup_package,
            &share_selection_rule_hash,
            &share_records,
            &smudging_bound_certificate_hash,
            &fin_dec_lagrange_coefficient_audit_root,
            &input_rank_ciphertext_root,
            &masked_opening_payload_root,
        );
        let masked_opening_root = crate::hashing::derive_protocol_hash(
            "MaskedRankRefreshFinDecMaskedOpeningRoot",
            &masked_opening,
        )
        .expect("masked opening root");
        let (
            encrypted_mask_ciphertext_root,
            encrypted_mask_ciphertext_payload_hash,
            encrypted_mask_ciphertext_payload,
        ) = mask_re_encryption_ciphertext_payload(
            setup_package,
            "encrypted-mask",
            "encryptedMaskCiphertextRoot",
            "MaskedRankRefreshEncryptedMaskCiphertextPayloadHash",
            41,
        );
        let (
            refreshed_rank_ciphertext_root,
            refreshed_rank_ciphertext_payload_hash,
            refreshed_rank_ciphertext_payload,
        ) = mask_re_encryption_ciphertext_payload(
            setup_package,
            "refreshed-packed-rank",
            "refreshedRankCiphertextRoot",
            "MaskedRankRefreshRefreshedRankCiphertextPayloadHash",
            89,
        );
        let mask_commitment = mask_commitment(
            setup_package,
            &share_selection_rule_hash,
            &input_rank_ciphertext_root,
            &masked_opening_payload_root,
            &smudging_bound_certificate_hash,
            &encrypted_mask_ciphertext_root,
            &encrypted_mask_ciphertext_payload_hash,
        );
        let mask_commitment_root = crate::hashing::derive_protocol_hash(
            "MaskedRankRefreshMaskCommitmentRoot",
            &mask_commitment,
        )
        .expect("mask commitment root");
        let mask_encryption_randomness_evidence = mask_encryption_randomness_evidence(
            setup_package,
            &input_rank_ciphertext_root,
            &mask_commitment_root,
            &encrypted_mask_ciphertext_root,
            &encrypted_mask_ciphertext_payload_hash,
        );
        let mask_encryption_randomness_evidence_hash = crate::hashing::derive_protocol_hash(
            "MaskedRankRefreshMaskEncryptionRandomnessEvidenceHash",
            &mask_encryption_randomness_evidence,
        )
        .expect("mask encryption randomness evidence hash");
        let mask_re_encryption_proof_statement = mask_re_encryption_proof_statement(
            setup_package,
            &share_selection_rule_hash,
            &input_rank_ciphertext_root,
            &masked_opening_root,
            &masked_opening_payload_root,
            &smudging_bound_certificate_hash,
            MaskReEncryptionProofCiphertextBindings {
                mask_commitment_root: &mask_commitment_root,
                mask_encryption_randomness_evidence_hash: &mask_encryption_randomness_evidence_hash,
                encrypted_mask_ciphertext_root: &encrypted_mask_ciphertext_root,
                encrypted_mask_ciphertext_payload_hash: &encrypted_mask_ciphertext_payload_hash,
                refreshed_rank_ciphertext_root: &refreshed_rank_ciphertext_root,
                refreshed_rank_ciphertext_payload_hash: &refreshed_rank_ciphertext_payload_hash,
            },
        );
        let mask_re_encryption_proof_root = crate::hashing::derive_protocol_hash(
            "MaskedRankRefreshMaskReEncryptionProofRoot",
            &mask_re_encryption_proof_statement,
        )
        .expect("mask re-encryption proof root");

        json!({
            "objectType": "MaskedRankRefreshTranscript",
            "objectVersion": 1,
            "profileId": MASKED_RANK_REFRESH_PROFILE_ID,
            "evaluationContextHash": hash("1"),
            "setupPackageHash": setup_package["setupPackageHash"],
            "collectivePublicKeyRoot": setup_package["collectivePublicKey"]["collectivePublicKeyRoot"],
            "bgvPublicKeyRoot": setup_package["collectivePublicKey"]["bgvPublicKeyRoot"],
            "evaluationKeyRoot": setup_package["evaluationKeys"]["evaluationKeyRoot"],
            "targetLayoutHash": setup_package["profileBindings"]["targetLayoutHash"],
            "thresholdShareVerificationKeyRoot": setup_package["thresholdVerificationMaterial"]["thresholdShareVerificationKeyRoot"],
            "thresholdShareVerificationKeyHash": setup_package["thresholdVerificationMaterial"]["thresholdShareVerificationKeyHash"],
            "algebraicShareVerificationKeyRoot": setup_package["thresholdVerificationMaterial"]["algebraicShareVerificationKeyRoot"],
            "algebraicShareVerificationKeyHash": setup_package["thresholdVerificationMaterial"]["algebraicShareVerificationKeyHash"],
            "inputRankCiphertextRoot": input_rank_ciphertext_root,
            "inputRankCiphertextComponentOnePayloadHash": input_rank_ciphertext_component_one_payload_hash,
            "inputRankCiphertextComponentOnePayload": input_rank_ciphertext_component_one_payload,
            "maskedOpeningRoot": masked_opening_root,
            "maskedOpening": masked_opening,
            "maskedOpeningPayloadRoot": masked_opening_payload_root,
            "maskedOpeningPayload": masked_opening_payload,
            "finDecLagrangeCoefficientAuditRoot": fin_dec_lagrange_coefficient_audit_root,
            "finDecLagrangeCoefficientAudit": fin_dec_lagrange_coefficient_audit,
            "smudgingBoundCertificateHash": smudging_bound_certificate_hash,
            "smudgingBoundCertificate": smudging_bound_certificate,
            "maskCommitmentRoot": mask_commitment_root,
            "maskCommitment": mask_commitment,
            "maskEncryptionRandomnessEvidenceHash": mask_encryption_randomness_evidence_hash,
            "maskEncryptionRandomnessEvidence": mask_encryption_randomness_evidence,
            "encryptedMaskCiphertextRoot": encrypted_mask_ciphertext_root,
            "encryptedMaskCiphertextPayloadHash": encrypted_mask_ciphertext_payload_hash,
            "encryptedMaskCiphertextPayload": encrypted_mask_ciphertext_payload,
            "refreshedRankCiphertextRoot": refreshed_rank_ciphertext_root,
            "refreshedRankCiphertextPayloadHash": refreshed_rank_ciphertext_payload_hash,
            "refreshedRankCiphertextPayload": refreshed_rank_ciphertext_payload,
            "shareSelectionRuleHash": share_selection_rule_hash,
            "shareSelectionRule": share_selection_rule,
            "publicKeyShareCoefficientMaterialSidecars": public_key_share_coefficient_material_sidecars,
            "selectedAlgebraicShareVerificationKeyBindings": selected_algebraic_share_verification_key_bindings,
            "ciphertextRole": "packed-rank",
            "semanticRankDecryptionAllowed": false,
            "plaintextRankExported": false,
            "maskedOpeningOnly": true,
            "topCount": 10,
            "polynomialDegree": POLYNOMIAL_DEGREE,
            "dataPrimeCount": crate::bgv::profile::DATA_PRIMES.len(),
            "rankRefreshShareRecords": share_records,
            "maskReEncryptionProofRecords": [{
                "objectType": "MaskedRankRefreshMaskReEncryptionProofRecord",
                "objectVersion": 1,
                "profileId": MASKED_RANK_REFRESH_PROFILE_ID,
                "proofRecordStatus": "MaskReEncryptionProofStatementBound",
                "proofBytesVerified": false,
                "rawWitnessExported": false,
                "encryptedMaskCiphertextPayloadHash": encrypted_mask_ciphertext_payload_hash,
                "refreshedRankCiphertextPayloadHash": refreshed_rank_ciphertext_payload_hash,
                "maskCommitmentRoot": mask_commitment_root,
                "maskEncryptionRandomnessEvidenceHash": mask_encryption_randomness_evidence_hash,
                "maskReEncryptionProofRoot": mask_re_encryption_proof_root,
                "maskReEncryptionProofStatement": mask_re_encryption_proof_statement,
                "maskPlaintextExported": false
            }]
        })
    }

    fn complete_transcript_from_without_root(mut transcript: Value) -> Value {
        let root =
            crate::hashing::derive_protocol_hash("MaskedRankRefreshTranscriptRoot", &transcript)
                .expect("transcript root");
        transcript["rankRefreshTranscriptRoot"] = Value::String(root);

        transcript
    }

    fn complete_transcript(setup_package: &Value) -> Value {
        complete_transcript_from_without_root(transcript_without_root(setup_package))
    }

    fn rebind_first_partial_decryption_share_root(transcript: &mut Value) {
        let partial_decryption_share_root = crate::hashing::derive_protocol_hash(
            "MaskedRankRefreshPartialDecryptionShareRoot",
            &transcript["rankRefreshShareRecords"][0]["partialDecryptionSharePayload"],
        )
        .expect("partial-decryption share root");
        transcript["rankRefreshShareRecords"][0]["partialDecryptionShareRoot"] =
            Value::String(partial_decryption_share_root);
        transcript["rankRefreshShareRecords"][0]["shareEquationProof"]["partialDecryptionShareRoot"] =
            transcript["rankRefreshShareRecords"][0]["partialDecryptionShareRoot"].clone();
        transcript["maskedOpening"]["partialDecryptionShareRoots"][0] =
            transcript["rankRefreshShareRecords"][0]["partialDecryptionShareRoot"].clone();
        transcript["maskedOpeningPayload"]["partialDecryptionShareRoots"][0] =
            transcript["rankRefreshShareRecords"][0]["partialDecryptionShareRoot"].clone();
        rebind_first_share_equation_proof_root(transcript);
        rebind_masked_opening_payload_root(transcript);
    }

    fn rebind_input_rank_ciphertext_component_one_payload_hash(transcript: &mut Value) {
        let payload_hash = crate::hashing::derive_protocol_hash(
            "MaskedRankRefreshInputRankCiphertextComponentOnePayloadHash",
            &transcript["inputRankCiphertextComponentOnePayload"],
        )
        .expect("input rank component-one payload hash");
        transcript["inputRankCiphertextComponentOnePayloadHash"] = Value::String(payload_hash);
    }

    fn rebind_first_part_dec_linear_relation_statement_root(transcript: &mut Value) {
        let relation_statement_root = crate::hashing::derive_protocol_hash(
            "MaskedRankRefreshPartDecLinearRelationStatementRoot",
            &transcript["rankRefreshShareRecords"][0]["shareEquationProof"]
                ["partDecLinearRelationStatement"],
        )
        .expect("PartDec linear relation statement root");
        transcript["rankRefreshShareRecords"][0]["shareEquationProof"]["partDecLinearRelationStatementRoot"] =
            Value::String(relation_statement_root);
        rebind_first_share_equation_proof_root(transcript);
    }

    fn rebind_part_dec_linear_relation_statement_root_for_proof(proof: &mut Value) {
        let relation_statement_root = crate::hashing::derive_protocol_hash(
            "MaskedRankRefreshPartDecLinearRelationStatementRoot",
            &proof["partDecLinearRelationStatement"],
        )
        .expect("PartDec linear relation statement root");
        proof["partDecLinearRelationStatementRoot"] = Value::String(relation_statement_root);
    }

    fn rebind_part_dec_linear_proof_backend_input_root_for_proof(proof: &mut Value) {
        let backend_input_root = crate::hashing::derive_protocol_hash(
            "MaskedRankRefreshPartDecLinearProofBackendInputRoot",
            &proof["linearProofBackendInput"],
        )
        .expect("PartDec linear proof backend input root");
        proof["linearProofBackendInputRoot"] = Value::String(backend_input_root);
    }

    fn rebind_part_dec_public_key_share_consistency_linear_proof_backend_input_root_for_proof(
        proof: &mut Value,
    ) {
        let backend_input_root =
            part_dec_public_key_share_consistency_linear_proof_backend_input_root(
                &proof["linearProofBackendInput"]
                    ["publicKeyShareConsistencyLinearProofBackendInput"],
            )
            .expect("PartDec public key-share consistency linear proof backend input root");
        proof["linearProofBackendInput"]["publicKeyShareConsistencyLinearProofBackendInputRoot"] =
            Value::String(backend_input_root);
        rebind_part_dec_split_same_witness_binding_for_proof(proof);
    }

    fn rebind_part_dec_masked_share_linear_proof_backend_input_root_for_proof(proof: &mut Value) {
        let backend_input_root = part_dec_masked_share_linear_proof_backend_input_root(
            &proof["linearProofBackendInput"]["maskedShareLinearProofBackendInput"],
        )
        .expect("PartDec masked-share linear proof backend input root");
        proof["linearProofBackendInput"]["maskedShareLinearProofBackendInputRoot"] =
            Value::String(backend_input_root);
        rebind_part_dec_split_same_witness_binding_for_proof(proof);
    }

    fn rebind_part_dec_split_same_witness_binding_for_proof(proof: &mut Value) {
        let binding = {
            let backend_input = &proof["linearProofBackendInput"];
            let statement_root = proof["partDecLinearRelationStatementRoot"]
                .as_str()
                .expect("PartDec statement root");
            let adapter_root = backend_input["linearProofBackendAdapterRoot"]
                .as_str()
                .expect("PartDec adapter root");
            let public_key_share_consistency_input_root =
                backend_input["publicKeyShareConsistencyLinearProofBackendInputRoot"]
                    .as_str()
                    .expect("PartDec public key-share input root");
            let public_key_share_consistency_input =
                &backend_input["publicKeyShareConsistencyLinearProofBackendInput"];
            let masked_share_input_root = backend_input["maskedShareLinearProofBackendInputRoot"]
                .as_str()
                .expect("PartDec masked-share input root");
            let masked_share_input = &backend_input["maskedShareLinearProofBackendInput"];
            part_dec_split_same_witness_binding(
                proof,
                statement_root,
                adapter_root,
                public_key_share_consistency_input_root,
                public_key_share_consistency_input,
                masked_share_input_root,
                masked_share_input,
            )
        };
        let binding_root = part_dec_split_same_witness_binding_root(&binding)
            .expect("PartDec split same-witness binding root");
        proof["linearProofBackendInput"]["splitSameWitnessBinding"] = binding;
        proof["linearProofBackendInput"]["splitSameWitnessBindingRoot"] =
            Value::String(binding_root);
        rebind_part_dec_linear_proof_backend_input_root_for_proof(proof);
    }

    fn rebind_part_dec_split_same_witness_binding_root_for_proof(proof: &mut Value) {
        let binding_root = part_dec_split_same_witness_binding_root(
            &proof["linearProofBackendInput"]["splitSameWitnessBinding"],
        )
        .expect("PartDec split same-witness binding root");
        proof["linearProofBackendInput"]["splitSameWitnessBindingRoot"] =
            Value::String(binding_root);
        rebind_part_dec_linear_proof_backend_input_root_for_proof(proof);
    }

    fn rebind_first_share_equation_proof_root(transcript: &mut Value) {
        rebind_part_dec_proof_statement_hash(
            &mut transcript["rankRefreshShareRecords"][0]["shareEquationProof"],
        );
        rebind_first_share_equation_proof_root_without_statement_hash(transcript);
    }

    fn rebind_first_share_equation_proof_root_without_statement_hash(transcript: &mut Value) {
        let proof_root = crate::hashing::derive_protocol_hash(
            "MaskedRankRefreshPartDecShareEquationProofRoot",
            &transcript["rankRefreshShareRecords"][0]["shareEquationProof"],
        )
        .expect("share equation proof root");
        transcript["rankRefreshShareRecords"][0]["shareEquationProofRoot"] =
            Value::String(proof_root);
        transcript["maskedOpening"]["shareEquationProofRoots"][0] =
            transcript["rankRefreshShareRecords"][0]["shareEquationProofRoot"].clone();
        rebind_masked_opening_root(transcript);
    }

    fn rebind_smudging_bound_certificate_hash(transcript: &mut Value) {
        bind_smudging_bound_proof_bytes(
            &mut transcript["smudgingBoundCertificate"],
            "masked rank refresh smudging proof bytes",
        );
        rebind_smudging_bound_certificate_hash_without_proof_metadata_rebind(transcript);
    }

    fn rebind_smudging_bound_certificate_hash_without_proof_metadata_rebind(
        transcript: &mut Value,
    ) {
        let certificate_hash = crate::hashing::derive_protocol_hash(
            "MaskedRankRefreshSmudgingBoundCertificateHash",
            &transcript["smudgingBoundCertificate"],
        )
        .expect("smudging-bound certificate hash");
        transcript["smudgingBoundCertificateHash"] = Value::String(certificate_hash);
    }

    fn rebind_masked_opening_root(transcript: &mut Value) {
        rebind_fin_dec_proof_statement_hash(&mut transcript["maskedOpening"]);
        let masked_opening_root = crate::hashing::derive_protocol_hash(
            "MaskedRankRefreshFinDecMaskedOpeningRoot",
            &transcript["maskedOpening"],
        )
        .expect("masked opening root");
        transcript["maskedOpeningRoot"] = Value::String(masked_opening_root);
        transcript["maskReEncryptionProofRecords"][0]["maskReEncryptionProofStatement"]["maskedOpeningRoot"] =
            transcript["maskedOpeningRoot"].clone();
        rebind_mask_re_encryption_proof_root(transcript);
    }

    fn rebind_masked_opening_payload_root(transcript: &mut Value) {
        let masked_opening_payload_root = crate::hashing::derive_protocol_hash(
            "MaskedRankRefreshFinDecMaskedOpeningPayloadRoot",
            &transcript["maskedOpeningPayload"],
        )
        .expect("masked opening payload root");
        transcript["maskedOpeningPayloadRoot"] = Value::String(masked_opening_payload_root);
        transcript["maskedOpening"]["maskedOpeningPayloadRoot"] =
            transcript["maskedOpeningPayloadRoot"].clone();
        transcript["maskCommitment"]["maskedOpeningPayloadRoot"] =
            transcript["maskedOpeningPayloadRoot"].clone();
        transcript["maskReEncryptionProofRecords"][0]["maskReEncryptionProofStatement"]["maskedOpeningPayloadRoot"] =
            transcript["maskedOpeningPayloadRoot"].clone();
        rebind_masked_opening_root(transcript);
        rebind_mask_commitment_root(transcript);
    }

    fn rebind_mask_commitment_root(transcript: &mut Value) {
        let mask_commitment_root = crate::hashing::derive_protocol_hash(
            "MaskedRankRefreshMaskCommitmentRoot",
            &transcript["maskCommitment"],
        )
        .expect("mask commitment root");
        transcript["maskCommitmentRoot"] = Value::String(mask_commitment_root);
        transcript["maskEncryptionRandomnessEvidence"]["maskCommitmentRoot"] =
            transcript["maskCommitmentRoot"].clone();
        transcript["maskReEncryptionProofRecords"][0]["maskCommitmentRoot"] =
            transcript["maskCommitmentRoot"].clone();
        transcript["maskReEncryptionProofRecords"][0]["maskReEncryptionProofStatement"]["maskCommitmentRoot"] =
            transcript["maskCommitmentRoot"].clone();
        rebind_mask_encryption_randomness_evidence_hash(transcript);
    }

    fn rebind_mask_encryption_randomness_evidence_hash(transcript: &mut Value) {
        let evidence_hash = crate::hashing::derive_protocol_hash(
            "MaskedRankRefreshMaskEncryptionRandomnessEvidenceHash",
            &transcript["maskEncryptionRandomnessEvidence"],
        )
        .expect("mask encryption randomness evidence hash");
        transcript["maskEncryptionRandomnessEvidenceHash"] = Value::String(evidence_hash);
        transcript["maskReEncryptionProofRecords"][0]["maskEncryptionRandomnessEvidenceHash"] =
            transcript["maskEncryptionRandomnessEvidenceHash"].clone();
        transcript["maskReEncryptionProofRecords"][0]["maskReEncryptionProofStatement"]["maskEncryptionRandomnessEvidenceHash"] =
            transcript["maskEncryptionRandomnessEvidenceHash"].clone();
        rebind_mask_re_encryption_proof_root(transcript);
    }

    fn rebind_encrypted_mask_ciphertext_payload_hash(transcript: &mut Value) {
        let payload_hash = crate::hashing::derive_protocol_hash(
            "MaskedRankRefreshEncryptedMaskCiphertextPayloadHash",
            &transcript["encryptedMaskCiphertextPayload"],
        )
        .expect("encrypted mask ciphertext payload hash");
        transcript["encryptedMaskCiphertextPayloadHash"] = Value::String(payload_hash);
    }

    fn rebind_refreshed_rank_ciphertext_payload_hash(transcript: &mut Value) {
        let payload_hash = crate::hashing::derive_protocol_hash(
            "MaskedRankRefreshRefreshedRankCiphertextPayloadHash",
            &transcript["refreshedRankCiphertextPayload"],
        )
        .expect("refreshed rank ciphertext payload hash");
        transcript["refreshedRankCiphertextPayloadHash"] = Value::String(payload_hash);
    }

    fn rebind_mask_re_encryption_proof_root(transcript: &mut Value) {
        rebind_mask_re_encryption_proof_statement_hash(
            &mut transcript["maskReEncryptionProofRecords"][0]["maskReEncryptionProofStatement"],
        );
        rebind_mask_re_encryption_proof_root_without_statement_hash(transcript);
    }

    fn rebind_mask_re_encryption_proof_root_without_statement_hash(transcript: &mut Value) {
        let proof_root = crate::hashing::derive_protocol_hash(
            "MaskedRankRefreshMaskReEncryptionProofRoot",
            &transcript["maskReEncryptionProofRecords"][0]["maskReEncryptionProofStatement"],
        )
        .expect("mask re-encryption proof root");
        transcript["maskReEncryptionProofRecords"][0]["maskReEncryptionProofRoot"] =
            Value::String(proof_root);
    }

    fn rebind_mask_re_encryption_proof_root_with_current_statement_fields(transcript: &mut Value) {
        rebind_proof_statement_hash(
            &mut transcript["maskReEncryptionProofRecords"][0]["maskReEncryptionProofStatement"],
            "proofStatementHash",
            "MaskedRankRefreshMaskReEncryptionProofStatementHash",
            &MASK_RE_ENCRYPTION_PROOF_METADATA_FIELDS,
        );
        rebind_mask_re_encryption_proof_root_without_statement_hash(transcript);
    }

    #[test]
    fn rank_refresh_profile_records_required_share_obligations() {
        let description = describe_masked_rank_refresh_profile().expect("profile");

        assert_eq!(
            description["profile"]["profileId"],
            MASKED_RANK_REFRESH_PROFILE_ID
        );
        assert_eq!(description["profile"]["partDecRequired"], true);
        assert_eq!(description["profile"]["finDecRequired"], true);
        assert_eq!(
            description["profile"]["finDecMaskedOpeningPayloadRequired"],
            true
        );
        assert_eq!(
            description["profile"]["finDecSelectedShareCombinerRequired"],
            true
        );
        assert_eq!(
            description["profile"]["finDecLagrangeCoefficientAuditRequired"],
            true
        );
        assert_eq!(
            description["profile"]["shareSelectionMustUseSetupDecryptionThreshold"],
            true
        );
        assert_eq!(
            description["profile"]["selectedAlgebraicShareVerificationKeyBindingRequired"],
            true
        );
        assert_eq!(description["profile"]["shareEquationProofRequired"], true);
        assert_eq!(
            description["profile"]["partDecLinearRelationStatementRequired"],
            true
        );
        assert_eq!(
            description["profile"]["partDecLinearProofBackendAdapterRequired"],
            true
        );
        assert_eq!(
            description["profile"]["partDecLinearProofAdapterMustBindPublicMatrixAndTarget"],
            true
        );
        assert_eq!(
            description["profile"]["partDecLinearProofBackendInputRequired"],
            true
        );
        assert_eq!(
            description["profile"]["partDecLinearProofBackendInputMustBindVerifierRandomness"],
            true
        );
        assert_eq!(
            description["profile"]["partDecLinearProofBackendInputMustBindWitnessBound"],
            true
        );
        assert_eq!(
            description["profile"]["partDecLinearProofBackendMustRejectOutOfCapacityWitnessBound"],
            true
        );
        assert_eq!(
            description["profile"]["partDecLinearProofBackendMustSplitOutPublicKeyShareConsistency"],
            true
        );
        assert_eq!(
            description["profile"]["partDecPublicKeyShareConsistencyProofInputMustFitCurrentBackend"],
            true
        );
        assert_eq!(
            description["profile"]["partDecMaskedShareProofInputMustBindSmudgingRelation"],
            true
        );
        assert_eq!(
            description["profile"]["partDecSmudgingRelationProofRemainsBackendCapacityGated"],
            true
        );
        assert_eq!(
            description["profile"]["partDecSplitSameWitnessBindingRequired"],
            true
        );
        assert_eq!(description["profile"]["proofBytesMetadataRequired"], true);
        assert_eq!(
            description["profile"]["maskReEncryptionProofRequired"],
            true
        );
        assert_eq!(description["profile"]["maskCommitmentRequired"], true);
        assert_eq!(
            description["profile"]["maskEncryptionRandomnessEvidenceRequired"],
            true
        );
        assert_eq!(
            description["profile"]["encryptedMaskCiphertextPayloadRequired"],
            true
        );
        assert_eq!(
            description["profile"]["refreshedRankCiphertextPayloadRequired"],
            true
        );
        assert_eq!(
            description["profile"]["maskReEncryptionProofMustBindCiphertextPayloads"],
            true
        );
        assert_eq!(
            description["profile"]["maskReEncryptionProofMustBindMaskCommitment"],
            true
        );
        assert_eq!(
            description["profile"]["maskReEncryptionProofMustBindMaskEncryptionRandomnessEvidence"],
            true
        );
        assert_eq!(
            description["profile"]["maskReEncryptionProofMustBindVerifierRandomness"],
            true
        );
        assert_eq!(
            description["profile"]["smudgingBoundMustBindLagrangeCoefficientAudit"],
            true
        );
        assert_eq!(
            description["profile"]["semanticRankDecryptionAllowed"],
            false
        );
        assert_eq!(
            description["profileHash"],
            masked_rank_refresh_profile_hash().expect("profile hash")
        );
    }

    #[test]
    fn rank_refresh_transcript_verifier_fails_closed_after_schema_validation() {
        let setup_package = generated_setup_package();
        let transcript = complete_transcript(&setup_package);
        let input_rank_ciphertext_root = transcript["inputRankCiphertextRoot"].clone();
        let refreshed_rank_ciphertext_root = transcript["refreshedRankCiphertextRoot"].clone();
        let error = verify_masked_rank_refresh_transcript_from_request(&json!({
            "setupPackage": setup_package,
            "rankRefreshTranscript": transcript,
            "expectedEvaluationContextHash": hash("1"),
            "expectedInputRankCiphertextRoot": input_rank_ciphertext_root,
            "expectedRefreshedRankCiphertextRoot": refreshed_rank_ciphertext_root,
            "expectedTopCount": 10
        }))
        .expect_err("share verifier is not implemented");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("claim-bearing FinDec masked-opening proof verification"),
            "{}",
            error.message
        );
    }

    #[test]
    fn rank_refresh_mask_re_encryption_binds_mask_commitment_and_randomness_evidence() {
        let setup_package = generated_setup_package();
        let transcript = transcript_without_root(&setup_package);

        validate_mask_commitment_and_randomness_evidence(&transcript)
            .expect("fixture mask commitment and randomness evidence are valid");
        validate_mask_re_encryption_proof_records(&transcript)
            .expect("fixture mask re-encryption proof record is valid");

        let mut mutated_transcript = transcript.clone();
        mutated_transcript["maskCommitment"]["encryptedMaskCiphertextPayloadHash"] =
            Value::String(hash("0"));
        rebind_mask_commitment_root(&mut mutated_transcript);
        let error = validate_mask_commitment_and_randomness_evidence(&mutated_transcript)
            .expect_err("mask commitment over a different encrypted mask payload must reject");
        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("mask commitment encrypted mask ciphertext payload hash"),
            "{}",
            error.message
        );

        let mut mutated_transcript = transcript.clone();
        mutated_transcript["maskEncryptionRandomnessEvidence"]["claimBearingFreshRandomnessEvidence"] =
            json!(true);
        rebind_mask_encryption_randomness_evidence_hash(&mut mutated_transcript);
        let error = validate_mask_commitment_and_randomness_evidence(&mutated_transcript)
            .expect_err("claim-bearing mask encryption randomness evidence must reject");
        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("mask encryption claim-bearing randomness evidence flag"),
            "{}",
            error.message
        );

        let mut mutated_transcript = transcript.clone();
        mutated_transcript["maskReEncryptionProofRecords"][0]["maskReEncryptionProofStatement"]["maskCommitmentRoot"] =
            Value::String(hash("0"));
        rebind_mask_re_encryption_proof_root(&mut mutated_transcript);
        let error = validate_mask_re_encryption_proof_records(&mutated_transcript)
            .expect_err("mask re-encryption over a different mask commitment must reject");
        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("mask re-encryption mask commitment root"),
            "{}",
            error.message
        );

        let mut mutated_transcript = transcript.clone();
        mutated_transcript["maskReEncryptionProofRecords"][0]["maskReEncryptionProofStatement"]["maskEncryptionRandomnessEvidenceHash"] =
            Value::String(hash("0"));
        rebind_mask_re_encryption_proof_root(&mut mutated_transcript);
        let error = validate_mask_re_encryption_proof_records(&mutated_transcript).expect_err(
            "mask re-encryption over different mask encryption randomness evidence must reject",
        );
        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("mask re-encryption mask encryption randomness evidence hash"),
            "{}",
            error.message
        );

        let mut mutated_transcript = transcript.clone();
        mutated_transcript["maskReEncryptionProofRecords"][0]["maskReEncryptionProofStatement"]["challengeDomainHash"] =
            Value::String(hash("0"));
        rebind_mask_re_encryption_proof_root_with_current_statement_fields(&mut mutated_transcript);
        let error = validate_mask_re_encryption_proof_records(&mutated_transcript)
            .expect_err("wrong mask re-encryption challenge-domain hash must reject");
        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("mask re-encryption challenge-domain hash"),
            "{}",
            error.message
        );

        let mut mutated_transcript = transcript.clone();
        mutated_transcript["maskReEncryptionProofRecords"][0]["maskReEncryptionProofStatement"]["publicRandomnessHex"] =
            Value::String("00".repeat(32));
        rebind_mask_re_encryption_proof_root_with_current_statement_fields(&mut mutated_transcript);
        let error = validate_mask_re_encryption_proof_records(&mutated_transcript)
            .expect_err("wrong mask re-encryption public randomness must reject");
        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("mask re-encryption public randomness"),
            "{}",
            error.message
        );
    }

    #[test]
    fn rank_refresh_share_selection_rejects_threshold_rule_mutations() {
        let setup_package = generated_setup_package();
        let trustee_bindings =
            setup_trustee_bindings(&setup_package).expect("setup trustee bindings");
        let mut transcript = share_selection_validation_transcript(&setup_package);
        let decryption_threshold = transcript["shareSelectionRule"]["decryptionThreshold"]
            .as_u64()
            .expect("decryption threshold");
        transcript["shareSelectionRule"]["selectedShareCount"] = json!(decryption_threshold + 1);
        let error = validate_share_selection_rule(&setup_package, &transcript, &trustee_bindings)
            .expect_err("over-selected rank-refresh shares must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error.message.contains("setup decryption threshold"),
            "{}",
            error.message
        );

        let setup_package = generated_setup_package();
        let trustee_bindings =
            setup_trustee_bindings(&setup_package).expect("setup trustee bindings");
        let mut transcript = share_selection_validation_transcript(&setup_package);
        transcript["shareSelectionRule"]["selectedTrusteeIdentities"][0] = json!("trustee-2");
        transcript["shareSelectionRule"]["selectedRosterPositions"][0] = json!(1);
        let error = validate_share_selection_rule(&setup_package, &transcript, &trustee_bindings)
            .expect_err("wrong canonical rank-refresh share trustee must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error.message.contains("canonical threshold board order"),
            "{}",
            error.message
        );
    }

    #[test]
    fn rank_refresh_transcript_rejects_context_and_plaintext_mutations() {
        let setup_package = generated_setup_package();
        let transcript = complete_transcript(&setup_package);
        let input_rank_ciphertext_root = transcript["inputRankCiphertextRoot"].clone();
        let context_error = verify_masked_rank_refresh_transcript_from_request(&json!({
            "setupPackage": setup_package,
            "rankRefreshTranscript": transcript,
            "expectedEvaluationContextHash": hash("0"),
            "expectedInputRankCiphertextRoot": input_rank_ciphertext_root
        }))
        .expect_err("wrong context must reject before verifier status");
        assert_eq!(
            context_error.code,
            CanonicalErrorCode::ProfileComponentMismatch
        );
        assert!(context_error.message.contains("evaluation context"));

        let setup_package = generated_setup_package();
        let mut plaintext_leak = complete_transcript(&setup_package);
        plaintext_leak["rankRefreshShareRecords"][0]["plaintextRanks"] = json!([0, 1]);
        let leak_error = verify_masked_rank_refresh_transcript_from_request(&json!({
            "setupPackage": setup_package,
            "rankRefreshTranscript": plaintext_leak
        }))
        .expect_err("plaintext ranks must reject");
        assert_eq!(leak_error.code, CanonicalErrorCode::InvalidFixture);
        assert!(
            leak_error
                .message
                .contains("rankRefreshTranscript.rankRefreshShareRecords.0.plaintextRanks"),
            "{}",
            leak_error.message
        );
    }

    #[test]
    fn rank_refresh_transcript_rejects_fin_dec_lagrange_audit_mutations() {
        let setup_package = generated_setup_package();

        let mut transcript = transcript_without_root(&setup_package);
        transcript["finDecLagrangeCoefficientAudit"]["coefficientTables"][0]["lagrangeCoefficientEntries"]
            [0]["coefficient"] = json!(0_u64);
        let transcript = complete_transcript_from_without_root(transcript);
        let error = verify_masked_rank_refresh_transcript_from_request(&json!({
            "setupPackage": setup_package.clone(),
            "rankRefreshTranscript": transcript
        }))
        .expect_err("mutated FinDec Lagrange coefficient audit must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("FinDec Lagrange coefficient audit root"),
            "{}",
            error.message
        );

        let mut transcript = transcript_without_root(&setup_package);
        transcript["smudgingBoundCertificate"]["finDecLagrangeCoefficientAuditRoot"] =
            Value::String(hash("0"));
        rebind_smudging_bound_certificate_hash(&mut transcript);
        let transcript = complete_transcript_from_without_root(transcript);
        let error = verify_masked_rank_refresh_transcript_from_request(&json!({
            "setupPackage": setup_package.clone(),
            "rankRefreshTranscript": transcript
        }))
        .expect_err("smudging over a different FinDec Lagrange audit must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("smudging-bound FinDec Lagrange coefficient audit root"),
            "{}",
            error.message
        );

        let mut transcript = transcript_without_root(&setup_package);
        let maximum_lagrange_coefficient_bits =
            transcript["smudgingBoundCertificate"]["maximumLagrangeCoefficientBits"]
                .as_u64()
                .expect("maximum Lagrange coefficient bits");
        transcript["smudgingBoundCertificate"]["maximumLagrangeCoefficientBits"] =
            json!(maximum_lagrange_coefficient_bits + 1);
        rebind_smudging_bound_certificate_hash(&mut transcript);
        let transcript = complete_transcript_from_without_root(transcript);
        let error = verify_masked_rank_refresh_transcript_from_request(&json!({
            "setupPackage": setup_package.clone(),
            "rankRefreshTranscript": transcript
        }))
        .expect_err("smudging with wrong Lagrange coefficient bit budget must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("smudging-bound maximum Lagrange coefficient bits"),
            "{}",
            error.message
        );

        let mut transcript = transcript_without_root(&setup_package);
        transcript["maskedOpening"]["finDecLagrangeCoefficientAuditRoot"] =
            Value::String(hash("0"));
        rebind_masked_opening_root(&mut transcript);
        let transcript = complete_transcript_from_without_root(transcript);
        let error = verify_masked_rank_refresh_transcript_from_request(&json!({
            "setupPackage": setup_package.clone(),
            "rankRefreshTranscript": transcript
        }))
        .expect_err("FinDec opening over a different Lagrange audit must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("FinDec Lagrange coefficient audit root"),
            "{}",
            error.message
        );

        let mut transcript = transcript_without_root(&setup_package);
        transcript["maskedOpeningPayload"]["finDecLagrangeCoefficientAuditRoot"] =
            Value::String(hash("0"));
        rebind_masked_opening_payload_root(&mut transcript);
        let transcript = complete_transcript_from_without_root(transcript);
        let error = verify_masked_rank_refresh_transcript_from_request(&json!({
            "setupPackage": setup_package,
            "rankRefreshTranscript": transcript
        }))
        .expect_err("FinDec payload over a different Lagrange audit must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("masked-opening payload Lagrange coefficient audit root"),
            "{}",
            error.message
        );
    }

    #[test]
    fn rank_refresh_part_dec_linear_proof_adapter_uses_public_key_share_target_sign() {
        let setup_package = generated_setup_package();
        let transcript = transcript_without_root(&setup_package);
        let record = &transcript["rankRefreshShareRecords"][0];
        let adapter_table = &record["shareEquationProof"]["partDecLinearRelationStatement"]["linearProofBackendAdapter"]
            ["adapterTables"][0];
        let sidecar_table =
            &transcript["publicKeyShareCoefficientMaterialSidecars"][0]["coefficientTables"][0];
        let partial_share_table = &record["partialDecryptionSharePayload"]["coefficientTables"][0];
        let modulus = DATA_PRIMES[0];

        let public_key_share_component_zero_coefficients = coefficient_vector_from_le_hex(
            sidecar_table["componentZeroBLeHex"]
                .as_str()
                .expect("public key-share component-zero coefficients"),
            "public key-share component-zero coefficients",
        )
        .expect("public key-share component-zero coefficient vector");
        let partial_decryption_share_coefficients = coefficient_vector_from_le_hex(
            partial_share_table["shareCoefficientsLeHex"]
                .as_str()
                .expect("partial-decryption share coefficients"),
            "partial-decryption share coefficients",
        )
        .expect("partial-decryption share coefficient vector");
        let negative_partial_decryption_share_coefficients = partial_decryption_share_coefficients
            .iter()
            .map(|coefficient| sub_mod(0, *coefficient, modulus))
            .collect::<Result<Vec<_>, _>>()
            .expect("negative partial-decryption share coefficients");
        let old_negative_public_key_share_component_zero_coefficients =
            public_key_share_component_zero_coefficients
                .iter()
                .map(|coefficient| sub_mod(0, *coefficient, modulus))
                .collect::<Result<Vec<_>, _>>()
                .expect("old negative public key-share coefficients");

        assert_eq!(
            adapter_table["publicKeyShareComponentZeroTargetHash512"],
            part_dec_linear_proof_coefficient_hash(&public_key_share_component_zero_coefficients)
        );
        assert_eq!(
            adapter_table["negativePartialDecryptionShareTargetHash512"],
            part_dec_linear_proof_coefficient_hash(&negative_partial_decryption_share_coefficients)
        );
        assert_eq!(
            adapter_table["targetVectorHash512"],
            part_dec_target_vector_hash(
                modulus,
                &public_key_share_component_zero_coefficients,
                &negative_partial_decryption_share_coefficients,
            )
        );
        assert_ne!(
            adapter_table["targetVectorHash512"],
            part_dec_target_vector_hash(
                modulus,
                &old_negative_public_key_share_component_zero_coefficients,
                &partial_decryption_share_coefficients,
            )
        );
    }

    #[test]
    fn rank_refresh_part_dec_linear_proof_adapter_rejects_public_matrix_mutations() {
        let setup_package = generated_setup_package();
        let transcript = transcript_without_root(&setup_package);
        let trustee_bindings =
            setup_trustee_bindings(&setup_package).expect("setup trustee bindings");
        let record = &transcript["rankRefreshShareRecords"][0];
        let sidecar = &transcript["publicKeyShareCoefficientMaterialSidecars"][0];
        let trustee_identity = record["trusteeIdentity"]
            .as_str()
            .expect("trustee identity");
        let trustee_binding = trustee_bindings
            .iter()
            .find(|binding| binding.trustee_identity == trustee_identity)
            .expect("selected trustee binding");

        validate_part_dec_linear_relation_statement(
            &setup_package,
            &transcript,
            record,
            sidecar,
            &record["shareEquationProof"],
            trustee_binding,
        )
        .expect("fixture PartDec linear proof adapter is valid");

        let mut proof = record["shareEquationProof"].clone();
        proof["partDecLinearRelationStatement"]["linearProofBackendAdapter"]["adapterTables"][0]
            ["sourceMatrixHash512"] = Value::String(hash("0"));
        rebind_part_dec_linear_relation_statement_root_for_proof(&mut proof);
        let error = validate_part_dec_linear_relation_statement(
            &setup_package,
            &transcript,
            record,
            sidecar,
            &proof,
            trustee_binding,
        )
        .expect_err("wrong PartDec adapter source matrix hash must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("linear proof adapter source matrix hash"),
            "{}",
            error.message
        );

        let mut proof = record["shareEquationProof"].clone();
        proof["partDecLinearRelationStatement"]["linearProofBackendAdapter"]["adapterTables"][0]
            ["targetVectorHash512"] = Value::String(hash("0"));
        rebind_part_dec_linear_relation_statement_root_for_proof(&mut proof);
        let error = validate_part_dec_linear_relation_statement(
            &setup_package,
            &transcript,
            record,
            sidecar,
            &proof,
            trustee_binding,
        )
        .expect_err("wrong PartDec adapter target vector hash must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("linear proof adapter target vector hash"),
            "{}",
            error.message
        );

        let mut proof = record["shareEquationProof"].clone();
        proof["partDecLinearRelationStatement"]["linearProofBackendAdapter"]["adapterTables"][0]
            ["publicCommonRandomPolynomialHash512"] = Value::String(hash("0"));
        rebind_part_dec_linear_relation_statement_root_for_proof(&mut proof);
        let error = validate_part_dec_linear_relation_statement(
            &setup_package,
            &transcript,
            record,
            sidecar,
            &proof,
            trustee_binding,
        )
        .expect_err("wrong PartDec adapter common-random hash must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("linear proof adapter public common-random polynomial hash"),
            "{}",
            error.message
        );
    }

    #[test]
    fn rank_refresh_public_key_share_consistency_witness_satisfies_sidecar_relation() {
        let setup_package = generated_setup_package();
        let transcript = transcript_without_root(&setup_package);
        let record = &transcript["rankRefreshShareRecords"][0];
        let selected_sidecar = &transcript["publicKeyShareCoefficientMaterialSidecars"][0];
        let proof = &record["shareEquationProof"];
        let backend_input =
            &proof["linearProofBackendInput"]["publicKeyShareConsistencyLinearProofBackendInput"];
        let adapter = &proof["partDecLinearRelationStatement"]["linearProofBackendAdapter"];
        let adapter_tables = adapter["adapterTables"].as_array().expect("adapter tables");
        let proof_input = &backend_input["dataPrimeProofInputs"][0];

        validate_part_dec_public_key_share_consistency_linear_proof_prime_input(
            proof_input,
            &adapter_tables[0],
            0,
        )
        .expect("public key-share consistency proof input is bound");

        let trustee_identity = proof["trusteeIdentity"].as_str().expect("trustee identity");
        let witness = trustee_public_key_share_witness_coefficients_from_setup_witness(
            &setup_package,
            "rank-refresh-setup-seed",
            trustee_identity,
        )
        .expect("public key-share witness coefficients");
        let modulus = DATA_PRIMES[0];
        let source_ring = PolynomialRing::new(POLYNOMIAL_DEGREE, modulus).expect("source ring");
        let source_witness = PolynomialVector::new(
            source_ring,
            vec![
                signed_coefficients_to_source_residues(&witness.secret_share_coefficients, modulus),
                signed_coefficients_to_source_residues(&witness.error_share_coefficients, modulus),
            ],
        )
        .expect("source witness vector");
        let statement = part_dec_public_key_share_consistency_streamed_statement_for_modulus(
            &setup_package,
            selected_sidecar,
            &adapter_tables[0],
            0,
        )
        .expect("public key-share consistency statement");
        statement
            .validate_source_relation(
                &part_dec_public_key_share_consistency_linear_parameter_set(modulus),
                &source_witness,
            )
            .expect("public key-share consistency witness satisfies the sidecar relation");
    }

    #[test]
    fn rank_refresh_public_key_share_streamed_z4_products_match_sparse_automorphic_products() {
        let source_modulus = 257_u64;
        let parameter_set = LinearProofParameterSet {
            profile_id: PART_DEC_PUBLIC_KEY_SHARE_LINEAR_PROOF_PARAMETER_PROFILE_ID.to_string(),
            source: "sealed-lattice/test/rank-refresh-streamed-z4-products".to_string(),
            relation: "A*w + t = 0".to_string(),
            ring_degree: 128,
            proof_system_ring_degree: PART_DEC_LINEAR_PROOF_SYSTEM_RING_DEGREE as usize,
            coefficient_modulus: source_modulus,
            statement_rows: 1,
            statement_columns: 2,
            witness_l2_bound_squared: 1,
            expected_proof_size_bytes: None,
        };
        let proof_encoding = part_dec_public_key_share_consistency_linear_proof_encoding();
        let source_ring =
            PolynomialRing::new(parameter_set.ring_degree, source_modulus).expect("source ring");
        let statement = RankRefreshPublicKeyShareConsistencyStreamedStatement {
            source_matrix_hash: hash("c"),
            target_vector_hash: hash("d"),
            source_statement_matrix: SparsePolynomialMatrix::new(
                source_ring,
                parameter_set.statement_rows,
                parameter_set.statement_columns,
                vec![
                    SparsePolynomialMatrixEntry::new(
                        0,
                        0,
                        synthetic_source_polynomial(parameter_set.ring_degree, source_modulus, 3),
                    ),
                    SparsePolynomialMatrixEntry::new(
                        0,
                        1,
                        synthetic_source_polynomial(parameter_set.ring_degree, source_modulus, 11),
                    ),
                ],
            )
            .expect("synthetic source matrix"),
            target_vector_coefficients: vec![vec![0_u64; parameter_set.ring_degree]],
        };
        let proof_ring = PolynomialRing::new(
            proof_encoding.ring_degree,
            proof_encoding.coefficient_modulus,
        )
        .expect("proof ring");
        let source_polynomial_split_factor =
            source_polynomial_split_factor(&parameter_set, &proof_encoding)
                .expect("source split factor");
        let transformed_rows = parameter_set.statement_rows * source_polynomial_split_factor;
        let transformed_columns = parameter_set.statement_columns * source_polynomial_split_factor;
        let shifted_rotation_polynomial_matrix =
            deterministic_shifted_rotation_polynomial_matrix(proof_ring, 2, transformed_rows);

        let streamed_products = statement
            .build_z4_statement_products(
                proof_ring,
                &parameter_set,
                &proof_encoding,
                LinearProofMatrixCoefficientRepresentation::CenteredSignedSourceModulus,
                &shifted_rotation_polynomial_matrix,
            )
            .expect("streamed z4 products");
        let transformed_statement =
            transform_sparse_statement_matrix_to_proof_ring_with_coefficient_representation(
                &parameter_set,
                &proof_encoding,
                &statement.source_statement_matrix,
                LinearProofMatrixCoefficientRepresentation::CenteredSignedSourceModulus,
            )
            .expect("transformed sparse statement")
            .automorphism()
            .expect("automorphic transformed sparse statement");
        let mut expected_products = vec![
            vec![vec![0_u64; proof_ring.degree()]; transformed_columns];
            shifted_rotation_polynomial_matrix.len()
        ];
        for entry in transformed_statement.entries() {
            for (expected_row, shifted_rotation_row) in expected_products
                .iter_mut()
                .zip(&shifted_rotation_polynomial_matrix)
            {
                proof_ring
                    .mul_negacyclic_accumulate(
                        &mut expected_row[entry.column_index()],
                        &shifted_rotation_row[entry.row_index()],
                        entry.coefficients(),
                    )
                    .expect("expected sparse product");
            }
        }

        assert_eq!(streamed_products, expected_products);
    }

    fn synthetic_source_polynomial(ring_degree: usize, modulus: u64, offset: u64) -> Vec<u64> {
        (0..ring_degree)
            .map(|coefficient_index| {
                (offset + 17 * u64::try_from(coefficient_index).expect("coefficient index"))
                    % modulus
            })
            .collect()
    }

    fn deterministic_shifted_rotation_polynomial_matrix(
        proof_ring: PolynomialRing,
        row_count: usize,
        column_count: usize,
    ) -> Vec<Vec<Vec<u64>>> {
        (0..row_count)
            .map(|row_index| {
                (0..column_count)
                    .map(|column_index| {
                        let mut polynomial = vec![0_u64; proof_ring.degree()];
                        polynomial[(row_index + column_index) % proof_ring.degree()] =
                            (((row_index + 3) * (column_index + 5)) as u64) % proof_ring.modulus();
                        polynomial[(2 * row_index + column_index + 1) % proof_ring.degree()] =
                            (((row_index + 7) * (column_index + 11)) as u64) % proof_ring.modulus();
                        polynomial
                    })
                    .collect()
            })
            .collect()
    }

    #[test]
    #[ignore = "manual closure evidence: generates and verifies a full linear proof for one data prime"]
    fn rank_refresh_public_key_share_consistency_generated_proof_verifies_and_rejects_mutations() {
        let setup_package = generated_setup_package();
        let transcript = transcript_without_root(&setup_package);
        let record = &transcript["rankRefreshShareRecords"][0];
        let selected_sidecar = &transcript["publicKeyShareCoefficientMaterialSidecars"][0];
        let proof = &record["shareEquationProof"];
        let backend_input =
            &proof["linearProofBackendInput"]["publicKeyShareConsistencyLinearProofBackendInput"];
        let adapter = &proof["partDecLinearRelationStatement"]["linearProofBackendAdapter"];
        let adapter_tables = adapter["adapterTables"].as_array().expect("adapter tables");
        let modulus_index = 0;
        let modulus = DATA_PRIMES[modulus_index];
        let parameter_set = part_dec_public_key_share_consistency_linear_parameter_set(modulus);
        let proof_encoding = part_dec_public_key_share_consistency_linear_proof_encoding();
        let statement = part_dec_public_key_share_consistency_streamed_statement_for_modulus(
            &setup_package,
            selected_sidecar,
            &adapter_tables[modulus_index],
            modulus_index,
        )
        .expect("public key-share consistency statement");
        let trustee_identity = proof["trusteeIdentity"].as_str().expect("trustee identity");
        let witness = trustee_public_key_share_witness_coefficients_from_setup_witness(
            &setup_package,
            "rank-refresh-setup-seed",
            trustee_identity,
        )
        .expect("public key-share witness coefficients");
        let source_witness_coefficients = vec![
            witness.secret_share_coefficients,
            witness.error_share_coefficients,
        ];
        let public_randomness = decode_32_byte_hex(
            backend_input["publicRandomnessHex"]
                .as_str()
                .expect("public randomness"),
        );
        let prover_randomness = [17_u8; 32];

        let generated_proof = generate_streamed_linear_proof(StreamedLinearProverProofInput {
            parameter_set: &parameter_set,
            proof_encoding: &proof_encoding,
            statement: &statement,
            matrix_coefficient_representation:
                LinearProofMatrixCoefficientRepresentation::CenteredSignedSourceModulus,
            target_coefficient_representation:
                LinearProofTargetCoefficientRepresentation::CenteredSignedSourceModulus,
            source_witness_coefficients: &source_witness_coefficients,
            public_randomness: &public_randomness,
            prover_randomness: &prover_randomness,
        })
        .expect("generated public key-share consistency proof");
        let mut proof_input = backend_input["dataPrimeProofInputs"][modulus_index].clone();
        bind_generated_public_key_share_proof_bytes(&mut proof_input, &generated_proof.proof_bytes);

        validate_part_dec_public_key_share_consistency_verified_linear_proof_for_prime(
            &setup_package,
            selected_sidecar,
            backend_input,
            &adapter_tables[modulus_index],
            &proof_input,
            modulus_index,
        )
        .expect("generated public key-share consistency proof verifies");

        let mut mutated_proof_input = proof_input.clone();
        let mutated_proof_bytes = {
            let mut bytes = generated_proof.proof_bytes.clone();
            let last_byte = bytes.last_mut().expect("proof bytes are nonempty");
            *last_byte ^= 1;
            bytes
        };
        bind_generated_public_key_share_proof_bytes(&mut mutated_proof_input, &mutated_proof_bytes);
        let error = validate_part_dec_public_key_share_consistency_verified_linear_proof_for_prime(
            &setup_package,
            selected_sidecar,
            backend_input,
            &adapter_tables[modulus_index],
            &mutated_proof_input,
            modulus_index,
        )
        .expect_err("mutated generated proof must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error.message.contains("proof verification failed"),
            "{}",
            error.message
        );
    }

    #[test]
    #[ignore = "manual closure evidence: generates and verifies full linear proofs for every data prime"]
    fn rank_refresh_public_key_share_consistency_all_data_prime_generated_proofs_verify_and_reject_mutation()
     {
        let setup_package = generated_setup_package();
        let transcript = transcript_without_root(&setup_package);
        let record = &transcript["rankRefreshShareRecords"][0];
        let selected_sidecar = &transcript["publicKeyShareCoefficientMaterialSidecars"][0];
        let mut proof = record["shareEquationProof"].clone();
        bind_generated_public_key_share_consistency_proofs_for_all_data_primes(
            &setup_package,
            selected_sidecar,
            &mut proof,
        );

        validate_part_dec_linear_proof_backend_input(
            &setup_package,
            selected_sidecar,
            &proof,
            &proof["partDecLinearRelationStatement"],
            &transcript,
        )
        .expect("all data-prime public key-share consistency proofs verify");

        let mut mutated_proof = proof.clone();
        let mutated_modulus_index = DATA_PRIMES.len() - 1;
        let mut mutated_proof_bytes = crate::transcript_core::decode_hex(
            mutated_proof["linearProofBackendInput"]
                ["publicKeyShareConsistencyLinearProofBackendInput"]["dataPrimeProofInputs"]
                [mutated_modulus_index]["proofBytesHex"]
                .as_str()
                .expect("generated proof hex"),
        )
        .expect("generated proof bytes");
        let last_byte = mutated_proof_bytes
            .last_mut()
            .expect("generated proof bytes are nonempty");
        *last_byte ^= 1;
        bind_generated_public_key_share_proof_bytes(
            &mut mutated_proof["linearProofBackendInput"]["publicKeyShareConsistencyLinearProofBackendInput"]
                ["dataPrimeProofInputs"][mutated_modulus_index],
            &mutated_proof_bytes,
        );
        rebind_part_dec_public_key_share_consistency_linear_proof_backend_input_root_for_proof(
            &mut mutated_proof,
        );
        let error = validate_part_dec_linear_proof_backend_input(
            &setup_package,
            selected_sidecar,
            &mutated_proof,
            &mutated_proof["partDecLinearRelationStatement"],
            &transcript,
        )
        .expect_err("mutated all-prime public key-share proof must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("public key-share consistency proof verification failed"),
            "{}",
            error.message
        );
    }

    fn decode_32_byte_hex(hex: &str) -> [u8; 32] {
        let bytes = crate::transcript_core::decode_hex(hex).expect("canonical hex");
        bytes.try_into().expect("32-byte hex value")
    }

    fn bind_generated_public_key_share_consistency_proofs_for_all_data_primes(
        setup_package: &Value,
        selected_sidecar: &Value,
        proof: &mut Value,
    ) {
        let trustee_identity = proof["trusteeIdentity"]
            .as_str()
            .expect("trustee identity")
            .to_string();
        let witness = trustee_public_key_share_witness_coefficients_from_setup_witness(
            setup_package,
            "rank-refresh-setup-seed",
            &trustee_identity,
        )
        .expect("public key-share witness coefficients");
        let source_witness_coefficients = vec![
            witness.secret_share_coefficients,
            witness.error_share_coefficients,
        ];
        let public_randomness = decode_32_byte_hex(
            proof["linearProofBackendInput"]["publicKeyShareConsistencyLinearProofBackendInput"]
                ["publicRandomnessHex"]
                .as_str()
                .expect("public randomness"),
        );
        let generated_proofs = proof["partDecLinearRelationStatement"]["linearProofBackendAdapter"]
            ["adapterTables"]
            .as_array()
            .expect("adapter tables")
            .iter()
            .enumerate()
            .map(|(modulus_index, adapter_table)| {
                let modulus = DATA_PRIMES[modulus_index];
                let parameter_set =
                    part_dec_public_key_share_consistency_linear_parameter_set(modulus);
                let proof_encoding = part_dec_public_key_share_consistency_linear_proof_encoding();
                let statement =
                    part_dec_public_key_share_consistency_streamed_statement_for_modulus(
                        setup_package,
                        selected_sidecar,
                        adapter_table,
                        modulus_index,
                    )
                    .expect("public key-share consistency statement");
                let mut prover_randomness = [17_u8; 32];
                prover_randomness[0] =
                    u8::try_from(modulus_index).expect("data-prime index fits u8");
                prover_randomness[1] = 41;
                generate_streamed_linear_proof(StreamedLinearProverProofInput {
                    parameter_set: &parameter_set,
                    proof_encoding: &proof_encoding,
                    statement: &statement,
                    matrix_coefficient_representation:
                        LinearProofMatrixCoefficientRepresentation::CenteredSignedSourceModulus,
                    target_coefficient_representation:
                        LinearProofTargetCoefficientRepresentation::CenteredSignedSourceModulus,
                    source_witness_coefficients: &source_witness_coefficients,
                    public_randomness: &public_randomness,
                    prover_randomness: &prover_randomness,
                })
                .expect("generated public key-share consistency proof")
                .proof_bytes
            })
            .collect::<Vec<_>>();

        for (modulus_index, proof_bytes) in generated_proofs.iter().enumerate() {
            bind_generated_public_key_share_proof_bytes(
                &mut proof["linearProofBackendInput"]["publicKeyShareConsistencyLinearProofBackendInput"]
                    ["dataPrimeProofInputs"][modulus_index],
                proof_bytes,
            );
        }
        proof["linearProofBackendInput"]["publicKeyShareConsistencyLinearProofBackendInput"]["proofBackendStatus"] =
            Value::String(PART_DEC_PUBLIC_KEY_SHARE_LINEAR_PROOF_BACKEND_VERIFIED_STATUS.into());
        proof["linearProofBackendInput"]["publicKeyShareConsistencyLinearProofBackendInput"]["proofVerificationStatus"] =
            Value::String(PART_DEC_PUBLIC_KEY_SHARE_LINEAR_PROOF_VERIFIED_STATUS.into());
        proof["linearProofBackendInput"]["publicKeyShareConsistencyLinearProofBackendInput"]["proofBytesVerified"] =
            Value::Bool(true);
        rebind_part_dec_public_key_share_consistency_linear_proof_backend_input_root_for_proof(
            proof,
        );
    }

    fn bind_generated_public_key_share_proof_bytes(proof_input: &mut Value, proof_bytes: &[u8]) {
        let proof_hex = crate::transcript_core::encode_hex(proof_bytes);
        proof_input["proofBytesHex"] = Value::String(proof_hex.clone());
        proof_input["proofSizeBytes"] = json!(proof_bytes.len());
        proof_input["proofBytesHash"] = Value::String(
            crate::hashing::derive_protocol_hash_for_proof_bytes_payload(
                &proof_hex,
                u64::try_from(proof_bytes.len()).expect("proof size fits u64"),
            )
            .expect("proof bytes hash"),
        );
    }

    fn signed_coefficients_to_source_residues(coefficients: &[i64], modulus: u64) -> Vec<u64> {
        coefficients
            .iter()
            .map(|coefficient| {
                if *coefficient >= 0 {
                    u64::try_from(*coefficient).expect("nonnegative coefficient fits u64") % modulus
                } else {
                    sub_mod(0, coefficient.unsigned_abs() % modulus, modulus)
                        .expect("negative coefficient residue")
                }
            })
            .collect()
    }

    #[test]
    fn rank_refresh_part_dec_linear_proof_backend_input_rejects_binding_mutations() {
        let setup_package = generated_setup_package();
        let transcript = transcript_without_root(&setup_package);
        let record = &transcript["rankRefreshShareRecords"][0];
        let sidecar = &transcript["publicKeyShareCoefficientMaterialSidecars"][0];
        let proof = &record["shareEquationProof"];
        let statement = &proof["partDecLinearRelationStatement"];

        validate_part_dec_linear_proof_backend_input(
            &setup_package,
            sidecar,
            proof,
            statement,
            &transcript,
        )
        .expect("fixture PartDec linear proof backend input is valid");

        let mut proof = proof.clone();
        proof["linearProofBackendInput"]["publicRandomnessHex"] = Value::String("00".repeat(32));
        rebind_part_dec_linear_proof_backend_input_root_for_proof(&mut proof);
        let error = validate_part_dec_linear_proof_backend_input(
            &setup_package,
            sidecar,
            &proof,
            &proof["partDecLinearRelationStatement"],
            &transcript,
        )
        .expect_err("wrong PartDec backend public randomness must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("linear proof backend input public randomness"),
            "{}",
            error.message
        );

        let mut proof = record["shareEquationProof"].clone();
        proof["linearProofBackendInput"]["publicKeyShareConsistencyLinearProofBackendInput"]["publicRandomnessHex"] =
            Value::String("00".repeat(32));
        rebind_part_dec_public_key_share_consistency_linear_proof_backend_input_root_for_proof(
            &mut proof,
        );
        let error = validate_part_dec_linear_proof_backend_input(
            &setup_package,
            sidecar,
            &proof,
            &proof["partDecLinearRelationStatement"],
            &transcript,
        )
        .expect_err("wrong PartDec public key-share backend public randomness must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error.message.contains(
                "public key-share consistency linear proof backend input public randomness"
            ),
            "{}",
            error.message
        );

        let mut proof = record["shareEquationProof"].clone();
        proof["linearProofBackendInput"]["splitSameWitnessBinding"]["publicKeyShareConsistencyChallengeDomainHash"] =
            Value::String(hash("0"));
        rebind_part_dec_split_same_witness_binding_root_for_proof(&mut proof);
        let error = validate_part_dec_linear_proof_backend_input(
            &setup_package,
            sidecar,
            &proof,
            &proof["partDecLinearRelationStatement"],
            &transcript,
        )
        .expect_err("wrong split same-witness public key-share challenge must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("split same-witness public key-share challenge-domain hash"),
            "{}",
            error.message
        );

        let mut proof = record["shareEquationProof"].clone();
        proof["linearProofBackendInput"]["splitSameWitnessBinding"]["maskedShareLinearProofBackendInputRoot"] =
            Value::String(hash("0"));
        rebind_part_dec_split_same_witness_binding_root_for_proof(&mut proof);
        let error = validate_part_dec_linear_proof_backend_input(
            &setup_package,
            sidecar,
            &proof,
            &proof["partDecLinearRelationStatement"],
            &transcript,
        )
        .expect_err("wrong split same-witness masked-share root must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("split same-witness masked-share backend input root"),
            "{}",
            error.message
        );

        let mut proof = record["shareEquationProof"].clone();
        proof["linearProofBackendInput"]["splitSameWitnessBinding"]["rawSecretShareWitnessExported"] =
            Value::Bool(true);
        rebind_part_dec_split_same_witness_binding_root_for_proof(&mut proof);
        let error = validate_part_dec_linear_proof_backend_input(
            &setup_package,
            sidecar,
            &proof,
            &proof["partDecLinearRelationStatement"],
            &transcript,
        )
        .expect_err("raw split same-witness secret share export must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("split same-witness raw secret-share export flag"),
            "{}",
            error.message
        );

        let mut proof = record["shareEquationProof"].clone();
        proof["linearProofBackendInput"]["dataPrimeProofInputs"][0]["sourceMatrixHash512"] =
            Value::String(hash("0"));
        rebind_part_dec_linear_proof_backend_input_root_for_proof(&mut proof);
        let error = validate_part_dec_linear_proof_backend_input(
            &setup_package,
            sidecar,
            &proof,
            &proof["partDecLinearRelationStatement"],
            &transcript,
        )
        .expect_err("wrong PartDec backend source matrix hash must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("linear proof backend input source matrix hash"),
            "{}",
            error.message
        );

        let mut proof = record["shareEquationProof"].clone();
        proof["linearProofBackendInput"]["publicKeyShareConsistencyLinearProofBackendInput"]["dataPrimeProofInputs"]
            [0]["sourceMatrixHash512"] = Value::String(hash("0"));
        rebind_part_dec_public_key_share_consistency_linear_proof_backend_input_root_for_proof(
            &mut proof,
        );
        let error = validate_part_dec_linear_proof_backend_input(
            &setup_package,
            sidecar,
            &proof,
            &proof["partDecLinearRelationStatement"],
            &transcript,
        )
        .expect_err("wrong PartDec public key-share source matrix hash must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error.message.contains(
                "public key-share consistency linear proof backend input source matrix hash"
            ),
            "{}",
            error.message
        );

        let mut proof = record["shareEquationProof"].clone();
        proof["linearProofBackendInput"]["dataPrimeProofInputs"][0]["proofParameterBinding"]["witnessL2BoundSquared"] =
            Value::String("1".to_string());
        rebind_part_dec_linear_proof_backend_input_root_for_proof(&mut proof);
        let error = validate_part_dec_linear_proof_backend_input(
            &setup_package,
            sidecar,
            &proof,
            &proof["partDecLinearRelationStatement"],
            &transcript,
        )
        .expect_err("wrong PartDec backend witness bound must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("linear proof backend input parameter witness l2 bound squared"),
            "{}",
            error.message
        );

        let mut proof = record["shareEquationProof"].clone();
        proof["linearProofBackendInput"]["publicKeyShareConsistencyLinearProofBackendInput"]["dataPrimeProofInputs"]
            [0]["proofParameterBinding"]["witnessL2BoundSquared"] = Value::String("1".to_string());
        rebind_part_dec_public_key_share_consistency_linear_proof_backend_input_root_for_proof(
            &mut proof,
        );
        let error = validate_part_dec_linear_proof_backend_input(
            &setup_package,
            sidecar,
            &proof,
            &proof["partDecLinearRelationStatement"],
            &transcript,
        )
        .expect_err("wrong PartDec public key-share witness bound must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("public key-share consistency linear proof backend input parameter witness l2 bound squared"),
            "{}",
            error.message
        );

        let mut proof = record["shareEquationProof"].clone();
        proof["linearProofBackendInput"]["publicKeyShareConsistencyLinearProofBackendInput"]["proofVerificationStatus"] =
            Value::String("PartDecPublicKeyShareConsistencyLinearProofVerified".to_string());
        rebind_part_dec_public_key_share_consistency_linear_proof_backend_input_root_for_proof(
            &mut proof,
        );
        let error = validate_part_dec_linear_proof_backend_input(
            &setup_package,
            sidecar,
            &proof,
            &proof["partDecLinearRelationStatement"],
            &transcript,
        )
        .expect_err("verified PartDec public key-share proof status must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error.message.contains(
                "public key-share consistency linear proof backend input proof verification status"
            ),
            "{}",
            error.message
        );

        let mut proof = record["shareEquationProof"].clone();
        proof["linearProofBackendInput"]["publicKeyShareConsistencyLinearProofBackendInput"]["proofBytesVerified"] =
            Value::Bool(true);
        rebind_part_dec_public_key_share_consistency_linear_proof_backend_input_root_for_proof(
            &mut proof,
        );
        let error = validate_part_dec_linear_proof_backend_input(
            &setup_package,
            sidecar,
            &proof,
            &proof["partDecLinearRelationStatement"],
            &transcript,
        )
        .expect_err("verified PartDec public key-share proof bytes must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error.message.contains(
                "public key-share consistency linear proof backend input proof-byte verification flag"
            ),
            "{}",
            error.message
        );

        let mut proof = record["shareEquationProof"].clone();
        proof["linearProofBackendInput"]["publicKeyShareConsistencyLinearProofBackendInput"]["proofBackendStatus"] =
            Value::String(
                PART_DEC_PUBLIC_KEY_SHARE_LINEAR_PROOF_BACKEND_VERIFIED_STATUS.to_string(),
            );
        proof["linearProofBackendInput"]["publicKeyShareConsistencyLinearProofBackendInput"]["proofVerificationStatus"] =
            Value::String(PART_DEC_PUBLIC_KEY_SHARE_LINEAR_PROOF_VERIFIED_STATUS.to_string());
        proof["linearProofBackendInput"]["publicKeyShareConsistencyLinearProofBackendInput"]["proofBytesVerified"] =
            Value::Bool(true);
        rebind_part_dec_public_key_share_consistency_linear_proof_backend_input_root_for_proof(
            &mut proof,
        );
        let error = validate_part_dec_linear_proof_backend_input(
            &setup_package,
            sidecar,
            &proof,
            &proof["partDecLinearRelationStatement"],
            &transcript,
        )
        .expect_err(
            "verified PartDec public key-share proof inputs without proof bytes must reject",
        );

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(error.message.contains("proofBytesHex"), "{}", error.message);

        let mut proof = record["shareEquationProof"].clone();
        proof["linearProofBackendInput"]["maskedShareLinearProofBackendInput"]["dataPrimeProofInputs"]
            [0]["sourceMatrixHash512"] = Value::String(hash("0"));
        rebind_part_dec_masked_share_linear_proof_backend_input_root_for_proof(&mut proof);
        let error = validate_part_dec_linear_proof_backend_input(
            &setup_package,
            sidecar,
            &proof,
            &proof["partDecLinearRelationStatement"],
            &transcript,
        )
        .expect_err("wrong masked-share source matrix hash must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("masked-share linear proof backend input source matrix hash"),
            "{}",
            error.message
        );

        let mut proof = record["shareEquationProof"].clone();
        proof["linearProofBackendInput"]["maskedShareLinearProofBackendInput"]["witnessL2BoundSquaredFitsProofBackend"] =
            Value::Bool(true);
        rebind_part_dec_masked_share_linear_proof_backend_input_root_for_proof(&mut proof);
        let error = validate_part_dec_linear_proof_backend_input(
            &setup_package,
            sidecar,
            &proof,
            &proof["partDecLinearRelationStatement"],
            &transcript,
        )
        .expect_err("wrong masked-share backend witness-bound capacity flag must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error.message.contains(
                "masked-share linear proof backend input witness l2 bound fits proof backend flag"
            ),
            "{}",
            error.message
        );

        let mut proof = record["shareEquationProof"].clone();
        proof["linearProofBackendInput"]["witnessL2BoundSquaredFitsProofBackend"] =
            Value::Bool(true);
        rebind_part_dec_linear_proof_backend_input_root_for_proof(&mut proof);
        let error = validate_part_dec_linear_proof_backend_input(
            &setup_package,
            sidecar,
            &proof,
            &proof["partDecLinearRelationStatement"],
            &transcript,
        )
        .expect_err("wrong PartDec backend witness-bound capacity flag must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("linear proof backend input witness l2 bound fits proof backend flag"),
            "{}",
            error.message
        );

        let mut proof = record["shareEquationProof"].clone();
        proof["linearProofBackendInput"]["dataPrimeProofInputs"][0]["proofEncodingBinding"] =
            json!({});
        rebind_part_dec_linear_proof_backend_input_root_for_proof(&mut proof);
        let error = validate_part_dec_linear_proof_backend_input(
            &setup_package,
            sidecar,
            &proof,
            &proof["partDecLinearRelationStatement"],
            &transcript,
        )
        .expect_err("missing PartDec backend per-prime encoding binding must reject");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(
            error.message.contains("proofEncodingStatus"),
            "{}",
            error.message
        );
    }

    #[test]
    fn rank_refresh_transcript_rejects_setup_share_binding_mutations() {
        let setup_package = generated_setup_package();
        let mut transcript = transcript_without_root(&setup_package);
        transcript["rankRefreshShareRecords"][0]["trusteeThresholdVerificationKeyHash"] =
            Value::String(hash("0"));
        let transcript = complete_transcript_from_without_root(transcript);
        let error = verify_masked_rank_refresh_transcript_from_request(&json!({
            "setupPackage": setup_package,
            "rankRefreshTranscript": transcript
        }))
        .expect_err("wrong trustee verification key hash must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error.message.contains("trustee verification-key hash"),
            "{}",
            error.message
        );

        let setup_package = generated_setup_package();
        let mut transcript = transcript_without_root(&setup_package);
        transcript["rankRefreshShareRecords"][0]["shareEquationProof"]["publicKeyShareRoot"] =
            Value::String(hash("0"));
        rebind_first_share_equation_proof_root(&mut transcript);
        let transcript = complete_transcript_from_without_root(transcript);
        let error = verify_masked_rank_refresh_transcript_from_request(&json!({
            "setupPackage": setup_package,
            "rankRefreshTranscript": transcript
        }))
        .expect_err("wrong proof statement public key-share root must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error.message.contains("public key-share root"),
            "{}",
            error.message
        );

        let setup_package = generated_setup_package();
        let mut transcript = transcript_without_root(&setup_package);
        transcript["rankRefreshShareRecords"][0]["shareEquationProof"]["publicKeyShareCoefficientMaterialRoot"] =
            Value::String(hash("0"));
        rebind_first_share_equation_proof_root(&mut transcript);
        let transcript = complete_transcript_from_without_root(transcript);
        let error = verify_masked_rank_refresh_transcript_from_request(&json!({
            "setupPackage": setup_package,
            "rankRefreshTranscript": transcript
        }))
        .expect_err("wrong proof public key-share coefficient material root must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("PartDec proof public key-share coefficient sidecar root"),
            "{}",
            error.message
        );

        let setup_package = generated_setup_package();
        let mut transcript = transcript_without_root(&setup_package);
        transcript["selectedAlgebraicShareVerificationKeyBindings"][0]["publicKeyShareRoot"] =
            Value::String(hash("0"));
        let transcript = complete_transcript_from_without_root(transcript);
        let error = verify_masked_rank_refresh_transcript_from_request(&json!({
            "setupPackage": setup_package,
            "rankRefreshTranscript": transcript
        }))
        .expect_err("mutated selected algebraic share-verification key binding must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("selected algebraic share-verification key binding root"),
            "{}",
            error.message
        );

        let setup_package = generated_setup_package();
        let mut transcript = transcript_without_root(&setup_package);
        transcript["rankRefreshShareRecords"][0]["shareEquationProof"]["selectedAlgebraicShareVerificationKeyBindingRoot"] =
            Value::String(hash("0"));
        rebind_first_share_equation_proof_root(&mut transcript);
        let transcript = complete_transcript_from_without_root(transcript);
        let error = verify_masked_rank_refresh_transcript_from_request(&json!({
            "setupPackage": setup_package,
            "rankRefreshTranscript": transcript
        }))
        .expect_err("PartDec proof over a different selected algebraic key binding must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("PartDec proof selected algebraic share-verification key binding root"),
            "{}",
            error.message
        );

        let setup_package = generated_setup_package();
        let mut transcript = transcript_without_root(&setup_package);
        let coefficient_hex = transcript["publicKeyShareCoefficientMaterialSidecars"][0]
            ["coefficientTables"][0]["componentZeroBLeHex"]
            .as_str()
            .expect("component-zero sidecar coefficients")
            .to_string();
        let replacement_nibble = if coefficient_hex.ends_with('0') {
            "1"
        } else {
            "0"
        };
        transcript["publicKeyShareCoefficientMaterialSidecars"][0]["coefficientTables"][0]["componentZeroBLeHex"] =
            json!(format!(
                "{}{}",
                &coefficient_hex[..coefficient_hex.len() - 1],
                replacement_nibble
            ));
        let transcript = complete_transcript_from_without_root(transcript);
        let error = verify_masked_rank_refresh_transcript_from_request(&json!({
            "setupPackage": setup_package,
            "rankRefreshTranscript": transcript
        }))
        .expect_err("mutated public key-share coefficient sidecar must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error.message.contains("sidecar component-zero hash"),
            "{}",
            error.message
        );

        let setup_package = generated_setup_package();
        let mut transcript = transcript_without_root(&setup_package);
        let component_one_hex =
            transcript["inputRankCiphertextComponentOnePayload"]["componentOneCoefficientTables"]
                [0]["componentOneCoefficientsLeHex"]
                .as_str()
                .expect("input rank component-one coefficients")
                .to_string();
        let replacement_nibble = if component_one_hex.starts_with('0') {
            "1"
        } else {
            "0"
        };
        transcript["inputRankCiphertextComponentOnePayload"]["componentOneCoefficientTables"][0]
            ["componentOneCoefficientsLeHex"] =
            json!(format!("{}{}", replacement_nibble, &component_one_hex[1..]));
        rebind_input_rank_ciphertext_component_one_payload_hash(&mut transcript);
        let transcript = complete_transcript_from_without_root(transcript);
        let error = verify_masked_rank_refresh_transcript_from_request(&json!({
            "setupPackage": setup_package,
            "rankRefreshTranscript": transcript
        }))
        .expect_err("mutated input rank component-one sidecar must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("component-one coefficients do not match canonical bytes"),
            "{}",
            error.message
        );

        let setup_package = generated_setup_package();
        let mut transcript = transcript_without_root(&setup_package);
        transcript["rankRefreshShareRecords"][0]["shareEquationProof"]["inputRankCiphertextComponentOnePayloadHash"] =
            Value::String(hash("0"));
        rebind_first_share_equation_proof_root(&mut transcript);
        let transcript = complete_transcript_from_without_root(transcript);
        let error = verify_masked_rank_refresh_transcript_from_request(&json!({
            "setupPackage": setup_package,
            "rankRefreshTranscript": transcript
        }))
        .expect_err("PartDec proof over a different input rank component-one payload must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("PartDec proof input rank ciphertext component-one payload hash"),
            "{}",
            error.message
        );

        let setup_package = generated_setup_package();
        let mut transcript = transcript_without_root(&setup_package);
        transcript["rankRefreshShareRecords"][0]["shareEquationProof"]["partDecLinearRelationStatement"]
            ["linearRelationTables"][0]["partialDecryptionShareHash512"] = Value::String(hash("0"));
        rebind_first_part_dec_linear_relation_statement_root(&mut transcript);
        let transcript = complete_transcript_from_without_root(transcript);
        let error = verify_masked_rank_refresh_transcript_from_request(&json!({
            "setupPackage": setup_package,
            "rankRefreshTranscript": transcript
        }))
        .expect_err("PartDec proof over a different linear relation share hash must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("PartDec linear relation partial-decryption share hash"),
            "{}",
            error.message
        );

        let setup_package = generated_setup_package();
        let mut transcript = transcript_without_root(&setup_package);
        let coefficient_hex = transcript["rankRefreshShareRecords"][0]
            ["partialDecryptionSharePayload"]["coefficientTables"][0]["shareCoefficientsLeHex"]
            .as_str()
            .expect("partial-decryption share coefficients")
            .to_string();
        let replacement_nibble = if coefficient_hex.starts_with('0') {
            "1"
        } else {
            "0"
        };
        transcript["rankRefreshShareRecords"][0]["partialDecryptionSharePayload"]["coefficientTables"]
            [0]["shareCoefficientsLeHex"] =
            json!(format!("{}{}", replacement_nibble, &coefficient_hex[1..]));
        rebind_first_partial_decryption_share_root(&mut transcript);
        let transcript = complete_transcript_from_without_root(transcript);
        let error = verify_masked_rank_refresh_transcript_from_request(&json!({
            "setupPackage": setup_package,
            "rankRefreshTranscript": transcript
        }))
        .expect_err("mutated partial-decryption share payload must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("partial-decryption share coefficient hash"),
            "{}",
            error.message
        );

        let setup_package = generated_setup_package();
        let mut transcript = transcript_without_root(&setup_package);
        transcript["rankRefreshShareRecords"][0]["shareEquationProofRoot"] =
            Value::String(hash("0"));
        let transcript = complete_transcript_from_without_root(transcript);
        let error = verify_masked_rank_refresh_transcript_from_request(&json!({
            "setupPackage": setup_package,
            "rankRefreshTranscript": transcript
        }))
        .expect_err("wrong proof statement root must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error.message.contains("share-equation proof root"),
            "{}",
            error.message
        );

        let setup_package = generated_setup_package();
        let mut transcript = transcript_without_root(&setup_package);
        transcript["rankRefreshShareRecords"][0]["shareEquationProof"]["proofBytesHash"] =
            Value::String(hash("0"));
        rebind_first_share_equation_proof_root(&mut transcript);
        let transcript = complete_transcript_from_without_root(transcript);
        let error = verify_masked_rank_refresh_transcript_from_request(&json!({
            "setupPackage": setup_package,
            "rankRefreshTranscript": transcript
        }))
        .expect_err("wrong PartDec proof bytes hash must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("PartDec share-equation proof bytes hash"),
            "{}",
            error.message
        );

        let setup_package = generated_setup_package();
        let mut transcript = transcript_without_root(&setup_package);
        transcript["rankRefreshShareRecords"][0]["shareEquationProof"]["proofBytesHex"] =
            json!("AA");
        rebind_first_share_equation_proof_root(&mut transcript);
        let transcript = complete_transcript_from_without_root(transcript);
        let error = verify_masked_rank_refresh_transcript_from_request(&json!({
            "setupPackage": setup_package,
            "rankRefreshTranscript": transcript
        }))
        .expect_err("uppercase PartDec proof bytes must reject");

        assert_eq!(error.code, CanonicalErrorCode::InvalidHex);
        assert!(
            error.message.contains("canonical lowercase hexadecimal"),
            "{}",
            error.message
        );

        let setup_package = generated_setup_package();
        let mut transcript = transcript_without_root(&setup_package);
        transcript["rankRefreshShareRecords"][0]["shareEquationProof"]["proofStatementHash"] =
            Value::String(hash("0"));
        rebind_first_share_equation_proof_root_without_statement_hash(&mut transcript);
        let transcript = complete_transcript_from_without_root(transcript);
        let error = verify_masked_rank_refresh_transcript_from_request(&json!({
            "setupPackage": setup_package,
            "rankRefreshTranscript": transcript
        }))
        .expect_err("wrong PartDec proof public statement hash must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("PartDec share-equation public statement hash"),
            "{}",
            error.message
        );

        let setup_package = generated_setup_package();
        let mut transcript = transcript_without_root(&setup_package);
        transcript["smudgingBoundCertificate"]["boundProofBytesVerified"] = json!(true);
        rebind_smudging_bound_certificate_hash(&mut transcript);
        let transcript = complete_transcript_from_without_root(transcript);
        let error = verify_masked_rank_refresh_transcript_from_request(&json!({
            "setupPackage": setup_package,
            "rankRefreshTranscript": transcript
        }))
        .expect_err("premature smudging-bound proof verification must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error.message.contains("smudging-bound proof-byte"),
            "{}",
            error.message
        );

        let setup_package = generated_setup_package();
        let mut transcript = transcript_without_root(&setup_package);
        transcript["smudgingBoundCertificate"]["boundProofBytesHash"] = Value::String(hash("0"));
        rebind_smudging_bound_certificate_hash_without_proof_metadata_rebind(&mut transcript);
        let transcript = complete_transcript_from_without_root(transcript);
        let error = verify_masked_rank_refresh_transcript_from_request(&json!({
            "setupPackage": setup_package,
            "rankRefreshTranscript": transcript
        }))
        .expect_err("wrong smudging proof bytes hash must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error.message.contains("smudging-bound proof bytes hash"),
            "{}",
            error.message
        );

        let setup_package = generated_setup_package();
        let mut transcript = transcript_without_root(&setup_package);
        transcript["smudgingBoundCertificate"]["finalNoiseBoundBits"] =
            json!(data_basis_modulus_bits());
        rebind_smudging_bound_certificate_hash(&mut transcript);
        let transcript = complete_transcript_from_without_root(transcript);
        let error = verify_masked_rank_refresh_transcript_from_request(&json!({
            "setupPackage": setup_package,
            "rankRefreshTranscript": transcript
        }))
        .expect_err("over-budget smudging final noise bound must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error.message.contains("smudging-bound final noise budget"),
            "{}",
            error.message
        );

        let setup_package = generated_setup_package();
        let mut transcript = transcript_without_root(&setup_package);
        transcript["maskedOpening"]["proofSizeBytes"] = json!(99_u64);
        rebind_masked_opening_root(&mut transcript);
        let transcript = complete_transcript_from_without_root(transcript);
        let error = verify_masked_rank_refresh_transcript_from_request(&json!({
            "setupPackage": setup_package,
            "rankRefreshTranscript": transcript
        }))
        .expect_err("wrong FinDec proof byte size must reject");

        assert_eq!(error.code, CanonicalErrorCode::MalformedLength);
        assert!(
            error
                .message
                .contains("FinDec masked-opening proof byte size"),
            "{}",
            error.message
        );

        let setup_package = generated_setup_package();
        let mut transcript = transcript_without_root(&setup_package);
        transcript["maskedOpening"]["partialDecryptionShareRoots"][0] = Value::String(hash("0"));
        rebind_masked_opening_root(&mut transcript);
        let transcript = complete_transcript_from_without_root(transcript);
        let error = verify_masked_rank_refresh_transcript_from_request(&json!({
            "setupPackage": setup_package,
            "rankRefreshTranscript": transcript
        }))
        .expect_err("FinDec opening over different share roots must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("FinDec partial-decryption share roots"),
            "{}",
            error.message
        );

        let setup_package = generated_setup_package();
        let mut transcript = transcript_without_root(&setup_package);
        let input_rank_ciphertext = parse_bgv_object_hex(
            transcript["inputRankCiphertextComponentOnePayload"]["canonicalBytesHex"]
                .as_str()
                .expect("input rank canonical bytes"),
        )
        .expect("input rank ciphertext");
        let input_rank_ciphertext_component_zero = &input_rank_ciphertext.components[0];
        let mut coefficients = coefficient_vector_from_le_hex(
            transcript["maskedOpeningPayload"]["coefficientTables"][0]
                ["maskedOpeningCoefficientsLeHex"]
                .as_str()
                .expect("masked opening coefficients"),
            "masked opening coefficients",
        )
        .expect("masked opening coefficient vector");
        let component_zero_coefficients = input_ciphertext_component_zero_coefficients_for_modulus(
            input_rank_ciphertext_component_zero,
            0,
            DATA_PRIMES[0],
        )
        .expect("input ciphertext component-zero coefficients");
        for (coefficient, component_zero_coefficient) in
            coefficients.iter_mut().zip(component_zero_coefficients)
        {
            *coefficient = sub_mod(*coefficient, *component_zero_coefficient, DATA_PRIMES[0])
                .expect("masked opening without component zero");
        }
        transcript["maskedOpeningPayload"]["coefficientTables"][0]["maskedOpeningCoefficientsLeHex"] =
            json!(coefficient_vector_le_hex(&coefficients));
        transcript["maskedOpeningPayload"]["coefficientTables"][0]["maskedOpeningCoefficientHash512"] =
            json!(fin_dec_masked_opening_coefficient_hash(&coefficients));
        rebind_masked_opening_payload_root(&mut transcript);
        let transcript = complete_transcript_from_without_root(transcript);
        let error = verify_masked_rank_refresh_transcript_from_request(&json!({
            "setupPackage": setup_package,
            "rankRefreshTranscript": transcript
        }))
        .expect_err("FinDec masked-opening payload omitting input component zero must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("masked-opening payload coefficients do not match input component-zero plus selected-share Lagrange combination"),
            "{}",
            error.message
        );

        let setup_package = generated_setup_package();
        let mut transcript = transcript_without_root(&setup_package);
        transcript["maskReEncryptionProofRecords"][0]["proofBytesVerified"] = json!(true);
        let transcript = complete_transcript_from_without_root(transcript);
        let error = verify_masked_rank_refresh_transcript_from_request(&json!({
            "setupPackage": setup_package,
            "rankRefreshTranscript": transcript
        }))
        .expect_err("premature mask re-encryption proof verification must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error.message.contains("mask re-encryption proof-byte"),
            "{}",
            error.message
        );

        let setup_package = generated_setup_package();
        let mut transcript = transcript_without_root(&setup_package);
        transcript["encryptedMaskCiphertextPayload"]["ciphertextRoot"] = Value::String(hash("0"));
        rebind_encrypted_mask_ciphertext_payload_hash(&mut transcript);
        let transcript = complete_transcript_from_without_root(transcript);
        let error = verify_masked_rank_refresh_transcript_from_request(&json!({
            "setupPackage": setup_package,
            "rankRefreshTranscript": transcript
        }))
        .expect_err("encrypted mask payload root must match canonical ciphertext bytes");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("encrypted mask ciphertext payload ciphertext root"),
            "{}",
            error.message
        );

        let setup_package = generated_setup_package();
        let mut transcript = transcript_without_root(&setup_package);
        transcript["refreshedRankCiphertextPayload"]["ciphertextRoot"] = Value::String(hash("0"));
        rebind_refreshed_rank_ciphertext_payload_hash(&mut transcript);
        let transcript = complete_transcript_from_without_root(transcript);
        let error = verify_masked_rank_refresh_transcript_from_request(&json!({
            "setupPackage": setup_package,
            "rankRefreshTranscript": transcript
        }))
        .expect_err("refreshed rank payload root must match canonical ciphertext bytes");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("refreshed rank ciphertext payload ciphertext root"),
            "{}",
            error.message
        );

        let setup_package = generated_setup_package();
        let mut transcript = transcript_without_root(&setup_package);
        transcript["maskReEncryptionProofRecords"][0]["maskReEncryptionProofStatement"]["proofStatementHash"] =
            Value::String(hash("0"));
        rebind_mask_re_encryption_proof_root_without_statement_hash(&mut transcript);
        let transcript = complete_transcript_from_without_root(transcript);
        let error = verify_masked_rank_refresh_transcript_from_request(&json!({
            "setupPackage": setup_package,
            "rankRefreshTranscript": transcript
        }))
        .expect_err("wrong mask re-encryption public statement hash must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("mask re-encryption public statement hash"),
            "{}",
            error.message
        );

        let setup_package = generated_setup_package();
        let mut transcript = transcript_without_root(&setup_package);
        transcript["maskReEncryptionProofRecords"][0]["maskReEncryptionProofStatement"]["encryptedMaskCiphertextPayloadHash"] =
            Value::String(hash("0"));
        rebind_mask_re_encryption_proof_root(&mut transcript);
        let transcript = complete_transcript_from_without_root(transcript);
        let error = verify_masked_rank_refresh_transcript_from_request(&json!({
            "setupPackage": setup_package,
            "rankRefreshTranscript": transcript
        }))
        .expect_err("mask re-encryption over a different encrypted mask payload must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("encrypted mask ciphertext payload hash"),
            "{}",
            error.message
        );

        let setup_package = generated_setup_package();
        let mut transcript = transcript_without_root(&setup_package);
        transcript["maskReEncryptionProofRecords"][0]["maskReEncryptionProofStatement"]["refreshedRankCiphertextPayloadHash"] =
            Value::String(hash("0"));
        rebind_mask_re_encryption_proof_root(&mut transcript);
        let transcript = complete_transcript_from_without_root(transcript);
        let error = verify_masked_rank_refresh_transcript_from_request(&json!({
            "setupPackage": setup_package,
            "rankRefreshTranscript": transcript
        }))
        .expect_err("mask re-encryption over a different refreshed rank payload must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("refreshed rank ciphertext payload hash"),
            "{}",
            error.message
        );

        let setup_package = generated_setup_package();
        let mut transcript = transcript_without_root(&setup_package);
        transcript["maskReEncryptionProofRecords"][0]["maskReEncryptionProofStatement"]["refreshedRankCiphertextRoot"] =
            Value::String(hash("0"));
        rebind_mask_re_encryption_proof_root(&mut transcript);
        let transcript = complete_transcript_from_without_root(transcript);
        let error = verify_masked_rank_refresh_transcript_from_request(&json!({
            "setupPackage": setup_package,
            "rankRefreshTranscript": transcript
        }))
        .expect_err("mask re-encryption over a different refreshed rank root must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("mask re-encryption refreshed rank root"),
            "{}",
            error.message
        );
    }
}
