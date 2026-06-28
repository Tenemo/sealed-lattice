use super::setup_proof::{
    SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES, setup_proof_material_chunk_hash,
    setup_proof_material_chunk_manifest_root, setup_proof_material_full_object_hash,
};
use super::*;
use std::collections::BTreeSet;

pub(crate) const COMPACT_VSS_COMMITMENT_PROFILE_ID: &str =
    "sealed-lattice-compact-vss-sparse-linear-v1";
pub(super) const COMPACT_VSS_COMMITMENT_BINARY_FORMAT: &str =
    "sealed-lattice-compact-vss-commitment-binary-v1";
pub(crate) const COMPACT_VSS_OUTPUT_COORDINATE_COUNT: usize = 16;
pub(crate) const COMPACT_VSS_MESSAGE_DIGIT_COUNT: usize = 2;
pub(crate) const COMPACT_VSS_MESSAGE_BASE_DIGIT_TRIT_COUNT: usize = 17;
pub(crate) const COMPACT_VSS_MESSAGE_DIGIT_BASE: u64 = 129_140_163;
pub(crate) const COMPACT_VSS_RANDOMNESS_COLUMN_COUNT: usize = 2;
pub(in crate::bgv::setup) const COMPACT_VSS_PROJECTION_WEIGHT: usize = 32;
const COMPACT_VSS_COMMITMENT_MODULUS_LIMB_INDICES: [usize; 3] = [0, 1, 2];
const COMPACT_VSS_MATRIX_RESIDUE_HASH_DOMAIN: &str =
    "sealed-lattice-compact-vss-commitment/matrix-residue-v1";
const COMPACT_VSS_PROJECTION_INDEX_HASH_DOMAIN: &str =
    "sealed-lattice-compact-vss-commitment/projection-index-v1";
const COMPACT_VSS_OPENING_PAYLOAD_HASH_DOMAIN: &str =
    "sealed-lattice-compact-vss-commitment/opening-payload-v1";
const COMPACT_VSS_SHARE_LINKAGE_STATEMENT_RELATION: &str = "recipient share commitments open to Shamir evaluations of the coefficient commitments, and aggregate threshold commitments are the public sum of recipient share commitments";
const COMPACT_VSS_SHARE_LINKAGE_PROOF_FAMILY: &str = "compact-vss-share-linkage";
const COMPACT_VSS_SHARE_LINKAGE_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice-compact-vss-share-linkage-proof-bytes-v1";
const COMPACT_VSS_SHARE_LINKAGE_PROOF_MATERIAL_BINARY_MAGIC: &[u8] =
    b"SEALED-LATTICE-COMPACT-VSS-SHARE-LINKAGE-PROOF-MATERIAL-BINARY-V1";
const COMPACT_VSS_SHARE_LINKAGE_BINARY_TRANSPORT_OBJECT_TYPE: &str =
    "CompactVssShareLinkageBinaryProofMaterialTransport";
const COMPACT_VSS_SHARE_LINKAGE_BINARY_FORMAT: &str =
    "compact-vss-share-linkage-proof-material-binary-v1";
const COMPACT_VSS_SHARE_LINKAGE_PROOF_BATCHING_RULE: &str = "one public share-linkage statement record is bound per source trustee, batching every recipient and target-basis limb for that source";
const COMPACT_VSS_SHARE_LINKAGE_SHAMIR_EVALUATION_RULE: &str = "recipient-share commitments must open to the Shamir evaluation of the source trustee coefficient commitments at the recipient trustee point";
const COMPACT_VSS_SHARE_LINKAGE_AGGREGATE_THRESHOLD_RULE: &str = "aggregate threshold commitments must be the public sum of source-to-recipient share commitments for the same recipient and target-basis limb";
const COMPACT_VSS_SHARE_LINKAGE_COMMON_KEY_RULE: &str = "coefficient, recipient-share, and aggregate threshold compact commitments must use the same public matrix seed hash and compact commitment profile";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::setup) enum CompactVssMessageRangeEvidence {
    DigitAndTritColumns,
    DigitColumnsOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::setup) struct CompactVssMessageEncodingLayout {
    high_digit_trit_count: usize,
    range_evidence: CompactVssMessageRangeEvidence,
}

impl CompactVssMessageEncodingLayout {
    pub(in crate::bgv::setup) fn with_digit_columns_only(self) -> Self {
        Self {
            high_digit_trit_count: self.high_digit_trit_count,
            range_evidence: CompactVssMessageRangeEvidence::DigitColumnsOnly,
        }
    }

    pub(in crate::bgv::setup) fn has_digit_decoder_relations(self) -> bool {
        self.range_evidence == CompactVssMessageRangeEvidence::DigitAndTritColumns
    }

    pub(in crate::bgv::setup) fn digit_trit_count(
        self,
        digit_index: usize,
    ) -> CanonicalResult<usize> {
        if self.range_evidence == CompactVssMessageRangeEvidence::DigitColumnsOnly {
            return match digit_index {
                0 | 1 => Ok(0),
                _ => Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "compact VSS message digit index is outside the selected profile",
                )),
            };
        }
        match digit_index {
            0 => Ok(COMPACT_VSS_MESSAGE_BASE_DIGIT_TRIT_COUNT),
            1 => Ok(self.high_digit_trit_count),
            _ => Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "compact VSS message digit index is outside the selected profile",
            )),
        }
    }

    pub(in crate::bgv::setup) fn total_trit_count(self) -> usize {
        if self.range_evidence == CompactVssMessageRangeEvidence::DigitColumnsOnly {
            return 0;
        }
        COMPACT_VSS_MESSAGE_BASE_DIGIT_TRIT_COUNT + self.high_digit_trit_count
    }

    pub(in crate::bgv::setup) fn encoding_column_count(self) -> usize {
        COMPACT_VSS_MESSAGE_DIGIT_COUNT + self.total_trit_count()
    }

    pub(in crate::bgv::setup) fn digit_encoding_column(
        self,
        digit_index: usize,
    ) -> CanonicalResult<usize> {
        if self.range_evidence == CompactVssMessageRangeEvidence::DigitColumnsOnly {
            return match digit_index {
                0 => Ok(0),
                1 => Ok(1),
                _ => Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "compact VSS message digit index is outside the selected profile",
                )),
            };
        }
        match digit_index {
            0 => Ok(0),
            1 => Ok(1 + COMPACT_VSS_MESSAGE_BASE_DIGIT_TRIT_COUNT),
            _ => Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "compact VSS message digit index is outside the selected profile",
            )),
        }
    }

    pub(in crate::bgv::setup) fn trit_encoding_column(
        self,
        digit_index: usize,
        trit_index: usize,
    ) -> CanonicalResult<usize> {
        let trit_count = self.digit_trit_count(digit_index)?;
        if trit_index >= trit_count {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "compact VSS message trit index is outside the statement-bound layout",
            ));
        }

        Ok(self.digit_encoding_column(digit_index)? + 1 + trit_index)
    }
}

pub(crate) struct CompactVssCommitmentOpeningInput<'a> {
    pub(crate) commitment_role: &'a str,
    pub(crate) commitment_context: &'a Value,
    pub(crate) public_matrix_seed_hash: &'a str,
    pub(crate) rns_limb_index: usize,
    pub(crate) rns_prime: u64,
    pub(crate) ring_degree: usize,
    pub(crate) message_coefficients: &'a [u64],
    pub(crate) message_coefficient_bound: u64,
    pub(crate) randomness_by_column: &'a [Vec<i64>],
}

pub(crate) struct CompactVssCommitmentComputation {
    pub(crate) commitment: Value,
    pub(crate) commitment_root: String,
    pub(crate) commitment_context_hash: String,
    pub(crate) opening_root: String,
}

pub(crate) fn compute_compact_vss_commitment_from_opening(
    input: CompactVssCommitmentOpeningInput<'_>,
) -> CanonicalResult<CompactVssCommitmentComputation> {
    validate_hash_string(input.public_matrix_seed_hash, "publicMatrixSeedHash")?;
    validate_compact_vss_commitment_role(input.commitment_role)?;
    if input.rns_prime == 0 {
        return Err(invalid_compact_vss_input("rnsPrime must be positive"));
    }
    if input.ring_degree == 0 {
        return Err(invalid_compact_vss_input("ringDegree must be positive"));
    }
    if input.message_coefficient_bound == 0 {
        return Err(invalid_compact_vss_input(
            "messageCoefficientBound must be positive",
        ));
    }
    if input.message_coefficients.len() != input.ring_degree {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "compact VSS message coefficient count must match ringDegree",
        ));
    }
    for (coefficient_index, coefficient) in input.message_coefficients.iter().enumerate() {
        if *coefficient >= input.message_coefficient_bound {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "compact VSS message coefficient {coefficient_index} must be below messageCoefficientBound"
                ),
            ));
        }
        compact_vss_message_digits(*coefficient)?;
    }
    validate_compact_vss_randomness_columns(
        input.randomness_by_column,
        input.ring_degree,
        None,
        "randomnessByColumn",
    )?;

    let commitment_context_hash = derive_protocol_hash(
        "SetupCommitmentRoot",
        &json!({
            "objectType": "CompactVssCommitmentContext",
            "objectVersion": 1,
            "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
            "commitmentRole": input.commitment_role,
            "commitmentContext": input.commitment_context,
        }),
    )?;
    let commitment_limbs = COMPACT_VSS_COMMITMENT_MODULUS_LIMB_INDICES
        .iter()
        .map(|commitment_modulus_index| {
            let modulus = DATA_PRIMES[*commitment_modulus_index];
            let coordinates = (0..COMPACT_VSS_OUTPUT_COORDINATE_COUNT)
                .map(|output_coordinate_index| {
                    compact_commitment_coordinate(CompactCommitmentCoordinateInput {
                        public_matrix_seed_hash: input.public_matrix_seed_hash,
                        rns_limb_index: input.rns_limb_index,
                        commitment_modulus_index: *commitment_modulus_index,
                        output_coordinate_index,
                        modulus,
                        message_coefficients: input.message_coefficients,
                        randomness_by_column: input.randomness_by_column,
                    })
                })
                .collect::<CanonicalResult<Vec<_>>>()?;

            Ok(json!({
                "commitmentModulusIndex": commitment_modulus_index,
                "modulus": modulus,
                "coordinates": coordinates,
            }))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let commitment = json!({
        "objectType": "CompactVssCommitment",
        "objectVersion": 1,
        "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "commitmentRole": input.commitment_role,
        "commitmentContextHash": commitment_context_hash,
        "publicMatrixSeedHash": input.public_matrix_seed_hash,
        "rnsLimbIndex": input.rns_limb_index,
        "rnsPrime": input.rns_prime,
        "ringDegree": input.ring_degree,
        "outputCoordinateCount": COMPACT_VSS_OUTPUT_COORDINATE_COUNT,
        "randomnessColumnCount": COMPACT_VSS_RANDOMNESS_COLUMN_COUNT,
        "commitmentLimbs": commitment_limbs,
    });
    let commitment_root = derive_protocol_hash("SetupCommitmentRoot", &commitment)?;
    let opening_root = derive_protocol_hash(
        "SetupCommitmentRoot",
        &json!({
            "objectType": "CompactVssCommitmentOpening",
            "objectVersion": 1,
            "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
            "commitmentRole": input.commitment_role,
            "commitmentContext": input.commitment_context,
            "publicMatrixSeedHash": input.public_matrix_seed_hash,
            "rnsLimbIndex": input.rns_limb_index,
            "rnsPrime": input.rns_prime,
            "ringDegree": input.ring_degree,
            "openingPayloadHash512": compact_vss_opening_payload_hash(
                input.message_coefficients,
                input.randomness_by_column,
            )?,
        }),
    )?;

    Ok(CompactVssCommitmentComputation {
        commitment,
        commitment_root,
        commitment_context_hash,
        opening_root,
    })
}

pub(crate) fn compute_compact_vss_commitment_from_opening_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let computation = compute_compact_vss_commitment_from_opening_value(request)?;

    Ok(compact_vss_commitment_computation_response(&computation))
}

pub(crate) fn verify_compact_vss_commitment_opening_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let opening = value_at_path(request, &["opening"])?;
    let expected_commitment_root = hash_at_path(request, &["expectedCommitmentRoot"])?;
    let computation = compute_compact_vss_commitment_from_opening_value(opening)?;
    if computation.commitment_root != expected_commitment_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "compact VSS commitment opening does not match the expected commitment root",
        ));
    }

    Ok(json!({
        "ok": true,
        "operation": "verifyCompactVssCommitmentOpening",
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "commitmentRoot": computation.commitment_root,
    }))
}

pub(crate) fn encode_compact_vss_commitment_body_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let commitment = value_at_path(request, &["commitment"])?;
    validate_standalone_compact_vss_commitment_body(commitment, "compact VSS commitment")?;
    let commitment_body_bytes = encode_compact_vss_commitment_body_value(commitment)?;

    Ok(json!({
        "ok": true,
        "operation": "encodeCompactVssCommitmentBody",
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "binaryFormat": COMPACT_VSS_COMMITMENT_BINARY_FORMAT,
        "encodedCommitmentByteLength": compact_vss_encoded_commitment_byte_length(),
        "commitmentBodyBytesHex": crate::transcript_core::encode_hex(&commitment_body_bytes),
    }))
}

pub(crate) fn decode_compact_vss_commitment_body_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let metadata = value_at_path(request, &["metadata"])?;
    let commitment_body_bytes_hex = string_at_path(request, &["commitmentBodyBytesHex"])?;
    let commitment_body_bytes = crate::transcript_core::decode_hex(commitment_body_bytes_hex)?;
    let commitment = decode_compact_vss_commitment_body_value(metadata, &commitment_body_bytes)?;
    let commitment_root = derive_protocol_hash("SetupCommitmentRoot", &commitment)?;

    Ok(json!({
        "ok": true,
        "operation": "decodeCompactVssCommitmentBody",
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "binaryFormat": COMPACT_VSS_COMMITMENT_BINARY_FORMAT,
        "encodedCommitmentByteLength": compact_vss_encoded_commitment_byte_length(),
        "commitment": commitment,
        "commitmentRoot": commitment_root,
    }))
}

pub(crate) fn verify_compact_vss_coefficient_commitment_set_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let coefficient_set = value_at_path(request, &["coefficientCommitmentSet"])?;
    compare_required_string(
        string_at_path(coefficient_set, &["objectType"])?,
        "CompactVssCoefficientCommitmentSet",
        "compact VSS coefficient commitment set objectType",
    )?;
    compare_required_u64(
        unsigned_at_path(coefficient_set, &["objectVersion"])?,
        1,
        "compact VSS coefficient commitment set objectVersion",
    )?;
    compare_required_string(
        string_at_path(coefficient_set, &["setupProfileId"])?,
        COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "compact VSS coefficient commitment set setupProfileId",
    )?;
    compare_required_string(
        string_at_path(coefficient_set, &["profileId"])?,
        COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "compact VSS coefficient commitment set profileId",
    )?;
    let public_matrix_seed_hash = hash_at_path(coefficient_set, &["publicMatrixSeedHash"])?;
    let participant_count = read_positive_usize_at_path(
        coefficient_set,
        &["participantCount"],
        "compact VSS coefficient commitment set participantCount",
    )?;
    let rns_limb_count = read_positive_usize_at_path(
        coefficient_set,
        &["rnsLimbCount"],
        "compact VSS coefficient commitment set rnsLimbCount",
    )?;
    let threshold_degree = read_positive_usize_at_path(
        coefficient_set,
        &["thresholdDegree"],
        "compact VSS coefficient commitment set thresholdDegree",
    )?;
    let ring_degree = read_positive_usize_at_path(
        coefficient_set,
        &["ringDegree"],
        "compact VSS coefficient commitment set ringDegree",
    )?;
    let source_trustee_records = array_at_path(coefficient_set, &["sourceTrusteeRecords"])?;
    if source_trustee_records.len() != participant_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "compact VSS coefficient commitment set must contain one source record per participant",
        ));
    }
    let expected_coefficient_count =
        rns_limb_count
            .checked_mul(threshold_degree)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "compact VSS coefficient commitment coordinate count overflowed",
                )
            })?;

    let mut verified_source_trustee_records = Vec::with_capacity(source_trustee_records.len());
    for (expected_roster_position, source_record) in source_trustee_records.iter().enumerate() {
        verified_source_trustee_records.push(verify_compact_vss_source_coefficient_record(
            CompactVssSourceCoefficientRecordInput {
                source_record,
                expected_roster_position,
                expected_coefficient_count,
                threshold_degree,
                public_matrix_seed_hash,
            },
        )?);
    }

    let expected_set_root = derive_protocol_hash(
        "VssCoefficientCommitmentRoot",
        &json!({
            "objectType": "CompactVssCoefficientCommitmentSet",
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "participantCount": participant_count,
            "rnsLimbCount": rns_limb_count,
            "thresholdDegree": threshold_degree,
            "ringDegree": ring_degree,
            "sourceTrusteeRecords": verified_source_trustee_records,
        }),
    )?;
    let coefficient_commitment_root =
        hash_at_path(coefficient_set, &["coefficientCommitmentRoot"])?;
    if expected_set_root != coefficient_commitment_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "compact VSS coefficient commitment set root does not match its source records",
        ));
    }

    Ok(json!({
        "ok": true,
        "operation": "verifyCompactVssCoefficientCommitmentSet",
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "coefficientCommitmentRoot": coefficient_commitment_root,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "participantCount": participant_count,
        "rnsLimbCount": rns_limb_count,
        "thresholdDegree": threshold_degree,
        "ringDegree": ring_degree,
    }))
}

pub(crate) fn verify_compact_vss_recipient_share_commitment_set_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let recipient_set = value_at_path(request, &["recipientShareCommitmentSet"])?;
    compare_required_string(
        string_at_path(recipient_set, &["objectType"])?,
        "CompactVssRecipientShareCommitmentSet",
        "compact VSS recipient-share commitment set objectType",
    )?;
    compare_required_u64(
        unsigned_at_path(recipient_set, &["objectVersion"])?,
        1,
        "compact VSS recipient-share commitment set objectVersion",
    )?;
    compare_required_string(
        string_at_path(recipient_set, &["setupProfileId"])?,
        COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "compact VSS recipient-share commitment set setupProfileId",
    )?;
    compare_required_string(
        string_at_path(recipient_set, &["profileId"])?,
        COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "compact VSS recipient-share commitment set profileId",
    )?;
    let public_matrix_seed_hash = hash_at_path(recipient_set, &["publicMatrixSeedHash"])?;
    let participant_count = read_positive_usize_at_path(
        recipient_set,
        &["participantCount"],
        "compact VSS recipient-share commitment set participantCount",
    )?;
    let rns_limb_count = read_positive_usize_at_path(
        recipient_set,
        &["rnsLimbCount"],
        "compact VSS recipient-share commitment set rnsLimbCount",
    )?;
    let ring_degree = read_positive_usize_at_path(
        recipient_set,
        &["ringDegree"],
        "compact VSS recipient-share commitment set ringDegree",
    )?;
    let source_trustee_records = array_at_path(recipient_set, &["sourceTrusteeRecords"])?;
    if source_trustee_records.len() != participant_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "compact VSS recipient-share commitment set must contain one source record per participant",
        ));
    }
    let expected_recipient_share_count =
        participant_count
            .checked_mul(rns_limb_count)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "compact VSS recipient-share commitment coordinate count overflowed",
                )
            })?;

    let mut verified_source_trustee_records = Vec::with_capacity(source_trustee_records.len());
    for (expected_roster_position, source_record) in source_trustee_records.iter().enumerate() {
        verified_source_trustee_records.push(verify_compact_vss_source_recipient_share_record(
            CompactVssSourceRecipientShareRecordInput {
                source_record,
                expected_source_roster_position: expected_roster_position,
                expected_recipient_share_count,
                rns_limb_count,
                public_matrix_seed_hash,
            },
        )?);
    }

    let expected_set_root = derive_protocol_hash(
        "ThresholdShareCommitmentRoot",
        &json!({
            "objectType": "CompactVssRecipientShareCommitmentSet",
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "participantCount": participant_count,
            "rnsLimbCount": rns_limb_count,
            "ringDegree": ring_degree,
            "sourceTrusteeRecords": verified_source_trustee_records,
        }),
    )?;
    let recipient_share_commitment_root =
        hash_at_path(recipient_set, &["recipientShareCommitmentRoot"])?;
    if expected_set_root != recipient_share_commitment_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "compact VSS recipient-share commitment set root does not match its source records",
        ));
    }

    Ok(json!({
        "ok": true,
        "operation": "verifyCompactVssRecipientShareCommitmentSet",
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "recipientShareCommitmentRoot": recipient_share_commitment_root,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "participantCount": participant_count,
        "rnsLimbCount": rns_limb_count,
        "ringDegree": ring_degree,
    }))
}

pub(crate) fn verify_compact_vss_aggregate_threshold_commitment_set_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let aggregate_set = value_at_path(request, &["aggregateThresholdCommitmentSet"])?;
    compare_required_string(
        string_at_path(aggregate_set, &["objectType"])?,
        "CompactVssAggregateThresholdCommitmentSet",
        "compact VSS aggregate threshold commitment set objectType",
    )?;
    compare_required_u64(
        unsigned_at_path(aggregate_set, &["objectVersion"])?,
        1,
        "compact VSS aggregate threshold commitment set objectVersion",
    )?;
    compare_required_string(
        string_at_path(aggregate_set, &["setupProfileId"])?,
        COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "compact VSS aggregate threshold commitment set setupProfileId",
    )?;
    compare_required_string(
        string_at_path(aggregate_set, &["profileId"])?,
        COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "compact VSS aggregate threshold commitment set profileId",
    )?;
    let public_matrix_seed_hash = hash_at_path(aggregate_set, &["publicMatrixSeedHash"])?;
    let participant_count = read_positive_usize_at_path(
        aggregate_set,
        &["participantCount"],
        "compact VSS aggregate threshold commitment set participantCount",
    )?;
    let rns_limb_count = read_positive_usize_at_path(
        aggregate_set,
        &["rnsLimbCount"],
        "compact VSS aggregate threshold commitment set rnsLimbCount",
    )?;
    let ring_degree = read_positive_usize_at_path(
        aggregate_set,
        &["ringDegree"],
        "compact VSS aggregate threshold commitment set ringDegree",
    )?;
    let recipient_records = array_at_path(aggregate_set, &["recipientRecords"])?;
    let expected_recipient_record_count = participant_count
        .checked_mul(rns_limb_count)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "compact VSS aggregate threshold commitment coordinate count overflowed",
            )
        })?;
    if recipient_records.len() != expected_recipient_record_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "compact VSS aggregate threshold commitment set must cover every recipient and RNS limb",
        ));
    }

    let mut verified_recipient_records = Vec::with_capacity(recipient_records.len());
    for (recipient_record_index, recipient_record) in recipient_records.iter().enumerate() {
        verified_recipient_records.push(verify_compact_vss_aggregate_threshold_record(
            CompactVssAggregateThresholdRecordInput {
                recipient_record,
                expected_recipient_roster_position: recipient_record_index / rns_limb_count,
                expected_rns_limb_index: recipient_record_index % rns_limb_count,
                participant_count,
                public_matrix_seed_hash,
            },
        )?);
    }

    let expected_set_root = derive_protocol_hash(
        "ThresholdShareCommitmentRoot",
        &json!({
            "objectType": "CompactVssAggregateThresholdCommitmentSet",
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "participantCount": participant_count,
            "rnsLimbCount": rns_limb_count,
            "ringDegree": ring_degree,
            "recipientRecords": verified_recipient_records,
        }),
    )?;
    let aggregate_threshold_commitment_root =
        hash_at_path(aggregate_set, &["aggregateThresholdCommitmentRoot"])?;
    if expected_set_root != aggregate_threshold_commitment_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "compact VSS aggregate threshold commitment set root does not match its recipient records",
        ));
    }

    Ok(json!({
        "ok": true,
        "operation": "verifyCompactVssAggregateThresholdCommitmentSet",
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "aggregateThresholdCommitmentRoot": aggregate_threshold_commitment_root,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "participantCount": participant_count,
        "rnsLimbCount": rns_limb_count,
        "ringDegree": ring_degree,
    }))
}

pub(crate) fn verify_compact_vss_share_linkage_statement_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let statement = value_at_path(request, &["statement"])?;
    compare_required_string(
        string_at_path(statement, &["objectType"])?,
        "CompactVssShareLinkageStatement",
        "compact VSS share linkage statement objectType",
    )?;
    compare_required_u64(
        unsigned_at_path(statement, &["objectVersion"])?,
        1,
        "compact VSS share linkage statement objectVersion",
    )?;
    compare_required_string(
        string_at_path(statement, &["setupProfileId"])?,
        COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "compact VSS share linkage statement setupProfileId",
    )?;
    compare_required_string(
        string_at_path(statement, &["profileId"])?,
        COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "compact VSS share linkage statement profileId",
    )?;
    let ceremony_id = read_non_empty_string(statement, "ceremonyId")?;
    let setup_epoch = read_non_empty_string(statement, "setupEpoch")?;
    let manifest_hash = hash_at_path(statement, &["manifestHash"])?;
    let roster_hash = hash_at_path(statement, &["rosterHash"])?;
    let setup_profile_hash = hash_at_path(statement, &["setupProfileHash"])?;
    let q_share_hash = hash_at_path(statement, &["qShareHash"])?;
    let carry_aware_vss_share_relation_profile_hash =
        hash_at_path(statement, &["carryAwareVssShareRelationProfileHash"])?;
    let commitment_profile_hash = hash_at_path(statement, &["commitmentProfileHash"])?;
    let public_matrix_seed_hash = hash_at_path(statement, &["publicMatrixSeedHash"])?;
    let target_basis_hash = hash_at_path(statement, &["targetBasisHash"])?;
    let coefficient_commitment_root = hash_at_path(statement, &["coefficientCommitmentRoot"])?;
    let recipient_share_commitment_root =
        hash_at_path(statement, &["recipientShareCommitmentRoot"])?;
    let aggregate_threshold_commitment_root =
        hash_at_path(statement, &["aggregateThresholdCommitmentRoot"])?;
    let participant_count = read_positive_usize_at_path(
        statement,
        &["participantCount"],
        "compact VSS share linkage statement participantCount",
    )?;
    let target_rns_limb_count = read_positive_usize_at_path(
        statement,
        &["targetRnsLimbCount"],
        "compact VSS share linkage statement targetRnsLimbCount",
    )?;
    let threshold_degree = read_positive_usize_at_path(
        statement,
        &["thresholdDegree"],
        "compact VSS share linkage statement thresholdDegree",
    )?;
    compare_required_string(
        string_at_path(statement, &["relation"])?,
        COMPACT_VSS_SHARE_LINKAGE_STATEMENT_RELATION,
        "compact VSS share linkage statement relation",
    )?;
    compare_required_string(
        string_at_path(statement, &["proofBatchingRule"])?,
        COMPACT_VSS_SHARE_LINKAGE_PROOF_BATCHING_RULE,
        "compact VSS share linkage statement proofBatchingRule",
    )?;
    compare_required_string(
        string_at_path(statement, &["shamirEvaluationRule"])?,
        COMPACT_VSS_SHARE_LINKAGE_SHAMIR_EVALUATION_RULE,
        "compact VSS share linkage statement shamirEvaluationRule",
    )?;
    compare_required_string(
        string_at_path(statement, &["aggregateThresholdRule"])?,
        COMPACT_VSS_SHARE_LINKAGE_AGGREGATE_THRESHOLD_RULE,
        "compact VSS share linkage statement aggregateThresholdRule",
    )?;
    compare_required_string(
        string_at_path(statement, &["commonKeyRule"])?,
        COMPACT_VSS_SHARE_LINKAGE_COMMON_KEY_RULE,
        "compact VSS share linkage statement commonKeyRule",
    )?;
    let source_statement_records = array_at_path(statement, &["sourceStatementRecords"])?;
    if source_statement_records.len() != participant_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "compact VSS share linkage statement must contain one source statement per participant",
        ));
    }
    let mut verified_source_statement_records = Vec::with_capacity(source_statement_records.len());
    for (expected_source_position, source_statement_record) in
        source_statement_records.iter().enumerate()
    {
        verified_source_statement_records.push(verify_compact_vss_share_linkage_source_statement(
            CompactVssShareLinkageSourceStatementInput {
                source_statement_record,
                expected_source_position,
                statement: CompactVssShareLinkageStatementBinding {
                    ceremony_id,
                    manifest_hash,
                    roster_hash,
                    setup_profile_hash,
                    q_share_hash,
                    carry_aware_vss_share_relation_profile_hash,
                    commitment_profile_hash,
                    setup_epoch,
                    public_matrix_seed_hash,
                    target_basis_hash,
                    participant_count,
                    target_rns_limb_count,
                    threshold_degree,
                    coefficient_commitment_root,
                    aggregate_threshold_commitment_root,
                },
            },
        )?);
    }
    let statement_root = hash_at_path(statement, &["statementRoot"])?;
    let statement_without_root = json!({
        "objectType": "CompactVssShareLinkageStatement",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupProfileHash": setup_profile_hash,
        "qShareHash": q_share_hash,
        "carryAwareVssShareRelationProfileHash": carry_aware_vss_share_relation_profile_hash,
        "commitmentProfileHash": commitment_profile_hash,
        "setupEpoch": setup_epoch,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "targetBasisHash": target_basis_hash,
        "participantCount": participant_count,
        "targetRnsLimbCount": target_rns_limb_count,
        "thresholdDegree": threshold_degree,
        "coefficientCommitmentRoot": coefficient_commitment_root,
        "recipientShareCommitmentRoot": recipient_share_commitment_root,
        "aggregateThresholdCommitmentRoot": aggregate_threshold_commitment_root,
        "relation": COMPACT_VSS_SHARE_LINKAGE_STATEMENT_RELATION,
        "proofBatchingRule": COMPACT_VSS_SHARE_LINKAGE_PROOF_BATCHING_RULE,
        "shamirEvaluationRule": COMPACT_VSS_SHARE_LINKAGE_SHAMIR_EVALUATION_RULE,
        "aggregateThresholdRule": COMPACT_VSS_SHARE_LINKAGE_AGGREGATE_THRESHOLD_RULE,
        "commonKeyRule": COMPACT_VSS_SHARE_LINKAGE_COMMON_KEY_RULE,
        "sourceStatementRecords": verified_source_statement_records,
    });
    let expected_statement_root =
        derive_protocol_hash("SetupProofRecordBindingHash", &statement_without_root)?;
    if expected_statement_root != statement_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "compact VSS share linkage statement root does not match its bound public roots",
        ));
    }
    verify_optional_compact_vss_share_linkage_evidence(CompactVssShareLinkageEvidenceInput {
        request,
        statement: CompactVssShareLinkageStatementBinding {
            ceremony_id,
            manifest_hash,
            roster_hash,
            setup_profile_hash,
            q_share_hash,
            carry_aware_vss_share_relation_profile_hash,
            commitment_profile_hash,
            setup_epoch,
            public_matrix_seed_hash,
            target_basis_hash,
            participant_count,
            target_rns_limb_count,
            threshold_degree,
            coefficient_commitment_root,
            aggregate_threshold_commitment_root,
        },
        recipient_share_commitment_root,
        verified_source_statement_records: &verified_source_statement_records,
    })?;

    Ok(json!({
        "ok": true,
        "operation": "verifyCompactVssShareLinkageStatement",
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "statementRoot": statement_root,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "targetBasisHash": target_basis_hash,
        "participantCount": participant_count,
        "targetRnsLimbCount": target_rns_limb_count,
        "thresholdDegree": threshold_degree,
        "coefficientCommitmentRoot": coefficient_commitment_root,
        "recipientShareCommitmentRoot": recipient_share_commitment_root,
        "aggregateThresholdCommitmentRoot": aggregate_threshold_commitment_root,
        "proofBatchingRule": COMPACT_VSS_SHARE_LINKAGE_PROOF_BATCHING_RULE,
        "shamirEvaluationRule": COMPACT_VSS_SHARE_LINKAGE_SHAMIR_EVALUATION_RULE,
        "aggregateThresholdRule": COMPACT_VSS_SHARE_LINKAGE_AGGREGATE_THRESHOLD_RULE,
        "commonKeyRule": COMPACT_VSS_SHARE_LINKAGE_COMMON_KEY_RULE,
    }))
}

pub(crate) fn verify_compact_vss_share_linkage_proof_material_set_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let statement = value_at_path(request, &["statement"])?;
    let statement_verification =
        verify_compact_vss_share_linkage_statement_request(&json!({ "statement": statement }))?;
    let statement_root = hash_at_path(&statement_verification, &["statementRoot"])?;
    let participant_count = read_positive_usize_at_path(
        &statement_verification,
        &["participantCount"],
        "compact VSS share-linkage proof material statement participantCount",
    )?;
    let target_rns_limb_count = read_positive_usize_at_path(
        &statement_verification,
        &["targetRnsLimbCount"],
        "compact VSS share-linkage proof material statement targetRnsLimbCount",
    )?;
    let threshold_degree = read_positive_usize_at_path(
        &statement_verification,
        &["thresholdDegree"],
        "compact VSS share-linkage proof material statement thresholdDegree",
    )?;
    let coefficient_commitment_set = value_at_path(request, &["coefficientCommitmentSet"])?;
    let recipient_share_commitment_set = value_at_path(request, &["recipientShareCommitmentSet"])?;
    let coefficient_verification = verify_compact_vss_coefficient_commitment_set_request(&json!({
        "coefficientCommitmentSet": coefficient_commitment_set,
    }))?;
    let recipient_verification =
        verify_compact_vss_recipient_share_commitment_set_request(&json!({
            "recipientShareCommitmentSet": recipient_share_commitment_set,
        }))?;
    compare_required_string(
        hash_at_path(&coefficient_verification, &["coefficientCommitmentRoot"])?,
        hash_at_path(statement, &["coefficientCommitmentRoot"])?,
        "compact VSS share-linkage proof material coefficientCommitmentRoot",
    )?;
    compare_required_string(
        hash_at_path(&recipient_verification, &["recipientShareCommitmentRoot"])?,
        hash_at_path(statement, &["recipientShareCommitmentRoot"])?,
        "compact VSS share-linkage proof material recipientShareCommitmentRoot",
    )?;
    for (verification, description) in [
        (&coefficient_verification, "coefficient"),
        (&recipient_verification, "recipient-share"),
    ] {
        compare_required_string(
            hash_at_path(verification, &["publicMatrixSeedHash"])?,
            hash_at_path(statement, &["publicMatrixSeedHash"])?,
            &format!("compact VSS share-linkage proof material {description} publicMatrixSeedHash"),
        )?;
        compare_required_u64(
            unsigned_at_path(verification, &["participantCount"])?,
            participant_count as u64,
            &format!("compact VSS share-linkage proof material {description} participantCount"),
        )?;
        compare_required_u64(
            unsigned_at_path(verification, &["rnsLimbCount"])?,
            target_rns_limb_count as u64,
            &format!("compact VSS share-linkage proof material {description} rnsLimbCount"),
        )?;
    }
    compare_required_u64(
        unsigned_at_path(&coefficient_verification, &["thresholdDegree"])?,
        threshold_degree as u64,
        "compact VSS share-linkage proof material coefficient thresholdDegree",
    )?;
    let ring_degree = read_positive_usize_at_path(
        &coefficient_verification,
        &["ringDegree"],
        "compact VSS share-linkage proof material coefficient ringDegree",
    )?;
    compare_required_u64(
        unsigned_at_path(&recipient_verification, &["ringDegree"])?,
        ring_degree as u64,
        "compact VSS share-linkage proof material recipient-share ringDegree",
    )?;
    let proof_material_set = value_at_path(request, &["proofMaterialSet"])?;
    compare_required_string(
        string_at_path(proof_material_set, &["objectType"])?,
        "CompactVssShareLinkageProofMaterialSet",
        "compact VSS share-linkage proof material set objectType",
    )?;
    compare_required_u64(
        unsigned_at_path(proof_material_set, &["objectVersion"])?,
        1,
        "compact VSS share-linkage proof material set objectVersion",
    )?;
    compare_required_string(
        string_at_path(proof_material_set, &["setupProfileId"])?,
        COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "compact VSS share-linkage proof material set setupProfileId",
    )?;
    compare_required_string(
        string_at_path(proof_material_set, &["profileId"])?,
        COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "compact VSS share-linkage proof material set profileId",
    )?;
    compare_required_string(
        string_at_path(proof_material_set, &["proofFamily"])?,
        COMPACT_VSS_SHARE_LINKAGE_PROOF_FAMILY,
        "compact VSS share-linkage proof material set proofFamily",
    )?;
    let ceremony_id = string_at_path(statement, &["ceremonyId"])?;
    let setup_epoch = string_at_path(statement, &["setupEpoch"])?;
    let manifest_hash = hash_at_path(statement, &["manifestHash"])?;
    let roster_hash = hash_at_path(statement, &["rosterHash"])?;
    let setup_profile_hash = hash_at_path(statement, &["setupProfileHash"])?;
    let q_share_hash = hash_at_path(statement, &["qShareHash"])?;
    let carry_aware_vss_share_relation_profile_hash =
        hash_at_path(statement, &["carryAwareVssShareRelationProfileHash"])?;
    let commitment_profile_hash = hash_at_path(statement, &["commitmentProfileHash"])?;
    let public_matrix_seed_hash = hash_at_path(statement, &["publicMatrixSeedHash"])?;
    compare_required_string(
        string_at_path(proof_material_set, &["ceremonyId"])?,
        ceremony_id,
        "compact VSS share-linkage proof material set ceremonyId",
    )?;
    compare_required_string(
        hash_at_path(proof_material_set, &["manifestHash"])?,
        manifest_hash,
        "compact VSS share-linkage proof material set manifestHash",
    )?;
    compare_required_string(
        hash_at_path(proof_material_set, &["rosterHash"])?,
        roster_hash,
        "compact VSS share-linkage proof material set rosterHash",
    )?;
    compare_required_string(
        hash_at_path(proof_material_set, &["setupProfileHash"])?,
        setup_profile_hash,
        "compact VSS share-linkage proof material set setupProfileHash",
    )?;
    compare_required_string(
        hash_at_path(proof_material_set, &["qShareHash"])?,
        q_share_hash,
        "compact VSS share-linkage proof material set qShareHash",
    )?;
    compare_required_string(
        hash_at_path(
            proof_material_set,
            &["carryAwareVssShareRelationProfileHash"],
        )?,
        carry_aware_vss_share_relation_profile_hash,
        "compact VSS share-linkage proof material set carryAwareVssShareRelationProfileHash",
    )?;
    compare_required_string(
        hash_at_path(proof_material_set, &["commitmentProfileHash"])?,
        commitment_profile_hash,
        "compact VSS share-linkage proof material set commitmentProfileHash",
    )?;
    compare_required_string(
        string_at_path(proof_material_set, &["setupEpoch"])?,
        setup_epoch,
        "compact VSS share-linkage proof material set setupEpoch",
    )?;
    compare_required_u64(
        unsigned_at_path(proof_material_set, &["participantCount"])?,
        participant_count as u64,
        "compact VSS share-linkage proof material set participantCount",
    )?;
    compare_required_string(
        hash_at_path(proof_material_set, &["shareLinkageStatementRoot"])?,
        statement_root,
        "compact VSS share-linkage proof material set shareLinkageStatementRoot",
    )?;

    let source_statement_records = array_at_path(statement, &["sourceStatementRecords"])?;
    let coefficient_source_records =
        array_at_path(coefficient_commitment_set, &["sourceTrusteeRecords"])?;
    let recipient_source_records =
        array_at_path(recipient_share_commitment_set, &["sourceTrusteeRecords"])?;
    if coefficient_source_records.len() != participant_count
        || recipient_source_records.len() != participant_count
        || source_statement_records.len() != participant_count
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "compact VSS share-linkage proof material public sets must cover every source statement",
        ));
    }
    let proof_materials = array_at_path(proof_material_set, &["proofMaterials"])?;
    if proof_materials.len() != participant_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "compact VSS share-linkage proof material set must contain one proof per source statement",
        ));
    }
    let mut total_proof_byte_length = 0usize;
    let mut proof_record_count = 0usize;
    let mut verified_restricted_proof_count = 0usize;
    let mut verified_proof_materials = Vec::with_capacity(proof_materials.len());
    for (source_statement_index, proof_material) in proof_materials.iter().enumerate() {
        let source_statement = source_statement_records
            .get(source_statement_index)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "compact VSS share-linkage proof material set has no matching source statement",
                )
            })?;
        let coefficient_source_record =
            coefficient_source_records
                .get(source_statement_index)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "compact VSS share-linkage proof material coefficient set is missing a source record",
                    )
                })?;
        let recipient_source_record =
            recipient_source_records
                .get(source_statement_index)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "compact VSS share-linkage proof material recipient-share set is missing a source record",
                    )
                })?;
        compare_required_string(
            string_at_path(proof_material, &["objectType"])?,
            "CompactVssShareLinkageProofMaterial",
            "compact VSS share-linkage proof material objectType",
        )?;
        compare_required_u64(
            unsigned_at_path(proof_material, &["objectVersion"])?,
            1,
            "compact VSS share-linkage proof material objectVersion",
        )?;
        compare_required_string(
            string_at_path(proof_material, &["setupProfileId"])?,
            COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "compact VSS share-linkage proof material setupProfileId",
        )?;
        compare_required_string(
            string_at_path(proof_material, &["profileId"])?,
            COMPACT_VSS_COMMITMENT_PROFILE_ID,
            "compact VSS share-linkage proof material profileId",
        )?;
        compare_required_string(
            string_at_path(proof_material, &["proofFamily"])?,
            COMPACT_VSS_SHARE_LINKAGE_PROOF_FAMILY,
            "compact VSS share-linkage proof material proofFamily",
        )?;
        compare_required_string(
            string_at_path(proof_material, &["ceremonyId"])?,
            ceremony_id,
            "compact VSS share-linkage proof material ceremonyId",
        )?;
        compare_required_string(
            hash_at_path(proof_material, &["manifestHash"])?,
            manifest_hash,
            "compact VSS share-linkage proof material manifestHash",
        )?;
        compare_required_string(
            hash_at_path(proof_material, &["rosterHash"])?,
            roster_hash,
            "compact VSS share-linkage proof material rosterHash",
        )?;
        compare_required_string(
            hash_at_path(proof_material, &["setupProfileHash"])?,
            setup_profile_hash,
            "compact VSS share-linkage proof material setupProfileHash",
        )?;
        compare_required_string(
            hash_at_path(proof_material, &["qShareHash"])?,
            q_share_hash,
            "compact VSS share-linkage proof material qShareHash",
        )?;
        compare_required_string(
            hash_at_path(proof_material, &["carryAwareVssShareRelationProfileHash"])?,
            carry_aware_vss_share_relation_profile_hash,
            "compact VSS share-linkage proof material carryAwareVssShareRelationProfileHash",
        )?;
        compare_required_string(
            hash_at_path(proof_material, &["commitmentProfileHash"])?,
            commitment_profile_hash,
            "compact VSS share-linkage proof material commitmentProfileHash",
        )?;
        compare_required_string(
            string_at_path(proof_material, &["setupEpoch"])?,
            setup_epoch,
            "compact VSS share-linkage proof material setupEpoch",
        )?;
        let source_trustee_identity = string_at_path(source_statement, &["sourceTrusteeIdentity"])?;
        compare_required_string(
            string_at_path(coefficient_source_record, &["sourceTrusteeIdentity"])?,
            source_trustee_identity,
            "compact VSS share-linkage proof material coefficient sourceTrusteeIdentity",
        )?;
        compare_required_string(
            string_at_path(recipient_source_record, &["sourceTrusteeIdentity"])?,
            source_trustee_identity,
            "compact VSS share-linkage proof material recipient sourceTrusteeIdentity",
        )?;
        compare_required_u64(
            unsigned_at_path(coefficient_source_record, &["sourceTrusteeRosterPosition"])?,
            source_statement_index as u64,
            "compact VSS share-linkage proof material coefficient sourceTrusteeRosterPosition",
        )?;
        compare_required_u64(
            unsigned_at_path(recipient_source_record, &["sourceTrusteeRosterPosition"])?,
            source_statement_index as u64,
            "compact VSS share-linkage proof material recipient sourceTrusteeRosterPosition",
        )?;
        compare_required_string(
            hash_at_path(
                coefficient_source_record,
                &["sourceCoefficientCommitmentRoot"],
            )?,
            hash_at_path(source_statement, &["sourceCoefficientCommitmentRoot"])?,
            "compact VSS share-linkage proof material sourceCoefficientCommitmentRoot",
        )?;
        compare_required_string(
            hash_at_path(
                recipient_source_record,
                &["sourceRecipientShareCommitmentRoot"],
            )?,
            hash_at_path(source_statement, &["sourceRecipientShareCommitmentRoot"])?,
            "compact VSS share-linkage proof material sourceRecipientShareCommitmentRoot",
        )?;
        compact_vss_share_linkage_compare_source_opening_roots(
            source_statement,
            coefficient_source_record,
            recipient_source_record,
        )?;
        compare_required_string(
            string_at_path(proof_material, &["sourceTrusteeIdentity"])?,
            source_trustee_identity,
            "compact VSS share-linkage proof material sourceTrusteeIdentity",
        )?;
        compare_required_u64(
            unsigned_at_path(proof_material, &["sourceTrusteeRosterPosition"])?,
            source_statement_index as u64,
            "compact VSS share-linkage proof material sourceTrusteeRosterPosition",
        )?;
        compare_required_string(
            hash_at_path(proof_material, &["shareLinkageStatementRoot"])?,
            statement_root,
            "compact VSS share-linkage proof material shareLinkageStatementRoot",
        )?;
        let source_statement_root = hash_at_path(source_statement, &["sourceStatementRoot"])?;
        compare_required_string(
            hash_at_path(proof_material, &["sourceStatementRoot"])?,
            source_statement_root,
            "compact VSS share-linkage proof material sourceStatementRoot",
        )?;
        let proof_records = array_at_path(proof_material, &["proofRecords"])?;
        if proof_records.is_empty() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "compact VSS share-linkage proof material proofRecords must be non-empty",
            ));
        }
        let mut proof_statement_hashes_for_material = BTreeSet::new();
        let mut restricted_coverage_for_material = BTreeSet::new();
        let mut pending_proof_verifications = Vec::with_capacity(proof_records.len());
        let mut verified_proof_records = Vec::with_capacity(proof_records.len());
        for proof_record in proof_records {
            compare_required_string(
                string_at_path(proof_record, &["objectType"])?,
                "CompactVssShareLinkageProofRecord",
                "compact VSS share-linkage proof record objectType",
            )?;
            compare_required_u64(
                unsigned_at_path(proof_record, &["objectVersion"])?,
                1,
                "compact VSS share-linkage proof record objectVersion",
            )?;
            compare_required_string(
                string_at_path(proof_record, &["proofFamily"])?,
                COMPACT_VSS_SHARE_LINKAGE_PROOF_FAMILY,
                "compact VSS share-linkage proof record proofFamily",
            )?;
            compare_required_string(
                hash_at_path(proof_record, &["sourceStatementRoot"])?,
                source_statement_root,
                "compact VSS share-linkage proof record sourceStatementRoot",
            )?;
            let proof_statement_hash = hash_at_path(proof_record, &["proofStatementHash"])?;
            if !proof_statement_hashes_for_material.insert(proof_statement_hash.to_string()) {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "compact VSS share-linkage proof material proofRecords must not repeat a proof statement hash",
                ));
            }
            let linkage_items = compact_vss_share_linkage_proof_record_linkage_items(
                proof_record,
                participant_count,
                target_rns_limb_count,
            )?;
            if linkage_items.is_empty() {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "compact VSS share-linkage proof record linkageItems must be non-empty",
                ));
            }
            for linkage_item in &linkage_items {
                if !restricted_coverage_for_material.insert((
                    linkage_item.recipient_roster_position,
                    linkage_item.source_rns_limb_index,
                )) {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::ProfileComponentMismatch,
                        "compact VSS share-linkage proof record linkageItems must not repeat recipient and target-limb coverage for a source statement",
                    ));
                }
            }
            let proof_bytes_hash = hash_at_path(proof_record, &["proofBytesHash"])?;
            let proof_bytes_base64 = string_at_path(proof_record, &["proofBytesBase64"])?;
            let proof_bytes = crate::transcript_core::decode_standard_base64(
                proof_bytes_base64,
                "compact VSS share-linkage proofBytesBase64",
            )?;
            let proof_byte_length = proof_bytes.len();
            let expected_proof_bytes_hash = hash512_hex(
                COMPACT_VSS_SHARE_LINKAGE_PROOF_BYTES_HASH_DOMAIN,
                &[&proof_bytes],
            );
            compare_required_string(
                proof_bytes_hash,
                &expected_proof_bytes_hash,
                "compact VSS share-linkage proof record proofBytesHash",
            )?;
            total_proof_byte_length = total_proof_byte_length
                .checked_add(proof_byte_length)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "compact VSS share-linkage proof material byte length overflowed",
                    )
                })?;
            proof_record_count = proof_record_count.checked_add(1).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "compact VSS share-linkage proof record count overflowed",
                )
            })?;
            let proof_record_without_root = json!({
                "objectType": "CompactVssShareLinkageProofRecord",
                "objectVersion": 1,
                "proofFamily": COMPACT_VSS_SHARE_LINKAGE_PROOF_FAMILY,
                "sourceStatementRoot": source_statement_root,
                "proofStatementHash": proof_statement_hash,
                "linkageItems": linkage_items
                    .iter()
                    .map(|linkage_item| linkage_item.to_value())
                    .collect::<Vec<_>>(),
                "proofBytesHash": proof_bytes_hash,
                "proofBytesBase64": proof_bytes_base64,
            });
            let proof_record_root = hash_at_path(proof_record, &["proofRecordRoot"])?;
            let expected_proof_record_root =
                derive_protocol_hash("SetupProofRecordBindingHash", &proof_record_without_root)?;
            if expected_proof_record_root != proof_record_root {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "compact VSS share-linkage proof record root does not match its bound proof bytes",
                ));
            }

            let proof_verification_request = compact_vss_share_linkage_proof_request_from_material(
                CompactVssShareLinkageProofRequestMaterialInput {
                    source_statement,
                    coefficient_source_record,
                    recipient_source_record,
                    linkage_items: &linkage_items,
                    proof_bytes: &proof_bytes,
                    ring_degree,
                    ceremony_id,
                    manifest_hash,
                    roster_hash,
                    setup_epoch,
                    public_matrix_seed_hash,
                    source_trustee_identity,
                    source_statement_index,
                    threshold_degree,
                    target_rns_limb_count,
                },
            )?;
            pending_proof_verifications.push((
                proof_verification_request,
                proof_statement_hash.to_string(),
                proof_byte_length,
            ));

            let mut verified_proof_record = proof_record_without_root;
            verified_proof_record["proofRecordRoot"] = json!(proof_record_root);
            verified_proof_records.push(verified_proof_record);
        }
        let expected_coverage_count = participant_count
            .checked_mul(target_rns_limb_count)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "restricted compact VSS coverage count overflowed",
                )
            })?;
        if restricted_coverage_for_material.len() != expected_coverage_count {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "compact VSS share-linkage proof record linkageItems must cover every recipient and target limb for each source statement",
            ));
        }
        for (proof_verification_request, proof_statement_hash, proof_byte_length) in
            pending_proof_verifications
        {
            let proof_verification = super::verify_compact_vss_share_linkage_proof_from_request(
                &proof_verification_request,
            )?;
            compare_required_string(
                string_at_path(&proof_verification, &["proofFamily"])?,
                COMPACT_VSS_SHARE_LINKAGE_PROOF_FAMILY,
                "restricted compact VSS proof verification proofFamily",
            )?;
            compare_required_string(
                hash_at_path(&proof_verification, &["statementHash"])?,
                &proof_statement_hash,
                "restricted compact VSS proof verification statementHash",
            )?;
            compare_required_u64(
                unsigned_at_path(&proof_verification, &["proofByteLength"])?,
                proof_byte_length as u64,
                "restricted compact VSS proof verification proofByteLength",
            )?;
            verified_restricted_proof_count += 1;
        }
        let proof_material_without_root = json!({
            "objectType": "CompactVssShareLinkageProofMaterial",
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
            "proofFamily": COMPACT_VSS_SHARE_LINKAGE_PROOF_FAMILY,
            "ceremonyId": ceremony_id,
            "manifestHash": manifest_hash,
            "rosterHash": roster_hash,
            "setupProfileHash": setup_profile_hash,
            "qShareHash": q_share_hash,
            "carryAwareVssShareRelationProfileHash": carry_aware_vss_share_relation_profile_hash,
            "commitmentProfileHash": commitment_profile_hash,
            "setupEpoch": setup_epoch,
            "sourceTrusteeIdentity": source_trustee_identity,
            "sourceTrusteeRosterPosition": source_statement_index,
            "shareLinkageStatementRoot": statement_root,
            "sourceStatementRoot": source_statement_root,
            "proofRecords": verified_proof_records,
        });
        let proof_material_root = hash_at_path(proof_material, &["proofMaterialRoot"])?;
        let expected_proof_material_root =
            derive_protocol_hash("SetupProofRecordBindingHash", &proof_material_without_root)?;
        if expected_proof_material_root != proof_material_root {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "compact VSS share-linkage proof material root does not match its bound proof records",
            ));
        }
        let mut verified_proof_material = proof_material_without_root;
        verified_proof_material["proofMaterialRoot"] = json!(proof_material_root);
        verified_proof_materials.push(verified_proof_material);
    }

    let proof_material_set_without_root = json!({
        "objectType": "CompactVssShareLinkageProofMaterialSet",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "proofFamily": COMPACT_VSS_SHARE_LINKAGE_PROOF_FAMILY,
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupProfileHash": setup_profile_hash,
        "qShareHash": q_share_hash,
        "carryAwareVssShareRelationProfileHash": carry_aware_vss_share_relation_profile_hash,
        "commitmentProfileHash": commitment_profile_hash,
        "setupEpoch": setup_epoch,
        "participantCount": participant_count,
        "shareLinkageStatementRoot": statement_root,
        "proofMaterials": verified_proof_materials,
    });
    let proof_material_set_root = hash_at_path(proof_material_set, &["proofMaterialSetRoot"])?;
    let expected_proof_material_set_root = derive_protocol_hash(
        "SetupProofRecordBindingHash",
        &proof_material_set_without_root,
    )?;
    if expected_proof_material_set_root != proof_material_set_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "compact VSS share-linkage proof material set root does not match its bound proof materials",
        ));
    }

    Ok(json!({
        "ok": true,
        "operation": "verifyCompactVssShareLinkageProofMaterialSet",
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "proofFamily": COMPACT_VSS_SHARE_LINKAGE_PROOF_FAMILY,
        "shareLinkageStatementRoot": statement_root,
        "proofMaterialSetRoot": proof_material_set_root,
        "participantCount": participant_count,
        "proofMaterialCount": proof_materials.len(),
        "proofRecordCount": proof_record_count,
        "totalProofByteLength": total_proof_byte_length,
        "restrictedProofVerificationCount": verified_restricted_proof_count,
    }))
}

pub(crate) fn verify_compact_vss_share_linkage_binary_proof_material_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let statement = value_at_path(request, &["statement"])?;
    let transported_material =
        value_at_path(request, &["transportedCompactVssShareLinkageProofMaterial"])?;
    let coefficient_commitment_set = value_at_path(request, &["coefficientCommitmentSet"])?;
    let recipient_share_commitment_set = value_at_path(request, &["recipientShareCommitmentSet"])?;
    let proof_material_set = compact_vss_share_linkage_proof_material_set_from_binary_transport(
        transported_material,
        statement,
    )?;

    let verification = verify_compact_vss_share_linkage_proof_material_set_request(&json!({
        "statement": statement.clone(),
        "proofMaterialSet": proof_material_set,
        "coefficientCommitmentSet": coefficient_commitment_set.clone(),
        "recipientShareCommitmentSet": recipient_share_commitment_set.clone(),
    }))?;

    Ok(json!({
        "ok": true,
        "operation": "verifyCompactVssShareLinkageBinaryProofMaterial",
        "setupProfileId": verification["setupProfileId"].clone(),
        "proofFamily": verification["proofFamily"].clone(),
        "shareLinkageStatementRoot": verification["shareLinkageStatementRoot"].clone(),
        "proofMaterialSetRoot": verification["proofMaterialSetRoot"].clone(),
        "participantCount": verification["participantCount"].clone(),
        "proofMaterialCount": verification["proofMaterialCount"].clone(),
        "proofRecordCount": verification["proofRecordCount"].clone(),
        "totalProofByteLength": verification["totalProofByteLength"].clone(),
        "restrictedProofVerificationCount": verification["restrictedProofVerificationCount"].clone(),
        "binaryFormat": COMPACT_VSS_SHARE_LINKAGE_BINARY_FORMAT,
        "binaryTotalByteLength": unsigned_at_path(transported_material, &["totalByteLength"])?,
        "binaryChunkCount": unsigned_at_path(transported_material, &["chunkCount"])?,
        "binaryFullObjectHash": hash_at_path(transported_material, &["fullObjectHash"])?,
        "binaryChunkRoot": hash_at_path(transported_material, &["chunkRoot"])?,
    }))
}

fn compact_vss_share_linkage_proof_material_set_from_binary_transport(
    transported_material: &Value,
    statement: &Value,
) -> CanonicalResult<Value> {
    compact_vss_verify_share_linkage_binary_transport_header(transported_material)?;
    let chunks = compact_vss_share_linkage_binary_transport_chunks(transported_material)?;
    compact_vss_verify_share_linkage_binary_transport_hashes(transported_material, &chunks)?;
    let bytes = compact_vss_concatenate_binary_transport_chunks(&chunks)?;
    let mut reader = crate::encoding::CanonicalReader::new(&bytes);
    let magic = reader.read_exact(COMPACT_VSS_SHARE_LINKAGE_PROOF_MATERIAL_BINARY_MAGIC.len())?;
    if magic != COMPACT_VSS_SHARE_LINKAGE_PROOF_MATERIAL_BINARY_MAGIC {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedMagic,
            "compact VSS share-linkage proof material binary magic is invalid",
        ));
    }
    if reader.read_varuint()? != 1 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::UnsupportedObjectVersion,
            "compact VSS share-linkage proof material binary version is not supported",
        ));
    }
    let share_linkage_statement_root =
        compact_vss_read_binary_hash(&mut reader, "shareLinkageStatementRoot")?;
    let proof_material_set_root =
        compact_vss_read_binary_hash(&mut reader, "proofMaterialSetRoot")?;
    compare_required_string(
        &share_linkage_statement_root,
        hash_at_path(statement, &["statementRoot"])?,
        "compact VSS share-linkage binary proof material shareLinkageStatementRoot",
    )?;
    compare_required_string(
        &proof_material_set_root,
        hash_at_path(transported_material, &["proofMaterialSetRoot"])?,
        "compact VSS share-linkage binary proof material proofMaterialSetRoot",
    )?;
    compare_required_string(
        &share_linkage_statement_root,
        hash_at_path(transported_material, &["shareLinkageStatementRoot"])?,
        "compact VSS share-linkage binary proof material transport shareLinkageStatementRoot",
    )?;

    let proof_material_count = compact_vss_read_binary_usize(&mut reader, "proofMaterialCount")?;
    let participant_count = compact_vss_usize_from_value(
        unsigned_at_path(statement, &["participantCount"])?,
        "compact VSS share-linkage statement participantCount",
    )?;
    if proof_material_count != participant_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "compact VSS share-linkage binary proof material count must match participantCount",
        ));
    }
    let source_statement_records = array_at_path(statement, &["sourceStatementRecords"])?;
    if source_statement_records.len() != participant_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "compact VSS share-linkage statement must contain one source statement per participant",
        ));
    }

    let mut proof_materials = Vec::with_capacity(proof_material_count);
    for source_statement_index in 0..proof_material_count {
        let source_statement = source_statement_records
            .get(source_statement_index)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "compact VSS share-linkage binary proof material has no matching source statement",
                )
            })?;
        let source_trustee_roster_position =
            compact_vss_read_binary_usize(&mut reader, "sourceTrusteeRosterPosition")?;
        let source_statement_root =
            compact_vss_read_binary_hash(&mut reader, "sourceStatementRoot")?;
        let proof_record_count = compact_vss_read_binary_usize(&mut reader, "proofRecordCount")?;
        let mut proof_records = Vec::with_capacity(proof_record_count);
        for _proof_record_index in 0..proof_record_count {
            let proof_statement_hash =
                compact_vss_read_binary_hash(&mut reader, "proofStatementHash")?;
            let linkage_item_count =
                compact_vss_read_binary_usize(&mut reader, "linkageItemCount")?;
            let mut linkage_items = Vec::with_capacity(linkage_item_count);
            for _linkage_item_index in 0..linkage_item_count {
                let recipient_roster_position =
                    compact_vss_read_binary_usize(&mut reader, "recipientRosterPosition")?;
                let source_rns_limb_index =
                    compact_vss_read_binary_usize(&mut reader, "sourceRnsLimbIndex")?;
                linkage_items.push(json!({
                    "recipientRosterPosition": recipient_roster_position,
                    "sourceRnsLimbIndex": source_rns_limb_index,
                }));
            }
            let proof_byte_length = compact_vss_read_binary_usize(&mut reader, "proofByteLength")?;
            let proof_bytes = reader.read_exact(proof_byte_length)?.to_vec();
            let proof_bytes_base64 = crate::transcript_core::encode_standard_base64(&proof_bytes);
            let proof_bytes_hash = hash512_hex(
                COMPACT_VSS_SHARE_LINKAGE_PROOF_BYTES_HASH_DOMAIN,
                &[&proof_bytes],
            );
            let proof_record_without_root = json!({
                "objectType": "CompactVssShareLinkageProofRecord",
                "objectVersion": 1,
                "proofFamily": COMPACT_VSS_SHARE_LINKAGE_PROOF_FAMILY,
                "sourceStatementRoot": source_statement_root,
                "proofStatementHash": proof_statement_hash,
                "linkageItems": linkage_items,
                "proofBytesHash": proof_bytes_hash,
                "proofBytesBase64": proof_bytes_base64,
            });
            let mut proof_record = proof_record_without_root;
            proof_record["proofRecordRoot"] = json!(derive_protocol_hash(
                "SetupProofRecordBindingHash",
                &proof_record,
            )?);
            proof_records.push(proof_record);
        }

        let proof_material_without_root = json!({
            "objectType": "CompactVssShareLinkageProofMaterial",
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
            "proofFamily": COMPACT_VSS_SHARE_LINKAGE_PROOF_FAMILY,
            "ceremonyId": string_at_path(statement, &["ceremonyId"])?,
            "manifestHash": hash_at_path(statement, &["manifestHash"])?,
            "rosterHash": hash_at_path(statement, &["rosterHash"])?,
            "setupProfileHash": hash_at_path(statement, &["setupProfileHash"])?,
            "qShareHash": hash_at_path(statement, &["qShareHash"])?,
            "carryAwareVssShareRelationProfileHash": hash_at_path(
                statement,
                &["carryAwareVssShareRelationProfileHash"],
            )?,
            "commitmentProfileHash": hash_at_path(statement, &["commitmentProfileHash"])?,
            "setupEpoch": string_at_path(statement, &["setupEpoch"])?,
            "sourceTrusteeIdentity": string_at_path(source_statement, &["sourceTrusteeIdentity"])?,
            "sourceTrusteeRosterPosition": source_trustee_roster_position,
            "shareLinkageStatementRoot": share_linkage_statement_root,
            "sourceStatementRoot": source_statement_root,
            "proofRecords": proof_records,
        });
        let mut proof_material = proof_material_without_root;
        proof_material["proofMaterialRoot"] = json!(derive_protocol_hash(
            "SetupProofRecordBindingHash",
            &proof_material,
        )?);
        proof_materials.push(proof_material);
    }
    if !reader.is_finished() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::TrailingBytes,
            "compact VSS share-linkage proof material binary has trailing bytes",
        ));
    }

    let proof_material_set_without_root = json!({
        "objectType": "CompactVssShareLinkageProofMaterialSet",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "proofFamily": COMPACT_VSS_SHARE_LINKAGE_PROOF_FAMILY,
        "ceremonyId": string_at_path(statement, &["ceremonyId"])?,
        "manifestHash": hash_at_path(statement, &["manifestHash"])?,
        "rosterHash": hash_at_path(statement, &["rosterHash"])?,
        "setupProfileHash": hash_at_path(statement, &["setupProfileHash"])?,
        "qShareHash": hash_at_path(statement, &["qShareHash"])?,
        "carryAwareVssShareRelationProfileHash": hash_at_path(
            statement,
            &["carryAwareVssShareRelationProfileHash"],
        )?,
        "commitmentProfileHash": hash_at_path(statement, &["commitmentProfileHash"])?,
        "setupEpoch": string_at_path(statement, &["setupEpoch"])?,
        "participantCount": participant_count,
        "shareLinkageStatementRoot": share_linkage_statement_root,
        "proofMaterials": proof_materials,
    });
    let mut proof_material_set = proof_material_set_without_root;
    proof_material_set["proofMaterialSetRoot"] = json!(proof_material_set_root);

    Ok(proof_material_set)
}

fn compact_vss_verify_share_linkage_binary_transport_header(
    transported_material: &Value,
) -> CanonicalResult<()> {
    for (field_name, expected_value) in [
        (
            "objectType",
            COMPACT_VSS_SHARE_LINKAGE_BINARY_TRANSPORT_OBJECT_TYPE,
        ),
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("profileId", COMPACT_VSS_COMMITMENT_PROFILE_ID),
        ("proofFamily", COMPACT_VSS_SHARE_LINKAGE_PROOF_FAMILY),
        ("binaryFormat", COMPACT_VSS_SHARE_LINKAGE_BINARY_FORMAT),
    ] {
        compare_required_string(
            string_at_path(transported_material, &[field_name])?,
            expected_value,
            &format!("compact VSS share-linkage binary transport {field_name}"),
        )?;
    }
    compare_required_u64(
        unsigned_at_path(transported_material, &["objectVersion"])?,
        1,
        "compact VSS share-linkage binary transport objectVersion",
    )?;
    validate_hash_string(
        hash_at_path(transported_material, &["proofMaterialSetRoot"])?,
        "compact VSS share-linkage binary transport proofMaterialSetRoot",
    )?;
    validate_hash_string(
        hash_at_path(transported_material, &["shareLinkageStatementRoot"])?,
        "compact VSS share-linkage binary transport shareLinkageStatementRoot",
    )?;
    validate_hash_string(
        hash_at_path(transported_material, &["fullObjectHash"])?,
        "compact VSS share-linkage binary transport fullObjectHash",
    )?;
    validate_hash_string(
        hash_at_path(transported_material, &["chunkRoot"])?,
        "compact VSS share-linkage binary transport chunkRoot",
    )?;
    compare_required_u64(
        unsigned_at_path(transported_material, &["chunkSizeBytes"])?,
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        "compact VSS share-linkage binary transport chunkSizeBytes",
    )?;

    Ok(())
}

fn compact_vss_share_linkage_binary_transport_chunks(
    transported_material: &Value,
) -> CanonicalResult<Vec<Vec<u8>>> {
    let chunk_values = array_at_path(transported_material, &["chunks"])?;
    if chunk_values.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "compact VSS share-linkage binary transport chunks must be non-empty",
        ));
    }

    chunk_values
        .iter()
        .enumerate()
        .map(|(chunk_index, chunk_value)| {
            let bytes_hex = string_at_path(chunk_value, &["bytesHex"])?;
            crate::transcript_core::decode_hex(bytes_hex).map_err(|error| {
                CanonicalError::new(
                    error.code,
                    format!(
                        "compact VSS share-linkage binary transport chunks[{chunk_index}].bytesHex: {}",
                        error.message
                    ),
                )
            })
        })
        .collect()
}

fn compact_vss_verify_share_linkage_binary_transport_hashes(
    transported_material: &Value,
    chunks: &[Vec<u8>],
) -> CanonicalResult<()> {
    let chunk_count = unsigned_at_path(transported_material, &["chunkCount"])?;
    compare_required_u64(
        u64::try_from(chunks.len()).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "compact VSS share-linkage binary chunk count does not fit u64",
            )
        })?,
        chunk_count,
        "compact VSS share-linkage binary transport chunkCount",
    )?;
    let total_byte_length = chunks.iter().enumerate().try_fold(
        0_u64,
        |byte_count, (chunk_index, chunk)| {
            if chunk.is_empty() {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "compact VSS share-linkage binary transport chunks must be non-empty",
                ));
            }
            if chunk.len() as u64 > SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "compact VSS share-linkage binary transport chunk exceeds chunkSizeBytes",
                ));
            }
            if chunk_index + 1 < chunks.len()
                && chunk.len() as u64 != SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES
            {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "compact VSS share-linkage binary transport contains a short non-final chunk",
                ));
            }
            byte_count
                .checked_add(u64::try_from(chunk.len()).map_err(|_| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "compact VSS share-linkage binary chunk length does not fit u64",
                    )
                })?)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "compact VSS share-linkage binary byte length overflowed",
                    )
                })
        },
    )?;
    compare_required_u64(
        total_byte_length,
        unsigned_at_path(transported_material, &["totalByteLength"])?,
        "compact VSS share-linkage binary transport totalByteLength",
    )?;

    let expected_full_object_hash = setup_proof_material_full_object_hash(
        COMPACT_VSS_SHARE_LINKAGE_PROOF_FAMILY,
        total_byte_length,
        chunks,
    )?;
    compare_required_string(
        hash_at_path(transported_material, &["fullObjectHash"])?,
        &expected_full_object_hash,
        "compact VSS share-linkage binary transport fullObjectHash",
    )?;
    let mut expected_chunk_hashes = Vec::with_capacity(chunks.len());
    for (chunk_index, chunk) in chunks.iter().enumerate() {
        expected_chunk_hashes.push(setup_proof_material_chunk_hash(
            COMPACT_VSS_SHARE_LINKAGE_PROOF_FAMILY,
            &expected_full_object_hash,
            chunk_index,
            chunk,
        )?);
    }
    let chunk_hash_values = array_at_path(transported_material, &["chunkHashes"])?;
    if chunk_hash_values.len() != expected_chunk_hashes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "compact VSS share-linkage binary transport chunkHashes length must match chunks length",
        ));
    }
    for (chunk_index, expected_chunk_hash) in expected_chunk_hashes.iter().enumerate() {
        let observed_chunk_hash = chunk_hash_values
            .get(chunk_index)
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "compact VSS share-linkage binary transport chunkHashes entries must be strings",
                )
            })?;
        validate_hash_string(
            observed_chunk_hash,
            &format!("compact VSS share-linkage binary transport chunkHashes[{chunk_index}]"),
        )?;
        compare_required_string(
            observed_chunk_hash,
            expected_chunk_hash,
            &format!("compact VSS share-linkage binary transport chunkHashes[{chunk_index}]"),
        )?;
    }
    let expected_chunk_root = setup_proof_material_chunk_manifest_root(
        COMPACT_VSS_SHARE_LINKAGE_PROOF_FAMILY,
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        chunk_count,
        total_byte_length,
        &expected_chunk_hashes,
        &expected_full_object_hash,
    )?;
    compare_required_string(
        hash_at_path(transported_material, &["chunkRoot"])?,
        &expected_chunk_root,
        "compact VSS share-linkage binary transport chunkRoot",
    )?;

    Ok(())
}

fn compact_vss_concatenate_binary_transport_chunks(chunks: &[Vec<u8>]) -> CanonicalResult<Vec<u8>> {
    let total_byte_length = chunks.iter().try_fold(0_usize, |byte_count, chunk| {
        byte_count.checked_add(chunk.len()).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "compact VSS share-linkage binary byte length overflowed",
            )
        })
    })?;
    let mut bytes = Vec::with_capacity(total_byte_length);
    for chunk in chunks {
        bytes.extend_from_slice(chunk);
    }

    Ok(bytes)
}

fn compact_vss_read_binary_hash(
    reader: &mut crate::encoding::CanonicalReader<'_>,
    _field_name: &str,
) -> CanonicalResult<String> {
    Ok(crate::transcript_core::encode_hex(reader.read_exact(64)?))
}

fn compact_vss_read_binary_usize(
    reader: &mut crate::encoding::CanonicalReader<'_>,
    field_name: &str,
) -> CanonicalResult<usize> {
    compact_vss_usize_from_value(reader.read_varuint()?, field_name)
}

fn compact_vss_usize_from_value(value: u64, field_name: &str) -> CanonicalResult<usize> {
    usize::try_from(value).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{field_name} does not fit usize"),
        )
    })
}

#[derive(Clone, Copy)]
struct CompactVssShareLinkageProofRecordLinkageItem {
    recipient_roster_position: usize,
    source_rns_limb_index: usize,
}

impl CompactVssShareLinkageProofRecordLinkageItem {
    fn to_value(self) -> Value {
        json!({
            "recipientRosterPosition": self.recipient_roster_position,
            "sourceRnsLimbIndex": self.source_rns_limb_index,
        })
    }
}

struct CompactVssShareLinkageProofRequestMaterialInput<'a> {
    source_statement: &'a Value,
    coefficient_source_record: &'a Value,
    recipient_source_record: &'a Value,
    linkage_items: &'a [CompactVssShareLinkageProofRecordLinkageItem],
    proof_bytes: &'a [u8],
    ring_degree: usize,
    ceremony_id: &'a str,
    manifest_hash: &'a str,
    roster_hash: &'a str,
    setup_epoch: &'a str,
    public_matrix_seed_hash: &'a str,
    source_trustee_identity: &'a str,
    source_statement_index: usize,
    threshold_degree: usize,
    target_rns_limb_count: usize,
}

struct CompactVssShareLinkageItemMaterialInput<'a> {
    coefficient_source_record: &'a Value,
    recipient_source_record: &'a Value,
    recipient_roster_position: usize,
    source_rns_limb_index: usize,
    threshold_degree: usize,
    target_rns_limb_count: usize,
}

fn compact_vss_share_linkage_compare_source_opening_roots(
    source_statement: &Value,
    coefficient_source_record: &Value,
    recipient_source_record: &Value,
) -> CanonicalResult<()> {
    let coefficient_records =
        array_at_path(coefficient_source_record, &["coefficientCommitments"])?;
    let coefficient_opening_roots = array_at_path(source_statement, &["coefficientOpeningRoots"])?;
    if coefficient_records.len() != coefficient_opening_roots.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "compact VSS share-linkage proof material coefficient openings must cover the source statement",
        ));
    }
    for (opening_root_index, coefficient_record) in coefficient_records.iter().enumerate() {
        let expected_opening_root = hash_at_path(coefficient_record, &["coefficientOpeningRoot"])?;
        let source_opening_root = coefficient_opening_roots
            .get(opening_root_index)
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "compact VSS share-linkage proof material coefficient opening root must be a string",
                )
            })?;
        compare_required_string(
            source_opening_root,
            expected_opening_root,
            "compact VSS share-linkage proof material coefficientOpeningRoots",
        )?;
    }

    let recipient_share_records =
        array_at_path(recipient_source_record, &["recipientShareCommitments"])?;
    let recipient_share_opening_roots =
        array_at_path(source_statement, &["recipientShareOpeningRoots"])?;
    if recipient_share_records.len() != recipient_share_opening_roots.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "compact VSS share-linkage proof material recipient-share openings must cover the source statement",
        ));
    }
    for (opening_root_index, recipient_share_record) in recipient_share_records.iter().enumerate() {
        let expected_opening_root = hash_at_path(recipient_share_record, &["shareOpeningRoot"])?;
        let source_opening_root = recipient_share_opening_roots
            .get(opening_root_index)
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "compact VSS share-linkage proof material recipient-share opening root must be a string",
                )
            })?;
        compare_required_string(
            source_opening_root,
            expected_opening_root,
            "compact VSS share-linkage proof material recipientShareOpeningRoots",
        )?;
    }

    Ok(())
}

fn compact_vss_share_linkage_proof_record_linkage_items(
    proof_record: &Value,
    participant_count: usize,
    target_rns_limb_count: usize,
) -> CanonicalResult<Vec<CompactVssShareLinkageProofRecordLinkageItem>> {
    array_at_path(proof_record, &["linkageItems"])?
        .iter()
        .enumerate()
        .map(|(linkage_item_index, linkage_item)| {
            let recipient_roster_position =
                usize::try_from(unsigned_at_path(linkage_item, &["recipientRosterPosition"])?)
                    .map_err(|_| {
                        CanonicalError::new(
                            CanonicalErrorCode::MalformedLength,
                            "compact VSS share-linkage proof record linkageItems recipientRosterPosition does not fit usize",
                        )
                    })?;
            if recipient_roster_position >= participant_count {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    format!(
                        "compact VSS share-linkage proof record linkageItems.{linkage_item_index} recipientRosterPosition is outside the statement"
                    ),
                ));
            }
            let source_rns_limb_index =
                usize::try_from(unsigned_at_path(linkage_item, &["sourceRnsLimbIndex"])?)
                    .map_err(|_| {
                        CanonicalError::new(
                            CanonicalErrorCode::MalformedLength,
                            "compact VSS share-linkage proof record linkageItems sourceRnsLimbIndex does not fit usize",
                        )
                    })?;
            if source_rns_limb_index >= target_rns_limb_count {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    format!(
                        "compact VSS share-linkage proof record linkageItems.{linkage_item_index} sourceRnsLimbIndex is outside the statement"
                    ),
                ));
            }

            Ok(CompactVssShareLinkageProofRecordLinkageItem {
                recipient_roster_position,
                source_rns_limb_index,
            })
        })
        .collect()
}

fn compact_vss_share_linkage_item_from_material(
    input: CompactVssShareLinkageItemMaterialInput<'_>,
) -> CanonicalResult<Value> {
    let coefficient_records =
        array_at_path(input.coefficient_source_record, &["coefficientCommitments"])?;
    let coefficient_record_offset = input
        .source_rns_limb_index
        .checked_mul(input.threshold_degree)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "compact VSS share-linkage coefficient record offset overflowed",
            )
        })?;
    let mut source_message_modulus = None;
    let mut coefficient_commitment_roots = Vec::with_capacity(input.threshold_degree);
    let mut coefficient_opening_roots = Vec::with_capacity(input.threshold_degree);
    let mut coefficient_commitments = Vec::with_capacity(input.threshold_degree);
    for coefficient_index in 0..input.threshold_degree {
        let coefficient_record = coefficient_records
            .get(coefficient_record_offset + coefficient_index)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "compact VSS share-linkage coefficient record is missing",
                )
            })?;
        compare_required_u64(
            unsigned_at_path(coefficient_record, &["rnsLimbIndex"])?,
            input.source_rns_limb_index as u64,
            "compact VSS share-linkage coefficient rnsLimbIndex",
        )?;
        compare_required_u64(
            unsigned_at_path(coefficient_record, &["shamirCoefficientIndex"])?,
            coefficient_index as u64,
            "compact VSS share-linkage coefficient shamirCoefficientIndex",
        )?;
        let rns_prime = unsigned_at_path(coefficient_record, &["rnsPrime"])?;
        if let Some(expected_modulus) = source_message_modulus {
            compare_required_u64(
                rns_prime,
                expected_modulus,
                "compact VSS share-linkage coefficient rnsPrime",
            )?;
        } else {
            source_message_modulus = Some(rns_prime);
        }
        coefficient_commitment_roots.push(Value::String(
            hash_at_path(coefficient_record, &["coefficientCommitmentRoot"])?.to_string(),
        ));
        coefficient_opening_roots.push(Value::String(
            hash_at_path(coefficient_record, &["coefficientOpeningRoot"])?.to_string(),
        ));
        coefficient_commitments.push(value_at_path(coefficient_record, &["commitment"])?.clone());
    }
    let source_message_modulus = source_message_modulus.ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "compact VSS share-linkage source message modulus is missing",
        )
    })?;

    let recipient_share_record_index = input
        .recipient_roster_position
        .checked_mul(input.target_rns_limb_count)
        .and_then(|offset| offset.checked_add(input.source_rns_limb_index))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "compact VSS share-linkage recipient-share record index overflowed",
            )
        })?;
    let recipient_share_records = array_at_path(
        input.recipient_source_record,
        &["recipientShareCommitments"],
    )?;
    let recipient_share_record = recipient_share_records
        .get(recipient_share_record_index)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "compact VSS share-linkage recipient-share record is missing",
            )
        })?;
    compare_required_u64(
        unsigned_at_path(recipient_share_record, &["recipientRosterPosition"])?,
        input.recipient_roster_position as u64,
        "compact VSS share-linkage recipient-share recipientRosterPosition",
    )?;
    compare_required_u64(
        unsigned_at_path(recipient_share_record, &["rnsLimbIndex"])?,
        input.source_rns_limb_index as u64,
        "compact VSS share-linkage recipient-share rnsLimbIndex",
    )?;
    compare_required_u64(
        unsigned_at_path(recipient_share_record, &["rnsPrime"])?,
        source_message_modulus,
        "compact VSS share-linkage recipient-share rnsPrime",
    )?;

    Ok(json!({
        "recipientIdentity": string_at_path(recipient_share_record, &["recipientIdentity"])?,
        "recipientRosterPosition": input.recipient_roster_position,
        "sourceRnsLimbIndex": input.source_rns_limb_index,
        "sourceMessageModulus": source_message_modulus,
        "coefficientCommitmentRoots": coefficient_commitment_roots,
        "coefficientOpeningRoots": coefficient_opening_roots,
        "coefficientCommitments": coefficient_commitments,
        "recipientShareCommitmentRoot": hash_at_path(recipient_share_record, &["shareCommitmentRoot"])?,
        "recipientShareOpeningRoot": hash_at_path(recipient_share_record, &["shareOpeningRoot"])?,
        "recipientShareCommitment": value_at_path(recipient_share_record, &["commitment"])?.clone(),
    }))
}

fn compact_vss_share_linkage_proof_request_from_material(
    input: CompactVssShareLinkageProofRequestMaterialInput<'_>,
) -> CanonicalResult<Value> {
    if input.linkage_items.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "compact VSS share-linkage proof record linkageItems must be non-empty",
        ));
    }
    let mut linkage_item_values = input
        .linkage_items
        .iter()
        .map(|linkage_item| {
            compact_vss_share_linkage_item_from_material(CompactVssShareLinkageItemMaterialInput {
                coefficient_source_record: input.coefficient_source_record,
                recipient_source_record: input.recipient_source_record,
                recipient_roster_position: linkage_item.recipient_roster_position,
                source_rns_limb_index: linkage_item.source_rns_limb_index,
                threshold_degree: input.threshold_degree,
                target_rns_limb_count: input.target_rns_limb_count,
            })
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let primary_item = linkage_item_values.remove(0);
    let mut compact_statement = primary_item.as_object().cloned().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "compact VSS share-linkage reconstructed item must be an object",
        )
    })?;
    compact_statement.insert(
        "publicMatrixSeedHash".to_string(),
        Value::String(input.public_matrix_seed_hash.to_string()),
    );
    compact_statement.insert(
        "sourceTrusteeIdentity".to_string(),
        Value::String(input.source_trustee_identity.to_string()),
    );
    compact_statement.insert(
        "sourceTrusteeRosterPosition".to_string(),
        json!(input.source_statement_index),
    );
    compact_statement.insert(
        "sourceCoefficientCommitmentRoot".to_string(),
        Value::String(
            hash_at_path(input.source_statement, &["sourceCoefficientCommitmentRoot"])?.to_string(),
        ),
    );
    compact_statement.insert(
        "sourceRecipientShareCommitmentRoot".to_string(),
        Value::String(
            hash_at_path(
                input.source_statement,
                &["sourceRecipientShareCommitmentRoot"],
            )?
            .to_string(),
        ),
    );
    if !linkage_item_values.is_empty() {
        compact_statement.insert(
            "additionalLinkageItems".to_string(),
            Value::Array(linkage_item_values),
        );
    }

    let context = json!({
        "ceremonyId": input.ceremony_id,
        "manifestHash": input.manifest_hash,
        "rosterHash": input.roster_hash,
        "trusteeIdentity": input.source_trustee_identity,
        "trusteeRosterPosition": input.source_statement_index,
        "setupEpoch": input.setup_epoch,
        "sourceCoefficientCommitmentRoot": hash_at_path(input.source_statement, &["sourceCoefficientCommitmentRoot"])?,
        "sourceRecipientShareCommitmentRoot": hash_at_path(input.source_statement, &["sourceRecipientShareCommitmentRoot"])?,
    });

    Ok(json!({
        "context": context,
        "ringDegree": input.ring_degree,
        "compactVssShareLinkage": Value::Object(compact_statement),
        "proofBytesHex": crate::transcript_core::encode_hex(input.proof_bytes),
    }))
}

#[derive(Clone, Copy)]
struct CompactVssShareLinkageStatementBinding<'a> {
    ceremony_id: &'a str,
    manifest_hash: &'a str,
    roster_hash: &'a str,
    setup_profile_hash: &'a str,
    q_share_hash: &'a str,
    carry_aware_vss_share_relation_profile_hash: &'a str,
    commitment_profile_hash: &'a str,
    setup_epoch: &'a str,
    public_matrix_seed_hash: &'a str,
    target_basis_hash: &'a str,
    participant_count: usize,
    target_rns_limb_count: usize,
    threshold_degree: usize,
    coefficient_commitment_root: &'a str,
    aggregate_threshold_commitment_root: &'a str,
}

struct CompactVssShareLinkageSourceStatementInput<'a> {
    source_statement_record: &'a Value,
    expected_source_position: usize,
    statement: CompactVssShareLinkageStatementBinding<'a>,
}

struct CompactVssShareLinkageEvidenceInput<'a> {
    request: &'a Value,
    statement: CompactVssShareLinkageStatementBinding<'a>,
    recipient_share_commitment_root: &'a str,
    verified_source_statement_records: &'a [Value],
}

fn verify_optional_compact_vss_share_linkage_evidence(
    input: CompactVssShareLinkageEvidenceInput<'_>,
) -> CanonicalResult<()> {
    match (
        input.request.get("coefficientCommitmentSet"),
        input.request.get("recipientShareCommitmentSet"),
        input.request.get("aggregateThresholdCommitmentSet"),
    ) {
        (None, None, None) => Ok(()),
        (
            Some(coefficient_commitment_set),
            Some(recipient_share_commitment_set),
            Some(aggregate_threshold_commitment_set),
        ) => verify_compact_vss_share_linkage_evidence_sets(
            input,
            coefficient_commitment_set,
            recipient_share_commitment_set,
            aggregate_threshold_commitment_set,
        ),
        _ => Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "compact VSS share linkage evidence verification requires coefficient, recipient-share, and aggregate-threshold commitment sets",
        )),
    }
}

fn verify_compact_vss_share_linkage_evidence_sets(
    input: CompactVssShareLinkageEvidenceInput<'_>,
    coefficient_commitment_set: &Value,
    recipient_share_commitment_set: &Value,
    aggregate_threshold_commitment_set: &Value,
) -> CanonicalResult<()> {
    let coefficient_verification = verify_compact_vss_coefficient_commitment_set_request(&json!({
        "coefficientCommitmentSet": coefficient_commitment_set,
    }))?;
    let recipient_verification =
        verify_compact_vss_recipient_share_commitment_set_request(&json!({
            "recipientShareCommitmentSet": recipient_share_commitment_set,
        }))?;
    let aggregate_verification =
        verify_compact_vss_aggregate_threshold_commitment_set_request(&json!({
            "aggregateThresholdCommitmentSet": aggregate_threshold_commitment_set,
        }))?;

    compare_required_string(
        hash_at_path(&coefficient_verification, &["coefficientCommitmentRoot"])?,
        input.statement.coefficient_commitment_root,
        "compact VSS share linkage evidence coefficientCommitmentRoot",
    )?;
    compare_required_string(
        hash_at_path(&recipient_verification, &["recipientShareCommitmentRoot"])?,
        input.recipient_share_commitment_root,
        "compact VSS share linkage evidence recipientShareCommitmentRoot",
    )?;
    compare_required_string(
        hash_at_path(
            &aggregate_verification,
            &["aggregateThresholdCommitmentRoot"],
        )?,
        input.statement.aggregate_threshold_commitment_root,
        "compact VSS share linkage evidence aggregateThresholdCommitmentRoot",
    )?;
    for (verification, description) in [
        (&coefficient_verification, "coefficient"),
        (&recipient_verification, "recipient-share"),
        (&aggregate_verification, "aggregate-threshold"),
    ] {
        compare_required_string(
            hash_at_path(verification, &["publicMatrixSeedHash"])?,
            input.statement.public_matrix_seed_hash,
            &format!("compact VSS share linkage evidence {description} publicMatrixSeedHash"),
        )?;
        compare_required_u64(
            unsigned_at_path(verification, &["participantCount"])?,
            input.statement.participant_count as u64,
            &format!("compact VSS share linkage evidence {description} participantCount"),
        )?;
        compare_required_u64(
            unsigned_at_path(verification, &["rnsLimbCount"])?,
            input.statement.target_rns_limb_count as u64,
            &format!("compact VSS share linkage evidence {description} rnsLimbCount"),
        )?;
    }
    compare_required_u64(
        unsigned_at_path(&coefficient_verification, &["thresholdDegree"])?,
        input.statement.threshold_degree as u64,
        "compact VSS share linkage evidence coefficient thresholdDegree",
    )?;
    verify_compact_vss_aggregate_threshold_public_sums(
        recipient_share_commitment_set,
        aggregate_threshold_commitment_set,
        input.statement.participant_count,
        input.statement.target_rns_limb_count,
    )?;

    let coefficient_source_records =
        array_at_path(coefficient_commitment_set, &["sourceTrusteeRecords"])?;
    let recipient_source_records =
        array_at_path(recipient_share_commitment_set, &["sourceTrusteeRecords"])?;
    if coefficient_source_records.len() != input.statement.participant_count
        || recipient_source_records.len() != input.statement.participant_count
        || input.verified_source_statement_records.len() != input.statement.participant_count
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "compact VSS share linkage evidence source records must cover every participant",
        ));
    }
    for expected_source_position in 0..input.statement.participant_count {
        let source_statement = &input.verified_source_statement_records[expected_source_position];
        let coefficient_source_record = &coefficient_source_records[expected_source_position];
        let recipient_source_record = &recipient_source_records[expected_source_position];
        let source_trustee_identity = string_at_path(source_statement, &["sourceTrusteeIdentity"])?;
        compare_required_string(
            string_at_path(coefficient_source_record, &["sourceTrusteeIdentity"])?,
            source_trustee_identity,
            "compact VSS share linkage evidence coefficient sourceTrusteeIdentity",
        )?;
        compare_required_string(
            string_at_path(recipient_source_record, &["sourceTrusteeIdentity"])?,
            source_trustee_identity,
            "compact VSS share linkage evidence recipient sourceTrusteeIdentity",
        )?;
        compare_required_u64(
            unsigned_at_path(coefficient_source_record, &["sourceTrusteeRosterPosition"])?,
            expected_source_position as u64,
            "compact VSS share linkage evidence coefficient sourceTrusteeRosterPosition",
        )?;
        compare_required_u64(
            unsigned_at_path(recipient_source_record, &["sourceTrusteeRosterPosition"])?,
            expected_source_position as u64,
            "compact VSS share linkage evidence recipient sourceTrusteeRosterPosition",
        )?;
        compare_required_string(
            hash_at_path(
                coefficient_source_record,
                &["sourceCoefficientCommitmentRoot"],
            )?,
            hash_at_path(source_statement, &["sourceCoefficientCommitmentRoot"])?,
            "compact VSS share linkage evidence sourceCoefficientCommitmentRoot",
        )?;
        compare_required_string(
            hash_at_path(
                recipient_source_record,
                &["sourceRecipientShareCommitmentRoot"],
            )?,
            hash_at_path(source_statement, &["sourceRecipientShareCommitmentRoot"])?,
            "compact VSS share linkage evidence sourceRecipientShareCommitmentRoot",
        )?;
        let coefficient_records =
            array_at_path(coefficient_source_record, &["coefficientCommitments"])?;
        let source_statement_coefficient_opening_roots =
            array_at_path(source_statement, &["coefficientOpeningRoots"])?;
        if coefficient_records.len() != source_statement_coefficient_opening_roots.len() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "compact VSS share linkage evidence coefficient opening roots must cover the source statement",
            ));
        }
        for (opening_root_index, coefficient_record) in coefficient_records.iter().enumerate() {
            let expected_opening_root =
                hash_at_path(coefficient_record, &["coefficientOpeningRoot"])?;
            let source_statement_opening_root = source_statement_coefficient_opening_roots
                .get(opening_root_index)
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "compact VSS share linkage source coefficient opening root must be a string",
                    )
                })?;
            compare_required_string(
                source_statement_opening_root,
                expected_opening_root,
                "compact VSS share linkage evidence coefficientOpeningRoots",
            )?;
        }
        let recipient_share_records =
            array_at_path(recipient_source_record, &["recipientShareCommitments"])?;
        let source_statement_recipient_share_opening_roots =
            array_at_path(source_statement, &["recipientShareOpeningRoots"])?;
        if recipient_share_records.len() != source_statement_recipient_share_opening_roots.len() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "compact VSS share linkage evidence recipient-share opening roots must cover the source statement",
            ));
        }
        for (opening_root_index, recipient_share_record) in
            recipient_share_records.iter().enumerate()
        {
            let expected_opening_root =
                hash_at_path(recipient_share_record, &["shareOpeningRoot"])?;
            let source_statement_opening_root = source_statement_recipient_share_opening_roots
                .get(opening_root_index)
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "compact VSS share linkage source recipient-share opening root must be a string",
                    )
                })?;
            compare_required_string(
                source_statement_opening_root,
                expected_opening_root,
                "compact VSS share linkage evidence recipientShareOpeningRoots",
            )?;
        }
    }

    Ok(())
}

fn verify_compact_vss_aggregate_threshold_public_sums(
    recipient_share_commitment_set: &Value,
    aggregate_threshold_commitment_set: &Value,
    participant_count: usize,
    rns_limb_count: usize,
) -> CanonicalResult<()> {
    let recipient_source_records =
        array_at_path(recipient_share_commitment_set, &["sourceTrusteeRecords"])?;
    let aggregate_recipient_records =
        array_at_path(aggregate_threshold_commitment_set, &["recipientRecords"])?;
    for aggregate_record in aggregate_recipient_records {
        let recipient_roster_position = usize::try_from(unsigned_at_path(
            aggregate_record,
            &["recipientRosterPosition"],
        )?)
        .map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "compact VSS aggregate recipient roster position does not fit usize",
            )
        })?;
        let rns_limb_index =
            usize::try_from(unsigned_at_path(aggregate_record, &["rnsLimbIndex"])?).map_err(
                |_| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "compact VSS aggregate RNS limb index does not fit usize",
                    )
                },
            )?;
        let recipient_share_record_index = recipient_roster_position
            .checked_mul(rns_limb_count)
            .and_then(|offset| offset.checked_add(rns_limb_index))
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "compact VSS aggregate recipient-share record index overflowed",
                )
            })?;
        let source_share_commitment_roots =
            array_at_path(aggregate_record, &["sourceShareCommitmentRoots"])?;
        if source_share_commitment_roots.len() != participant_count {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "compact VSS aggregate threshold commitment source roots must cover every participant",
            ));
        }
        let source_share_opening_roots =
            array_at_path(aggregate_record, &["sourceShareOpeningRoots"])?;
        if source_share_opening_roots.len() != participant_count {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "compact VSS aggregate threshold commitment source opening roots must cover every participant",
            ));
        }
        let mut source_recipient_share_records = Vec::with_capacity(participant_count);
        for (source_roster_position, source_share_commitment_root) in
            source_share_commitment_roots.iter().enumerate()
        {
            let source_record = recipient_source_records
                .get(source_roster_position)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "compact VSS recipient-share set is missing a source record",
                    )
                })?;
            let recipient_share_records =
                array_at_path(source_record, &["recipientShareCommitments"])?;
            let recipient_share_record = recipient_share_records
                .get(recipient_share_record_index)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "compact VSS aggregate threshold commitment references a missing recipient-share commitment",
                    )
                })?;
            let share_commitment_root =
                hash_at_path(recipient_share_record, &["shareCommitmentRoot"])?;
            let expected_root = source_share_commitment_root.as_str().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "compact VSS aggregate source share commitment root must be a string",
                )
            })?;
            compare_required_string(
                share_commitment_root,
                expected_root,
                "compact VSS aggregate source share commitment root",
            )?;
            let share_opening_root = hash_at_path(recipient_share_record, &["shareOpeningRoot"])?;
            let expected_opening_root = source_share_opening_roots
                .get(source_roster_position)
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "compact VSS aggregate source share opening root must be a string",
                    )
                })?;
            compare_required_string(
                share_opening_root,
                expected_opening_root,
                "compact VSS aggregate source share opening root",
            )?;
            source_recipient_share_records.push(recipient_share_record);
        }
        let aggregate_commitment = value_at_path(aggregate_record, &["commitment"])?;
        let aggregate_limbs = array_at_path(aggregate_commitment, &["commitmentLimbs"])?;
        for (limb_position, aggregate_limb) in aggregate_limbs.iter().enumerate() {
            let aggregate_coordinates = array_at_path(aggregate_limb, &["coordinates"])?;
            let modulus = unsigned_at_path(aggregate_limb, &["modulus"])?;
            for (coordinate_index, aggregate_coordinate) in aggregate_coordinates.iter().enumerate()
            {
                let aggregate_coordinate_value =
                    aggregate_coordinate.as_u64().ok_or_else(|| {
                        CanonicalError::new(
                            CanonicalErrorCode::InvalidFixture,
                            "compact VSS aggregate coordinate must be an unsigned integer",
                        )
                    })?;
                let mut summed_coordinate = 0_u128;
                for recipient_share_record in &source_recipient_share_records {
                    let commitment = value_at_path(recipient_share_record, &["commitment"])?;
                    let limb = array_at_path(commitment, &["commitmentLimbs"])?
                        .get(limb_position)
                        .ok_or_else(|| {
                            CanonicalError::new(
                                CanonicalErrorCode::MalformedLength,
                                "compact VSS recipient-share commitment is missing a limb",
                            )
                        })?;
                    compare_required_u64(
                        unsigned_at_path(limb, &["commitmentModulusIndex"])?,
                        unsigned_at_path(aggregate_limb, &["commitmentModulusIndex"])?,
                        "compact VSS aggregate source commitment modulus index",
                    )?;
                    compare_required_u64(
                        unsigned_at_path(limb, &["modulus"])?,
                        modulus,
                        "compact VSS aggregate source commitment modulus",
                    )?;
                    let coordinate = array_at_path(limb, &["coordinates"])?
                        .get(coordinate_index)
                        .and_then(Value::as_u64)
                        .ok_or_else(|| {
                            CanonicalError::new(
                                CanonicalErrorCode::MalformedLength,
                                "compact VSS recipient-share commitment is missing a coordinate",
                            )
                        })?;
                    summed_coordinate =
                        (summed_coordinate + u128::from(coordinate)) % u128::from(modulus);
                }
                if summed_coordinate as u64 != aggregate_coordinate_value {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::ProfileComponentMismatch,
                        "compact VSS aggregate threshold commitment body is not the public sum of recipient-share commitments",
                    ));
                }
            }
        }
    }

    Ok(())
}

fn verify_compact_vss_share_linkage_source_statement(
    input: CompactVssShareLinkageSourceStatementInput<'_>,
) -> CanonicalResult<Value> {
    compare_required_string(
        string_at_path(input.source_statement_record, &["objectType"])?,
        "CompactVssShareLinkageSourceStatement",
        "compact VSS share linkage source statement objectType",
    )?;
    compare_required_u64(
        unsigned_at_path(input.source_statement_record, &["objectVersion"])?,
        1,
        "compact VSS share linkage source statement objectVersion",
    )?;
    compare_required_string(
        string_at_path(input.source_statement_record, &["setupProfileId"])?,
        COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "compact VSS share linkage source statement setupProfileId",
    )?;
    compare_required_string(
        string_at_path(input.source_statement_record, &["profileId"])?,
        COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "compact VSS share linkage source statement profileId",
    )?;
    compare_required_string(
        string_at_path(input.source_statement_record, &["ceremonyId"])?,
        input.statement.ceremony_id,
        "compact VSS share linkage source statement ceremonyId",
    )?;
    compare_required_string(
        hash_at_path(input.source_statement_record, &["manifestHash"])?,
        input.statement.manifest_hash,
        "compact VSS share linkage source statement manifestHash",
    )?;
    compare_required_string(
        hash_at_path(input.source_statement_record, &["rosterHash"])?,
        input.statement.roster_hash,
        "compact VSS share linkage source statement rosterHash",
    )?;
    compare_required_string(
        hash_at_path(input.source_statement_record, &["setupProfileHash"])?,
        input.statement.setup_profile_hash,
        "compact VSS share linkage source statement setupProfileHash",
    )?;
    compare_required_string(
        hash_at_path(input.source_statement_record, &["qShareHash"])?,
        input.statement.q_share_hash,
        "compact VSS share linkage source statement qShareHash",
    )?;
    compare_required_string(
        hash_at_path(
            input.source_statement_record,
            &["carryAwareVssShareRelationProfileHash"],
        )?,
        input.statement.carry_aware_vss_share_relation_profile_hash,
        "compact VSS share linkage source statement carryAwareVssShareRelationProfileHash",
    )?;
    compare_required_string(
        hash_at_path(input.source_statement_record, &["commitmentProfileHash"])?,
        input.statement.commitment_profile_hash,
        "compact VSS share linkage source statement commitmentProfileHash",
    )?;
    compare_required_string(
        string_at_path(input.source_statement_record, &["setupEpoch"])?,
        input.statement.setup_epoch,
        "compact VSS share linkage source statement setupEpoch",
    )?;
    compare_required_string(
        hash_at_path(input.source_statement_record, &["publicMatrixSeedHash"])?,
        input.statement.public_matrix_seed_hash,
        "compact VSS share linkage source statement publicMatrixSeedHash",
    )?;
    compare_required_string(
        hash_at_path(input.source_statement_record, &["targetBasisHash"])?,
        input.statement.target_basis_hash,
        "compact VSS share linkage source statement targetBasisHash",
    )?;
    let source_trustee_identity =
        read_non_empty_string(input.source_statement_record, "sourceTrusteeIdentity")?;
    compare_required_u64(
        unsigned_at_path(
            input.source_statement_record,
            &["sourceTrusteeRosterPosition"],
        )?,
        input.expected_source_position as u64,
        "compact VSS share linkage source statement sourceTrusteeRosterPosition",
    )?;
    compare_required_u64(
        unsigned_at_path(input.source_statement_record, &["participantCount"])?,
        input.statement.participant_count as u64,
        "compact VSS share linkage source statement participantCount",
    )?;
    compare_required_u64(
        unsigned_at_path(input.source_statement_record, &["targetRnsLimbCount"])?,
        input.statement.target_rns_limb_count as u64,
        "compact VSS share linkage source statement targetRnsLimbCount",
    )?;
    compare_required_u64(
        unsigned_at_path(input.source_statement_record, &["thresholdDegree"])?,
        input.statement.threshold_degree as u64,
        "compact VSS share linkage source statement thresholdDegree",
    )?;
    compare_required_string(
        hash_at_path(
            input.source_statement_record,
            &["coefficientCommitmentRoot"],
        )?,
        input.statement.coefficient_commitment_root,
        "compact VSS share linkage source statement coefficientCommitmentRoot",
    )?;
    let source_coefficient_commitment_root = hash_at_path(
        input.source_statement_record,
        &["sourceCoefficientCommitmentRoot"],
    )?;
    let source_recipient_share_commitment_root = hash_at_path(
        input.source_statement_record,
        &["sourceRecipientShareCommitmentRoot"],
    )?;
    let expected_coefficient_opening_root_count = input
        .statement
        .target_rns_limb_count
        .checked_mul(input.statement.threshold_degree)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "compact VSS source statement coefficient opening root count overflowed",
            )
        })?;
    let coefficient_opening_roots =
        array_at_path(input.source_statement_record, &["coefficientOpeningRoots"])?;
    if coefficient_opening_roots.len() != expected_coefficient_opening_root_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "compact VSS share linkage source statement coefficientOpeningRoots must cover every target limb and coefficient",
        ));
    }
    let verified_coefficient_opening_roots = coefficient_opening_roots
        .iter()
        .enumerate()
        .map(|(opening_root_index, opening_root)| {
            let root = opening_root.as_str().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!(
                        "compact VSS share linkage source statement coefficientOpeningRoots.{opening_root_index} must be a string"
                    ),
                )
            })?;
            validate_hash_string(
                root,
                &format!(
                    "compact VSS share linkage source statement coefficientOpeningRoots.{opening_root_index}"
                ),
            )?;

            Ok(Value::String(root.to_string()))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let expected_recipient_share_opening_root_count = input
        .statement
        .participant_count
        .checked_mul(input.statement.target_rns_limb_count)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "compact VSS source statement recipient-share opening root count overflowed",
            )
        })?;
    let recipient_share_opening_roots = array_at_path(
        input.source_statement_record,
        &["recipientShareOpeningRoots"],
    )?;
    if recipient_share_opening_roots.len() != expected_recipient_share_opening_root_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "compact VSS share linkage source statement recipientShareOpeningRoots must cover every recipient and target limb",
        ));
    }
    let verified_recipient_share_opening_roots = recipient_share_opening_roots
        .iter()
        .enumerate()
        .map(|(opening_root_index, opening_root)| {
            let root = opening_root.as_str().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!(
                        "compact VSS share linkage source statement recipientShareOpeningRoots.{opening_root_index} must be a string"
                    ),
                )
            })?;
            validate_hash_string(
                root,
                &format!(
                    "compact VSS share linkage source statement recipientShareOpeningRoots.{opening_root_index}"
                ),
            )?;

            Ok(Value::String(root.to_string()))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    compare_required_string(
        hash_at_path(
            input.source_statement_record,
            &["aggregateThresholdCommitmentRoot"],
        )?,
        input.statement.aggregate_threshold_commitment_root,
        "compact VSS share linkage source statement aggregateThresholdCommitmentRoot",
    )?;
    compare_required_string(
        string_at_path(input.source_statement_record, &["relation"])?,
        COMPACT_VSS_SHARE_LINKAGE_STATEMENT_RELATION,
        "compact VSS share linkage source statement relation",
    )?;
    compare_required_string(
        string_at_path(input.source_statement_record, &["proofBatchingRule"])?,
        COMPACT_VSS_SHARE_LINKAGE_PROOF_BATCHING_RULE,
        "compact VSS share linkage source statement proofBatchingRule",
    )?;
    compare_required_string(
        string_at_path(input.source_statement_record, &["shamirEvaluationRule"])?,
        COMPACT_VSS_SHARE_LINKAGE_SHAMIR_EVALUATION_RULE,
        "compact VSS share linkage source statement shamirEvaluationRule",
    )?;
    compare_required_string(
        string_at_path(input.source_statement_record, &["aggregateThresholdRule"])?,
        COMPACT_VSS_SHARE_LINKAGE_AGGREGATE_THRESHOLD_RULE,
        "compact VSS share linkage source statement aggregateThresholdRule",
    )?;
    compare_required_string(
        string_at_path(input.source_statement_record, &["commonKeyRule"])?,
        COMPACT_VSS_SHARE_LINKAGE_COMMON_KEY_RULE,
        "compact VSS share linkage source statement commonKeyRule",
    )?;
    let expected_source_statement = json!({
        "objectType": "CompactVssShareLinkageSourceStatement",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "ceremonyId": input.statement.ceremony_id,
        "manifestHash": input.statement.manifest_hash,
        "rosterHash": input.statement.roster_hash,
        "setupProfileHash": input.statement.setup_profile_hash,
        "qShareHash": input.statement.q_share_hash,
        "carryAwareVssShareRelationProfileHash": input
            .statement
            .carry_aware_vss_share_relation_profile_hash,
        "commitmentProfileHash": input.statement.commitment_profile_hash,
        "setupEpoch": input.statement.setup_epoch,
        "publicMatrixSeedHash": input.statement.public_matrix_seed_hash,
        "targetBasisHash": input.statement.target_basis_hash,
        "sourceTrusteeIdentity": source_trustee_identity,
        "sourceTrusteeRosterPosition": input.expected_source_position,
        "participantCount": input.statement.participant_count,
        "targetRnsLimbCount": input.statement.target_rns_limb_count,
        "thresholdDegree": input.statement.threshold_degree,
        "coefficientCommitmentRoot": input.statement.coefficient_commitment_root,
        "sourceCoefficientCommitmentRoot": source_coefficient_commitment_root,
        "sourceRecipientShareCommitmentRoot": source_recipient_share_commitment_root,
        "coefficientOpeningRoots": verified_coefficient_opening_roots,
        "recipientShareOpeningRoots": verified_recipient_share_opening_roots,
        "aggregateThresholdCommitmentRoot": input.statement.aggregate_threshold_commitment_root,
        "relation": COMPACT_VSS_SHARE_LINKAGE_STATEMENT_RELATION,
        "proofBatchingRule": COMPACT_VSS_SHARE_LINKAGE_PROOF_BATCHING_RULE,
        "shamirEvaluationRule": COMPACT_VSS_SHARE_LINKAGE_SHAMIR_EVALUATION_RULE,
        "aggregateThresholdRule": COMPACT_VSS_SHARE_LINKAGE_AGGREGATE_THRESHOLD_RULE,
        "commonKeyRule": COMPACT_VSS_SHARE_LINKAGE_COMMON_KEY_RULE,
    });
    let source_statement_root =
        hash_at_path(input.source_statement_record, &["sourceStatementRoot"])?;
    let expected_source_statement_root =
        derive_protocol_hash("SetupProofRecordBindingHash", &expected_source_statement)?;
    if expected_source_statement_root != source_statement_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "compact VSS share linkage source statement root does not match its bound roots",
        ));
    }

    let mut verified_source_statement = expected_source_statement;
    verified_source_statement["sourceStatementRoot"] = json!(source_statement_root);

    Ok(verified_source_statement)
}

struct CompactVssSourceCoefficientRecordInput<'a> {
    source_record: &'a Value,
    expected_roster_position: usize,
    expected_coefficient_count: usize,
    threshold_degree: usize,
    public_matrix_seed_hash: &'a str,
}

fn verify_compact_vss_source_coefficient_record(
    input: CompactVssSourceCoefficientRecordInput<'_>,
) -> CanonicalResult<Value> {
    compare_required_string(
        string_at_path(input.source_record, &["objectType"])?,
        "CompactVssSourceCoefficientCommitments",
        "compact VSS source coefficient commitments objectType",
    )?;
    compare_required_u64(
        unsigned_at_path(input.source_record, &["objectVersion"])?,
        1,
        "compact VSS source coefficient commitments objectVersion",
    )?;
    compare_required_string(
        string_at_path(input.source_record, &["profileId"])?,
        COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "compact VSS source coefficient commitments profileId",
    )?;
    let source_trustee_identity =
        read_non_empty_string(input.source_record, "sourceTrusteeIdentity")?;
    compare_required_u64(
        unsigned_at_path(input.source_record, &["sourceTrusteeRosterPosition"])?,
        input.expected_roster_position as u64,
        "compact VSS source coefficient commitments sourceTrusteeRosterPosition",
    )?;
    compare_required_string(
        hash_at_path(input.source_record, &["publicMatrixSeedHash"])?,
        input.public_matrix_seed_hash,
        "compact VSS source coefficient commitments publicMatrixSeedHash",
    )?;
    let coefficient_commitments = array_at_path(input.source_record, &["coefficientCommitments"])?;
    if coefficient_commitments.len() != input.expected_coefficient_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "compact VSS source coefficient commitments must cover every RNS limb and Shamir coefficient",
        ));
    }

    let mut verified_coefficient_commitments = Vec::with_capacity(coefficient_commitments.len());
    for (coefficient_record_index, coefficient_record) in coefficient_commitments.iter().enumerate()
    {
        verified_coefficient_commitments.push(verify_compact_vss_coefficient_record(
            CompactVssCoefficientRecordInput {
                coefficient_record,
                source_trustee_identity,
                source_trustee_roster_position: input.expected_roster_position,
                expected_rns_limb_index: coefficient_record_index / input.threshold_degree,
                expected_shamir_coefficient_index: coefficient_record_index
                    % input.threshold_degree,
                public_matrix_seed_hash: input.public_matrix_seed_hash,
            },
        )?);
    }

    let expected_source_root = derive_protocol_hash(
        "VssCoefficientCommitmentRoot",
        &json!({
            "objectType": "CompactVssSourceCoefficientCommitments",
            "objectVersion": 1,
            "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
            "sourceTrusteeIdentity": source_trustee_identity,
            "sourceTrusteeRosterPosition": input.expected_roster_position,
            "publicMatrixSeedHash": input.public_matrix_seed_hash,
            "coefficientCommitments": verified_coefficient_commitments,
        }),
    )?;
    let source_coefficient_commitment_root =
        hash_at_path(input.source_record, &["sourceCoefficientCommitmentRoot"])?;
    if expected_source_root != source_coefficient_commitment_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "compact VSS source coefficient commitment root does not match its records",
        ));
    }

    Ok(json!({
        "objectType": "CompactVssSourceCoefficientCommitments",
        "objectVersion": 1,
        "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "sourceTrusteeIdentity": source_trustee_identity,
        "sourceTrusteeRosterPosition": input.expected_roster_position,
        "publicMatrixSeedHash": input.public_matrix_seed_hash,
        "coefficientCommitments": verified_coefficient_commitments,
        "sourceCoefficientCommitmentRoot": source_coefficient_commitment_root,
    }))
}

struct CompactVssCoefficientRecordInput<'a> {
    coefficient_record: &'a Value,
    source_trustee_identity: &'a str,
    source_trustee_roster_position: usize,
    expected_rns_limb_index: usize,
    expected_shamir_coefficient_index: usize,
    public_matrix_seed_hash: &'a str,
}

struct CompactVssCommitmentBodyInput<'a> {
    commitment: &'a Value,
    expected_commitment_role: &'a str,
    expected_commitment_root: &'a str,
    expected_public_matrix_seed_hash: &'a str,
    expected_rns_limb_index: usize,
    expected_rns_prime: u64,
    field_name: &'a str,
}

fn validate_standalone_compact_vss_commitment_body(
    commitment: &Value,
    field_name: &str,
) -> CanonicalResult<Value> {
    compare_required_string(
        string_at_path(commitment, &["objectType"])?,
        "CompactVssCommitment",
        &format!("{field_name} objectType"),
    )?;
    compare_required_u64(
        unsigned_at_path(commitment, &["objectVersion"])?,
        1,
        &format!("{field_name} objectVersion"),
    )?;
    compare_required_string(
        string_at_path(commitment, &["profileId"])?,
        COMPACT_VSS_COMMITMENT_PROFILE_ID,
        &format!("{field_name} profileId"),
    )?;
    validate_compact_vss_commitment_role(string_at_path(commitment, &["commitmentRole"])?)?;
    let _commitment_context_hash = hash_at_path(commitment, &["commitmentContextHash"])?;
    let _public_matrix_seed_hash = hash_at_path(commitment, &["publicMatrixSeedHash"])?;
    let _rns_limb_index = usize_at_path(commitment, &["rnsLimbIndex"])?;
    let _rns_prime =
        read_positive_u64_at_path(commitment, &["rnsPrime"], &format!("{field_name} rnsPrime"))?;
    let _ring_degree = read_positive_usize_at_path(
        commitment,
        &["ringDegree"],
        &format!("{field_name} ringDegree"),
    )?;
    compare_required_u64(
        unsigned_at_path(commitment, &["outputCoordinateCount"])?,
        COMPACT_VSS_OUTPUT_COORDINATE_COUNT as u64,
        &format!("{field_name} outputCoordinateCount"),
    )?;
    compare_required_u64(
        unsigned_at_path(commitment, &["randomnessColumnCount"])?,
        COMPACT_VSS_RANDOMNESS_COLUMN_COUNT as u64,
        &format!("{field_name} randomnessColumnCount"),
    )?;
    let commitment_limbs = array_at_path(commitment, &["commitmentLimbs"])?;
    if commitment_limbs.len() != COMPACT_VSS_COMMITMENT_MODULUS_LIMB_INDICES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{field_name} commitmentLimbs must cover the compact commitment modulus limbs"),
        ));
    }
    for (limb_position, commitment_limb) in commitment_limbs.iter().enumerate() {
        let expected_commitment_modulus_index =
            COMPACT_VSS_COMMITMENT_MODULUS_LIMB_INDICES[limb_position];
        compare_required_u64(
            unsigned_at_path(commitment_limb, &["commitmentModulusIndex"])?,
            expected_commitment_modulus_index as u64,
            &format!("{field_name} commitmentLimbs.{limb_position}.commitmentModulusIndex"),
        )?;
        let expected_modulus = DATA_PRIMES[expected_commitment_modulus_index];
        compare_required_u64(
            unsigned_at_path(commitment_limb, &["modulus"])?,
            expected_modulus,
            &format!("{field_name} commitmentLimbs.{limb_position}.modulus"),
        )?;
        let coordinates = array_at_path(commitment_limb, &["coordinates"])?;
        if coordinates.len() != COMPACT_VSS_OUTPUT_COORDINATE_COUNT {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                format!(
                    "{field_name} commitmentLimbs.{limb_position}.coordinates length must match the compact output count"
                ),
            ));
        }
        for (coordinate_index, coordinate) in coordinates.iter().enumerate() {
            let coordinate_value = coordinate.as_u64().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!(
                        "{field_name} commitmentLimbs.{limb_position}.coordinates.{coordinate_index} must be an unsigned integer"
                    ),
                )
            })?;
            if coordinate_value >= expected_modulus {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!(
                        "{field_name} commitmentLimbs.{limb_position}.coordinates.{coordinate_index} must be below the commitment modulus"
                    ),
                ));
            }
        }
    }

    Ok(commitment.clone())
}

fn verify_compact_vss_commitment_body(
    input: CompactVssCommitmentBodyInput<'_>,
) -> CanonicalResult<Value> {
    let commitment =
        validate_standalone_compact_vss_commitment_body(input.commitment, input.field_name)?;
    compare_required_string(
        string_at_path(&commitment, &["commitmentRole"])?,
        input.expected_commitment_role,
        &format!("{} commitmentRole", input.field_name),
    )?;
    compare_required_string(
        hash_at_path(&commitment, &["publicMatrixSeedHash"])?,
        input.expected_public_matrix_seed_hash,
        &format!("{} publicMatrixSeedHash", input.field_name),
    )?;
    compare_required_u64(
        unsigned_at_path(&commitment, &["rnsLimbIndex"])?,
        input.expected_rns_limb_index as u64,
        &format!("{} rnsLimbIndex", input.field_name),
    )?;
    compare_required_u64(
        unsigned_at_path(&commitment, &["rnsPrime"])?,
        input.expected_rns_prime,
        &format!("{} rnsPrime", input.field_name),
    )?;
    let commitment_root = derive_protocol_hash("SetupCommitmentRoot", &commitment)?;
    if commitment_root != input.expected_commitment_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!(
                "{} canonical root must match the containing record",
                input.field_name
            ),
        ));
    }

    Ok(commitment)
}

fn encode_compact_vss_commitment_body_value(commitment: &Value) -> CanonicalResult<Vec<u8>> {
    validate_standalone_compact_vss_commitment_body(commitment, "compact VSS commitment")?;
    let commitment_limbs = array_at_path(commitment, &["commitmentLimbs"])?;
    let mut commitment_body_bytes =
        Vec::with_capacity(compact_vss_encoded_commitment_byte_length());
    for commitment_limb in commitment_limbs {
        let coordinates = array_at_path(commitment_limb, &["coordinates"])?;
        for coordinate in coordinates {
            let coordinate_value = coordinate.as_u64().ok_or_else(|| {
                invalid_compact_vss_input(
                    "compact VSS commitment coordinate must be an unsigned integer",
                )
            })?;
            commitment_body_bytes.extend_from_slice(&coordinate_value.to_le_bytes());
        }
    }

    Ok(commitment_body_bytes)
}

fn decode_compact_vss_commitment_body_value(
    metadata: &Value,
    commitment_body_bytes: &[u8],
) -> CanonicalResult<Value> {
    let commitment_role = string_at_path(metadata, &["commitmentRole"])?;
    validate_compact_vss_commitment_role(commitment_role)?;
    let commitment_context_hash = hash_at_path(metadata, &["commitmentContextHash"])?;
    let public_matrix_seed_hash = hash_at_path(metadata, &["publicMatrixSeedHash"])?;
    let rns_limb_index = usize_at_path(metadata, &["rnsLimbIndex"])?;
    let rns_prime = read_positive_u64_at_path(metadata, &["rnsPrime"], "metadata rnsPrime")?;
    let ring_degree =
        read_positive_usize_at_path(metadata, &["ringDegree"], "metadata ringDegree")?;
    if commitment_body_bytes.len() != compact_vss_encoded_commitment_byte_length() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "compact VSS encoded commitment body length must match the compact commitment profile",
        ));
    }

    let mut offset = 0_usize;
    let commitment_limbs = COMPACT_VSS_COMMITMENT_MODULUS_LIMB_INDICES
        .iter()
        .map(|commitment_modulus_index| {
            let modulus = DATA_PRIMES[*commitment_modulus_index];
            let mut coordinates = Vec::with_capacity(COMPACT_VSS_OUTPUT_COORDINATE_COUNT);
            for coordinate_index in 0..COMPACT_VSS_OUTPUT_COORDINATE_COUNT {
                let mut coordinate_bytes = [0_u8; 8];
                coordinate_bytes.copy_from_slice(&commitment_body_bytes[offset..offset + 8]);
                offset += 8;
                let coordinate_value = u64::from_le_bytes(coordinate_bytes);
                if coordinate_value >= modulus {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        format!(
                            "compact VSS encoded commitment body coordinate {coordinate_index} must be below the commitment modulus"
                        ),
                    ));
                }
                coordinates.push(coordinate_value);
            }

            Ok(json!({
                "commitmentModulusIndex": commitment_modulus_index,
                "modulus": modulus,
                "coordinates": coordinates,
            }))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok(json!({
        "objectType": "CompactVssCommitment",
        "objectVersion": 1,
        "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "commitmentRole": commitment_role,
        "commitmentContextHash": commitment_context_hash,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "rnsLimbIndex": rns_limb_index,
        "rnsPrime": rns_prime,
        "ringDegree": ring_degree,
        "outputCoordinateCount": COMPACT_VSS_OUTPUT_COORDINATE_COUNT,
        "randomnessColumnCount": COMPACT_VSS_RANDOMNESS_COLUMN_COUNT,
        "commitmentLimbs": commitment_limbs,
    }))
}

fn verify_compact_vss_coefficient_record(
    input: CompactVssCoefficientRecordInput<'_>,
) -> CanonicalResult<Value> {
    compare_required_string(
        string_at_path(input.coefficient_record, &["objectType"])?,
        "CompactVssCoefficientCommitment",
        "compact VSS coefficient commitment objectType",
    )?;
    compare_required_u64(
        unsigned_at_path(input.coefficient_record, &["objectVersion"])?,
        1,
        "compact VSS coefficient commitment objectVersion",
    )?;
    compare_required_string(
        string_at_path(input.coefficient_record, &["profileId"])?,
        COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "compact VSS coefficient commitment profileId",
    )?;
    compare_required_string(
        string_at_path(input.coefficient_record, &["sourceTrusteeIdentity"])?,
        input.source_trustee_identity,
        "compact VSS coefficient commitment sourceTrusteeIdentity",
    )?;
    compare_required_u64(
        unsigned_at_path(input.coefficient_record, &["sourceTrusteeRosterPosition"])?,
        input.source_trustee_roster_position as u64,
        "compact VSS coefficient commitment sourceTrusteeRosterPosition",
    )?;
    compare_required_string(
        hash_at_path(input.coefficient_record, &["publicMatrixSeedHash"])?,
        input.public_matrix_seed_hash,
        "compact VSS coefficient commitment publicMatrixSeedHash",
    )?;
    compare_required_u64(
        unsigned_at_path(input.coefficient_record, &["rnsLimbIndex"])?,
        input.expected_rns_limb_index as u64,
        "compact VSS coefficient commitment rnsLimbIndex",
    )?;
    let rns_prime = read_positive_u64_at_path(
        input.coefficient_record,
        &["rnsPrime"],
        "compact VSS coefficient commitment rnsPrime",
    )?;
    compare_required_u64(
        unsigned_at_path(input.coefficient_record, &["shamirCoefficientIndex"])?,
        input.expected_shamir_coefficient_index as u64,
        "compact VSS coefficient commitment shamirCoefficientIndex",
    )?;
    let coefficient_commitment_root =
        hash_at_path(input.coefficient_record, &["coefficientCommitmentRoot"])?;
    let coefficient_opening_root =
        hash_at_path(input.coefficient_record, &["coefficientOpeningRoot"])?;
    let commitment = verify_compact_vss_commitment_body(CompactVssCommitmentBodyInput {
        commitment: value_at_path(input.coefficient_record, &["commitment"])?,
        expected_commitment_role: "coefficient",
        expected_commitment_root: coefficient_commitment_root,
        expected_public_matrix_seed_hash: input.public_matrix_seed_hash,
        expected_rns_limb_index: input.expected_rns_limb_index,
        expected_rns_prime: rns_prime,
        field_name: "compact VSS coefficient commitment commitment",
    })?;

    Ok(json!({
        "objectType": "CompactVssCoefficientCommitment",
        "objectVersion": 1,
        "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "sourceTrusteeIdentity": input.source_trustee_identity,
        "sourceTrusteeRosterPosition": input.source_trustee_roster_position,
        "publicMatrixSeedHash": input.public_matrix_seed_hash,
        "rnsLimbIndex": input.expected_rns_limb_index,
        "rnsPrime": rns_prime,
        "shamirCoefficientIndex": input.expected_shamir_coefficient_index,
        "coefficientCommitmentRoot": coefficient_commitment_root,
        "coefficientOpeningRoot": coefficient_opening_root,
        "commitment": commitment,
    }))
}

struct CompactVssSourceRecipientShareRecordInput<'a> {
    source_record: &'a Value,
    expected_source_roster_position: usize,
    expected_recipient_share_count: usize,
    rns_limb_count: usize,
    public_matrix_seed_hash: &'a str,
}

fn verify_compact_vss_source_recipient_share_record(
    input: CompactVssSourceRecipientShareRecordInput<'_>,
) -> CanonicalResult<Value> {
    compare_required_string(
        string_at_path(input.source_record, &["objectType"])?,
        "CompactVssSourceRecipientShareCommitments",
        "compact VSS source recipient-share commitments objectType",
    )?;
    compare_required_u64(
        unsigned_at_path(input.source_record, &["objectVersion"])?,
        1,
        "compact VSS source recipient-share commitments objectVersion",
    )?;
    compare_required_string(
        string_at_path(input.source_record, &["profileId"])?,
        COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "compact VSS source recipient-share commitments profileId",
    )?;
    let source_trustee_identity =
        read_non_empty_string(input.source_record, "sourceTrusteeIdentity")?;
    compare_required_u64(
        unsigned_at_path(input.source_record, &["sourceTrusteeRosterPosition"])?,
        input.expected_source_roster_position as u64,
        "compact VSS source recipient-share commitments sourceTrusteeRosterPosition",
    )?;
    let recipient_share_commitments =
        array_at_path(input.source_record, &["recipientShareCommitments"])?;
    if recipient_share_commitments.len() != input.expected_recipient_share_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "compact VSS source recipient-share commitments must cover every recipient and RNS limb",
        ));
    }

    let mut verified_recipient_share_commitments =
        Vec::with_capacity(recipient_share_commitments.len());
    for (recipient_share_record_index, recipient_share_record) in
        recipient_share_commitments.iter().enumerate()
    {
        verified_recipient_share_commitments.push(verify_compact_vss_recipient_share_record(
            CompactVssRecipientShareRecordInput {
                recipient_share_record,
                source_trustee_identity,
                source_trustee_roster_position: input.expected_source_roster_position,
                expected_recipient_roster_position: recipient_share_record_index
                    / input.rns_limb_count,
                expected_rns_limb_index: recipient_share_record_index % input.rns_limb_count,
                public_matrix_seed_hash: input.public_matrix_seed_hash,
            },
        )?);
    }

    let expected_source_root = derive_protocol_hash(
        "ThresholdShareCommitmentRoot",
        &json!({
            "objectType": "CompactVssSourceRecipientShareCommitments",
            "objectVersion": 1,
            "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
            "sourceTrusteeIdentity": source_trustee_identity,
            "sourceTrusteeRosterPosition": input.expected_source_roster_position,
            "recipientShareCommitments": verified_recipient_share_commitments,
        }),
    )?;
    let source_recipient_share_commitment_root =
        hash_at_path(input.source_record, &["sourceRecipientShareCommitmentRoot"])?;
    if expected_source_root != source_recipient_share_commitment_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "compact VSS source recipient-share commitment root does not match its records",
        ));
    }

    Ok(json!({
        "objectType": "CompactVssSourceRecipientShareCommitments",
        "objectVersion": 1,
        "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "sourceTrusteeIdentity": source_trustee_identity,
        "sourceTrusteeRosterPosition": input.expected_source_roster_position,
        "recipientShareCommitments": verified_recipient_share_commitments,
        "sourceRecipientShareCommitmentRoot": source_recipient_share_commitment_root,
    }))
}

struct CompactVssRecipientShareRecordInput<'a> {
    recipient_share_record: &'a Value,
    source_trustee_identity: &'a str,
    source_trustee_roster_position: usize,
    expected_recipient_roster_position: usize,
    expected_rns_limb_index: usize,
    public_matrix_seed_hash: &'a str,
}

fn verify_compact_vss_recipient_share_record(
    input: CompactVssRecipientShareRecordInput<'_>,
) -> CanonicalResult<Value> {
    compare_required_string(
        string_at_path(input.recipient_share_record, &["objectType"])?,
        "CompactVssRecipientShareCommitment",
        "compact VSS recipient-share commitment objectType",
    )?;
    compare_required_u64(
        unsigned_at_path(input.recipient_share_record, &["objectVersion"])?,
        1,
        "compact VSS recipient-share commitment objectVersion",
    )?;
    compare_required_string(
        string_at_path(input.recipient_share_record, &["profileId"])?,
        COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "compact VSS recipient-share commitment profileId",
    )?;
    compare_required_string(
        string_at_path(input.recipient_share_record, &["sourceTrusteeIdentity"])?,
        input.source_trustee_identity,
        "compact VSS recipient-share commitment sourceTrusteeIdentity",
    )?;
    compare_required_u64(
        unsigned_at_path(
            input.recipient_share_record,
            &["sourceTrusteeRosterPosition"],
        )?,
        input.source_trustee_roster_position as u64,
        "compact VSS recipient-share commitment sourceTrusteeRosterPosition",
    )?;
    let recipient_identity =
        read_non_empty_string(input.recipient_share_record, "recipientIdentity")?;
    compare_required_u64(
        unsigned_at_path(input.recipient_share_record, &["recipientRosterPosition"])?,
        input.expected_recipient_roster_position as u64,
        "compact VSS recipient-share commitment recipientRosterPosition",
    )?;
    compare_required_u64(
        unsigned_at_path(input.recipient_share_record, &["recipientTrusteePoint"])?,
        (input.expected_recipient_roster_position + 1) as u64,
        "compact VSS recipient-share commitment recipientTrusteePoint",
    )?;
    compare_required_u64(
        unsigned_at_path(input.recipient_share_record, &["rnsLimbIndex"])?,
        input.expected_rns_limb_index as u64,
        "compact VSS recipient-share commitment rnsLimbIndex",
    )?;
    let rns_prime = read_positive_u64_at_path(
        input.recipient_share_record,
        &["rnsPrime"],
        "compact VSS recipient-share commitment rnsPrime",
    )?;
    let share_commitment_root =
        hash_at_path(input.recipient_share_record, &["shareCommitmentRoot"])?;
    let share_opening_root = hash_at_path(input.recipient_share_record, &["shareOpeningRoot"])?;
    let commitment = verify_compact_vss_commitment_body(CompactVssCommitmentBodyInput {
        commitment: value_at_path(input.recipient_share_record, &["commitment"])?,
        expected_commitment_role: "recipient-share",
        expected_commitment_root: share_commitment_root,
        expected_public_matrix_seed_hash: input.public_matrix_seed_hash,
        expected_rns_limb_index: input.expected_rns_limb_index,
        expected_rns_prime: rns_prime,
        field_name: "compact VSS recipient-share commitment commitment",
    })?;

    Ok(json!({
        "objectType": "CompactVssRecipientShareCommitment",
        "objectVersion": 1,
        "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "sourceTrusteeIdentity": input.source_trustee_identity,
        "sourceTrusteeRosterPosition": input.source_trustee_roster_position,
        "recipientIdentity": recipient_identity,
        "recipientRosterPosition": input.expected_recipient_roster_position,
        "recipientTrusteePoint": input.expected_recipient_roster_position + 1,
        "rnsLimbIndex": input.expected_rns_limb_index,
        "rnsPrime": rns_prime,
        "shareCommitmentRoot": share_commitment_root,
        "shareOpeningRoot": share_opening_root,
        "commitment": commitment,
    }))
}

struct CompactVssAggregateThresholdRecordInput<'a> {
    recipient_record: &'a Value,
    expected_recipient_roster_position: usize,
    expected_rns_limb_index: usize,
    participant_count: usize,
    public_matrix_seed_hash: &'a str,
}

fn verify_compact_vss_aggregate_threshold_record(
    input: CompactVssAggregateThresholdRecordInput<'_>,
) -> CanonicalResult<Value> {
    compare_required_string(
        string_at_path(input.recipient_record, &["objectType"])?,
        "CompactVssAggregateThresholdCommitment",
        "compact VSS aggregate threshold commitment objectType",
    )?;
    compare_required_u64(
        unsigned_at_path(input.recipient_record, &["objectVersion"])?,
        1,
        "compact VSS aggregate threshold commitment objectVersion",
    )?;
    compare_required_string(
        string_at_path(input.recipient_record, &["profileId"])?,
        COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "compact VSS aggregate threshold commitment profileId",
    )?;
    let recipient_identity = read_non_empty_string(input.recipient_record, "recipientIdentity")?;
    compare_required_u64(
        unsigned_at_path(input.recipient_record, &["recipientRosterPosition"])?,
        input.expected_recipient_roster_position as u64,
        "compact VSS aggregate threshold commitment recipientRosterPosition",
    )?;
    compare_required_u64(
        unsigned_at_path(input.recipient_record, &["recipientTrusteePoint"])?,
        (input.expected_recipient_roster_position + 1) as u64,
        "compact VSS aggregate threshold commitment recipientTrusteePoint",
    )?;
    compare_required_u64(
        unsigned_at_path(input.recipient_record, &["rnsLimbIndex"])?,
        input.expected_rns_limb_index as u64,
        "compact VSS aggregate threshold commitment rnsLimbIndex",
    )?;
    let rns_prime = read_positive_u64_at_path(
        input.recipient_record,
        &["rnsPrime"],
        "compact VSS aggregate threshold commitment rnsPrime",
    )?;
    let aggregate_commitment_root =
        hash_at_path(input.recipient_record, &["aggregateCommitmentRoot"])?;
    let aggregate_opening_root = hash_at_path(input.recipient_record, &["aggregateOpeningRoot"])?;
    let commitment = verify_compact_vss_commitment_body(CompactVssCommitmentBodyInput {
        commitment: value_at_path(input.recipient_record, &["commitment"])?,
        expected_commitment_role: "aggregate-threshold-share",
        expected_commitment_root: aggregate_commitment_root,
        expected_public_matrix_seed_hash: input.public_matrix_seed_hash,
        expected_rns_limb_index: input.expected_rns_limb_index,
        expected_rns_prime: rns_prime,
        field_name: "compact VSS aggregate threshold commitment commitment",
    })?;
    let source_share_commitment_roots =
        array_at_path(input.recipient_record, &["sourceShareCommitmentRoots"])?;
    if source_share_commitment_roots.len() != input.participant_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "compact VSS aggregate threshold commitment must bind one source share commitment root per participant",
        ));
    }
    let verified_source_share_commitment_roots = source_share_commitment_roots
        .iter()
        .enumerate()
        .map(|(source_roster_position, source_share_commitment_root)| {
            let root = source_share_commitment_root.as_str().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!(
                        "compact VSS aggregate threshold commitment sourceShareCommitmentRoots.{source_roster_position} must be a string"
                    ),
                )
            })?;
            validate_hash_string(
                root,
                &format!(
                    "compact VSS aggregate threshold commitment sourceShareCommitmentRoots.{source_roster_position}"
                ),
            )?;

            Ok(Value::String(root.to_string()))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let source_share_opening_roots =
        array_at_path(input.recipient_record, &["sourceShareOpeningRoots"])?;
    if source_share_opening_roots.len() != input.participant_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "compact VSS aggregate threshold commitment must bind one source share opening root per participant",
        ));
    }
    let verified_source_share_opening_roots = source_share_opening_roots
        .iter()
        .enumerate()
        .map(|(source_roster_position, source_share_opening_root)| {
            let root = source_share_opening_root.as_str().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!(
                        "compact VSS aggregate threshold commitment sourceShareOpeningRoots.{source_roster_position} must be a string"
                    ),
                )
            })?;
            validate_hash_string(
                root,
                &format!(
                    "compact VSS aggregate threshold commitment sourceShareOpeningRoots.{source_roster_position}"
                ),
            )?;

            Ok(Value::String(root.to_string()))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok(json!({
        "objectType": "CompactVssAggregateThresholdCommitment",
        "objectVersion": 1,
        "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "recipientIdentity": recipient_identity,
        "recipientRosterPosition": input.expected_recipient_roster_position,
        "recipientTrusteePoint": input.expected_recipient_roster_position + 1,
        "rnsLimbIndex": input.expected_rns_limb_index,
        "rnsPrime": rns_prime,
        "aggregateCommitmentRoot": aggregate_commitment_root,
        "aggregateOpeningRoot": aggregate_opening_root,
        "commitment": commitment,
        "sourceShareCommitmentRoots": verified_source_share_commitment_roots,
        "sourceShareOpeningRoots": verified_source_share_opening_roots,
    }))
}

pub(crate) fn read_compact_vss_randomness_by_column(
    value: &Value,
    field_name: &str,
    ring_degree: usize,
    active_limb_modulus: Option<u64>,
) -> CanonicalResult<Vec<Vec<i64>>> {
    let columns = value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{field_name} must be an array"),
            )
        })?;
    if columns.len() != COMPACT_VSS_RANDOMNESS_COLUMN_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{field_name} must carry the compact randomness column count"),
        ));
    }
    let randomness_by_column = columns
        .iter()
        .enumerate()
        .map(|(column_index, column)| {
            let coefficients = column.as_array().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!("{field_name}.{column_index} must be an array"),
                )
            })?;
            if coefficients.len() != ring_degree {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    format!("{field_name}.{column_index} has the wrong coefficient count"),
                ));
            }
            coefficients
                .iter()
                .enumerate()
                .map(|(coefficient_index, coefficient)| {
                    let value = coefficient.as_i64().ok_or_else(|| {
                        CanonicalError::new(
                            CanonicalErrorCode::InvalidFixture,
                            format!(
                                "{field_name}.{column_index}.{coefficient_index} must be a signed integer"
                            ),
                        )
                    })?;
                    if active_limb_modulus.is_some_and(|modulus| value.unsigned_abs() >= modulus) {
                        return Err(CanonicalError::new(
                            CanonicalErrorCode::InvalidFixture,
                            "compact VSS opening randomness coefficient exceeds the active limb modulus",
                        ));
                    }

                    Ok(value)
                })
                .collect()
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    validate_compact_vss_randomness_columns(
        &randomness_by_column,
        ring_degree,
        active_limb_modulus,
        field_name,
    )?;

    Ok(randomness_by_column)
}

fn compute_compact_vss_commitment_from_opening_value(
    opening: &Value,
) -> CanonicalResult<CompactVssCommitmentComputation> {
    let commitment_role = string_at_path(opening, &["commitmentRole"])?;
    let commitment_context = value_at_path(opening, &["commitmentContext"])?;
    let public_matrix_seed_hash = hash_at_path(opening, &["publicMatrixSeedHash"])?;
    let rns_limb_index = usize_at_path(opening, &["rnsLimbIndex"])?;
    let rns_prime = unsigned_at_path(opening, &["rnsPrime"])?;
    let ring_degree = usize_at_path(opening, &["ringDegree"])?;
    let message_coefficient_bound =
        read_optional_u64(opening, "messageCoefficientBound")?.unwrap_or(rns_prime);
    let message_coefficients = read_compact_vss_message_coefficients(
        opening,
        "messageCoefficients",
        ring_degree,
        message_coefficient_bound,
    )?;
    let randomness_by_column =
        read_compact_vss_randomness_by_column(opening, "randomnessByColumn", ring_degree, None)?;

    compute_compact_vss_commitment_from_opening(CompactVssCommitmentOpeningInput {
        commitment_role,
        commitment_context,
        public_matrix_seed_hash,
        rns_limb_index,
        rns_prime,
        ring_degree,
        message_coefficients: &message_coefficients,
        message_coefficient_bound,
        randomness_by_column: &randomness_by_column,
    })
}

fn compact_vss_commitment_computation_response(
    computation: &CompactVssCommitmentComputation,
) -> Value {
    json!({
        "ok": true,
        "operation": "computeCompactVssCommitmentFromOpening",
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "commitment": computation.commitment,
        "commitmentRoot": computation.commitment_root,
        "openingRoot": computation.opening_root,
        "commitmentContextHash": computation.commitment_context_hash,
        "encodedCommitmentByteLength": compact_vss_encoded_commitment_byte_length(),
    })
}

fn read_compact_vss_message_coefficients(
    value: &Value,
    field_name: &str,
    ring_degree: usize,
    message_coefficient_bound: u64,
) -> CanonicalResult<Vec<u64>> {
    if message_coefficient_bound == 0 {
        return Err(invalid_compact_vss_input(
            "messageCoefficientBound must be positive",
        ));
    }
    let coefficients = value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{field_name} must be an array"),
            )
        })?;
    if coefficients.len() != ring_degree {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{field_name} length must match ringDegree"),
        ));
    }
    coefficients
        .iter()
        .enumerate()
        .map(|(coefficient_index, coefficient)| {
            let value = coefficient.as_u64().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!("{field_name}.{coefficient_index} must be a non-negative integer"),
                )
            })?;
            if value >= message_coefficient_bound {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!(
                        "{field_name}.{coefficient_index} must be below messageCoefficientBound"
                    ),
                ));
            }

            Ok(value)
        })
        .collect()
}

fn validate_compact_vss_commitment_role(commitment_role: &str) -> CanonicalResult<()> {
    match commitment_role {
        "coefficient"
        | "recipient-share"
        | "aggregate-threshold-share"
        | "target-decryption-smudging-polynomial-coefficient" => Ok(()),
        _ => Err(invalid_compact_vss_input(
            "compact VSS commitment role is not supported",
        )),
    }
}

fn compare_required_u64(actual: u64, expected: u64, description: &str) -> CanonicalResult<()> {
    if actual != expected {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("passive BGV setup package {description} does not match its canonical binding"),
        ));
    }

    Ok(())
}

fn read_positive_usize_at_path(
    value: &Value,
    path: &[&str],
    description: &str,
) -> CanonicalResult<usize> {
    let field = usize_at_path(value, path)?;
    if field == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{description} must be positive"),
        ));
    }

    Ok(field)
}

fn read_positive_u64_at_path(
    value: &Value,
    path: &[&str],
    description: &str,
) -> CanonicalResult<u64> {
    let field = unsigned_at_path(value, path)?;
    if field == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{description} must be positive"),
        ));
    }

    Ok(field)
}

fn validate_compact_vss_randomness_columns(
    randomness_by_column: &[Vec<i64>],
    ring_degree: usize,
    active_limb_modulus: Option<u64>,
    field_name: &str,
) -> CanonicalResult<()> {
    if randomness_by_column.len() != COMPACT_VSS_RANDOMNESS_COLUMN_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{field_name} must contain the compact randomness column count"),
        ));
    }
    for (column_index, column) in randomness_by_column.iter().enumerate() {
        if column.len() != ring_degree {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                format!("{field_name}.{column_index} length must match ringDegree"),
            ));
        }
        if let Some(modulus) = active_limb_modulus {
            for coefficient in column {
                if coefficient.unsigned_abs() >= modulus {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "compact VSS opening randomness coefficient exceeds the active limb modulus",
                    ));
                }
            }
        }
    }

    Ok(())
}

struct CompactCommitmentCoordinateInput<'a> {
    public_matrix_seed_hash: &'a str,
    rns_limb_index: usize,
    commitment_modulus_index: usize,
    output_coordinate_index: usize,
    modulus: u64,
    message_coefficients: &'a [u64],
    randomness_by_column: &'a [Vec<i64>],
}

fn compact_commitment_coordinate(
    input: CompactCommitmentCoordinateInput<'_>,
) -> CanonicalResult<u64> {
    let mut accumulator = 0_u128;
    for digit_index in 0..COMPACT_VSS_MESSAGE_DIGIT_COUNT {
        let input_column = compact_vss_message_digit_column_label(digit_index)?;
        for (ring_coefficient_index, matrix_residue) in
            compact_projection_terms(CompactProjectionTermsInput {
                public_matrix_seed_hash: input.public_matrix_seed_hash,
                rns_limb_index: input.rns_limb_index,
                commitment_modulus_index: input.commitment_modulus_index,
                output_coordinate_index: input.output_coordinate_index,
                input_column: &input_column,
                ring_degree: input.message_coefficients.len(),
                modulus: input.modulus,
            })?
        {
            let digits =
                compact_vss_message_digits(input.message_coefficients[ring_coefficient_index])?;
            accumulator = add_product_mod(
                accumulator,
                digits[digit_index] % input.modulus,
                matrix_residue,
                input.modulus,
            );
        }
    }
    for (randomness_column_index, randomness_column) in
        input.randomness_by_column.iter().enumerate()
    {
        let input_column = format!("randomness:{randomness_column_index}");
        for (ring_coefficient_index, matrix_residue) in
            compact_projection_terms(CompactProjectionTermsInput {
                public_matrix_seed_hash: input.public_matrix_seed_hash,
                rns_limb_index: input.rns_limb_index,
                commitment_modulus_index: input.commitment_modulus_index,
                output_coordinate_index: input.output_coordinate_index,
                input_column: &input_column,
                ring_degree: randomness_column.len(),
                modulus: input.modulus,
            })?
        {
            accumulator = add_product_mod(
                accumulator,
                signed_integer_to_residue(randomness_column[ring_coefficient_index], input.modulus),
                matrix_residue,
                input.modulus,
            );
        }
    }

    Ok(accumulator as u64)
}

pub(in crate::bgv::setup) fn compact_vss_message_digit_column_label(
    digit_index: usize,
) -> CanonicalResult<String> {
    if digit_index >= COMPACT_VSS_MESSAGE_DIGIT_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "compact VSS message digit index is outside the selected profile",
        ));
    }

    Ok(format!("message:{digit_index}"))
}

pub(in crate::bgv::setup) fn compact_vss_message_digit_weight(
    digit_index: usize,
    modulus: u64,
) -> CanonicalResult<u64> {
    match digit_index {
        0 => Ok(1 % modulus),
        1 => Ok(COMPACT_VSS_MESSAGE_DIGIT_BASE % modulus),
        _ => Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "compact VSS message digit index is outside the selected profile",
        )),
    }
}

pub(in crate::bgv::setup) fn compact_vss_message_digits(
    coefficient: u64,
) -> CanonicalResult<[u64; COMPACT_VSS_MESSAGE_DIGIT_COUNT]> {
    let maximum_coefficient = u128::from(COMPACT_VSS_MESSAGE_DIGIT_BASE)
        .checked_pow(COMPACT_VSS_MESSAGE_DIGIT_COUNT as u32)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "compact VSS message digit range overflowed",
            )
        })?;
    if u128::from(coefficient) >= maximum_coefficient {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "compact VSS message coefficient exceeds the two-digit message range",
        ));
    }

    Ok([
        coefficient % COMPACT_VSS_MESSAGE_DIGIT_BASE,
        coefficient / COMPACT_VSS_MESSAGE_DIGIT_BASE,
    ])
}

fn compact_vss_trit_count_for_bound(bound_exclusive: u64) -> CanonicalResult<usize> {
    if bound_exclusive == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "compact VSS message coefficient bound must be positive",
        ));
    }
    let mut represented_bound = 1_u64;
    let mut trit_count = 0_usize;
    while represented_bound < bound_exclusive {
        represented_bound = represented_bound.checked_mul(3).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "compact VSS message trit bound overflowed",
            )
        })?;
        trit_count += 1;
    }

    Ok(trit_count)
}

pub(in crate::bgv::setup) fn compact_vss_message_encoding_layout(
    message_bound_exclusive: u64,
) -> CanonicalResult<CompactVssMessageEncodingLayout> {
    if message_bound_exclusive == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "compact VSS message coefficient bound must be positive",
        ));
    }
    let maximum_coefficient = u128::from(COMPACT_VSS_MESSAGE_DIGIT_BASE)
        .checked_pow(COMPACT_VSS_MESSAGE_DIGIT_COUNT as u32)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "compact VSS message digit range overflowed",
            )
        })?;
    if u128::from(message_bound_exclusive) > maximum_coefficient {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "compact VSS message coefficient bound exceeds the two-digit message range",
        ));
    }
    let high_digit_bound_exclusive =
        message_bound_exclusive.div_ceil(COMPACT_VSS_MESSAGE_DIGIT_BASE);
    let high_digit_trit_count = compact_vss_trit_count_for_bound(high_digit_bound_exclusive)?;

    Ok(CompactVssMessageEncodingLayout {
        high_digit_trit_count,
        range_evidence: CompactVssMessageRangeEvidence::DigitAndTritColumns,
    })
}

pub(in crate::bgv::setup) fn compact_vss_message_digit_trits_for_count(
    digit: u64,
    trit_count: usize,
) -> CanonicalResult<Vec<u64>> {
    let digit_bound = (0..trit_count).try_fold(1_u64, |bound, _| {
        bound.checked_mul(3).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "compact VSS message trit bound overflowed",
            )
        })
    })?;
    if digit >= digit_bound {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "compact VSS message digit exceeds the statement-bound trit range",
        ));
    }
    let mut remaining = digit;
    let mut trits = vec![0_u64; trit_count];
    for trit in &mut trits {
        *trit = remaining % 3;
        remaining /= 3;
    }
    if remaining != 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "compact VSS message digit did not fit the selected trit count",
        ));
    }

    Ok(trits)
}

pub(in crate::bgv::setup) struct CompactProjectionTermsInput<'a> {
    pub(in crate::bgv::setup) public_matrix_seed_hash: &'a str,
    pub(in crate::bgv::setup) rns_limb_index: usize,
    pub(in crate::bgv::setup) commitment_modulus_index: usize,
    pub(in crate::bgv::setup) output_coordinate_index: usize,
    pub(in crate::bgv::setup) input_column: &'a str,
    pub(in crate::bgv::setup) ring_degree: usize,
    pub(in crate::bgv::setup) modulus: u64,
}

pub(in crate::bgv::setup) fn compact_projection_terms(
    input: CompactProjectionTermsInput<'_>,
) -> CanonicalResult<Vec<(usize, u64)>> {
    (0..COMPACT_VSS_PROJECTION_WEIGHT)
        .map(|projection_term_index| {
            Ok((
                sample_compact_projection_index(SampleCompactProjectionInput {
                    public_matrix_seed_hash: input.public_matrix_seed_hash,
                    rns_limb_index: input.rns_limb_index,
                    commitment_modulus_index: input.commitment_modulus_index,
                    output_coordinate_index: input.output_coordinate_index,
                    input_column: input.input_column,
                    projection_term_index,
                    ring_degree: input.ring_degree,
                })?,
                sample_compact_matrix_residue(SampleCompactMatrixInput {
                    public_matrix_seed_hash: input.public_matrix_seed_hash,
                    rns_limb_index: input.rns_limb_index,
                    commitment_modulus_index: input.commitment_modulus_index,
                    output_coordinate_index: input.output_coordinate_index,
                    input_column: input.input_column,
                    projection_term_index,
                    modulus: input.modulus,
                })?,
            ))
        })
        .collect()
}

struct SampleCompactMatrixInput<'a> {
    public_matrix_seed_hash: &'a str,
    rns_limb_index: usize,
    commitment_modulus_index: usize,
    output_coordinate_index: usize,
    input_column: &'a str,
    projection_term_index: usize,
    modulus: u64,
}

fn sample_compact_matrix_residue(input: SampleCompactMatrixInput<'_>) -> CanonicalResult<u64> {
    let modulus = u128::from(input.modulus);
    let limit = (1_u128 << 64) - ((1_u128 << 64) % modulus);
    let mut block_index = 0_usize;
    loop {
        let preimage = [
            input.public_matrix_seed_hash,
            COMPACT_VSS_COMMITMENT_PROFILE_ID,
            &input.rns_limb_index.to_string(),
            &input.commitment_modulus_index.to_string(),
            &input.output_coordinate_index.to_string(),
            input.input_column,
            &input.projection_term_index.to_string(),
            &input.modulus.to_string(),
            &block_index.to_string(),
        ]
        .join("|");
        let digest = hash512(
            COMPACT_VSS_MATRIX_RESIDUE_HASH_DOMAIN,
            &[preimage.as_bytes()],
        );
        for chunk in digest.chunks_exact(8) {
            let mut bytes = [0_u8; 8];
            bytes.copy_from_slice(chunk);
            let value = u128::from(u64::from_le_bytes(bytes));
            if value < limit {
                return Ok((value % modulus) as u64);
            }
        }
        block_index = block_index.checked_add(1).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "compact VSS matrix-residue sampler block index overflowed",
            )
        })?;
    }
}

struct SampleCompactProjectionInput<'a> {
    public_matrix_seed_hash: &'a str,
    rns_limb_index: usize,
    commitment_modulus_index: usize,
    output_coordinate_index: usize,
    input_column: &'a str,
    projection_term_index: usize,
    ring_degree: usize,
}

fn sample_compact_projection_index(
    input: SampleCompactProjectionInput<'_>,
) -> CanonicalResult<usize> {
    let modulus = input.ring_degree as u128;
    let limit = (1_u128 << 64) - ((1_u128 << 64) % modulus);
    let mut block_index = 0_usize;
    loop {
        let preimage = [
            input.public_matrix_seed_hash,
            COMPACT_VSS_COMMITMENT_PROFILE_ID,
            &input.rns_limb_index.to_string(),
            &input.commitment_modulus_index.to_string(),
            &input.output_coordinate_index.to_string(),
            input.input_column,
            &input.projection_term_index.to_string(),
            &input.ring_degree.to_string(),
            &block_index.to_string(),
        ]
        .join("|");
        let digest = hash512(
            COMPACT_VSS_PROJECTION_INDEX_HASH_DOMAIN,
            &[preimage.as_bytes()],
        );
        for chunk in digest.chunks_exact(8) {
            let mut bytes = [0_u8; 8];
            bytes.copy_from_slice(chunk);
            let value = u128::from(u64::from_le_bytes(bytes));
            if value < limit {
                return Ok((value % modulus) as usize);
            }
        }
        block_index = block_index.checked_add(1).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "compact VSS projection-index sampler block index overflowed",
            )
        })?;
    }
}

fn add_product_mod(accumulator: u128, left: u64, right: u64, modulus: u64) -> u128 {
    (accumulator + (u128::from(left) * u128::from(right))) % u128::from(modulus)
}

fn signed_integer_to_residue(value: i64, modulus: u64) -> u64 {
    i128::from(value).rem_euclid(i128::from(modulus)) as u64
}

fn compact_vss_opening_payload_hash(
    message_coefficients: &[u64],
    randomness_by_column: &[Vec<i64>],
) -> CanonicalResult<String> {
    let word_count = 2_usize
        .checked_add(message_coefficients.len())
        .and_then(|count| {
            randomness_by_column
                .iter()
                .try_fold(count, |total, column| {
                    total.checked_add(1)?.checked_add(column.len())
                })
        })
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "compact VSS opening payload length overflowed",
            )
        })?;
    let mut bytes = Vec::with_capacity(word_count * 8);
    bytes.extend((message_coefficients.len() as u64).to_le_bytes());
    for coefficient in message_coefficients {
        bytes.extend(coefficient.to_le_bytes());
    }
    bytes.extend((randomness_by_column.len() as u64).to_le_bytes());
    for column in randomness_by_column {
        bytes.extend((column.len() as u64).to_le_bytes());
        for coefficient in column {
            bytes.extend(coefficient.to_le_bytes());
        }
    }

    Ok(hash512_hex(
        COMPACT_VSS_OPENING_PAYLOAD_HASH_DOMAIN,
        &[&bytes],
    ))
}

fn compact_vss_encoded_commitment_byte_length() -> usize {
    COMPACT_VSS_COMMITMENT_MODULUS_LIMB_INDICES.len() * COMPACT_VSS_OUTPUT_COORDINATE_COUNT * 8
}

fn invalid_compact_vss_input(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

#[cfg(test)]
pub(in crate::bgv::setup) mod tests {
    use serde_json::json;

    use super::{
        COMPACT_VSS_COMMITMENT_BINARY_FORMAT, COMPACT_VSS_COMMITMENT_PROFILE_ID,
        COMPACT_VSS_OUTPUT_COORDINATE_COUNT, COMPACT_VSS_RANDOMNESS_COLUMN_COUNT,
        CompactVssCommitmentComputation, CompactVssCommitmentOpeningInput,
        compute_compact_vss_commitment_from_opening,
        compute_compact_vss_commitment_from_opening_request,
        decode_compact_vss_commitment_body_request, encode_compact_vss_commitment_body_request,
        verify_compact_vss_aggregate_threshold_commitment_set_request,
        verify_compact_vss_coefficient_commitment_set_request,
        verify_compact_vss_commitment_opening_request,
        verify_compact_vss_recipient_share_commitment_set_request,
        verify_compact_vss_share_linkage_statement_request,
    };
    use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

    #[test]
    fn compact_commitment_command_verifies_and_rejects_tampering() -> CanonicalResult<()> {
        let request = compact_opening_request();
        let response = compute_compact_vss_commitment_from_opening_request(&request)?;

        assert_eq!(
            response["operation"],
            "computeCompactVssCommitmentFromOpening"
        );
        assert_eq!(response["encodedCommitmentByteLength"], json!(384_u64));
        assert_eq!(
            response["commitment"]["commitmentLimbs"]
                .as_array()
                .expect("commitment limbs")
                .len(),
            3
        );
        assert_eq!(
            response["commitmentRoot"]
                .as_str()
                .expect("commitment root")
                .len(),
            128
        );

        let verification = verify_compact_vss_commitment_opening_request(&json!({
            "opening": request,
            "expectedCommitmentRoot": response["commitmentRoot"],
        }))?;
        assert_eq!(
            verification["operation"],
            "verifyCompactVssCommitmentOpening"
        );

        let mut tampered_opening = compact_opening_request();
        tampered_opening["messageCoefficients"][3] = json!(12_u64);
        assert!(
            verify_compact_vss_commitment_opening_request(&json!({
                "opening": tampered_opening,
                "expectedCommitmentRoot": response["commitmentRoot"],
            }))
            .is_err(),
            "tampered compact opening must reject"
        );

        let mut wrong_shape = compact_opening_request();
        wrong_shape["randomnessByColumn"][0] = json!([0, 1]);
        assert!(
            compute_compact_vss_commitment_from_opening_request(&wrong_shape).is_err(),
            "wrong compact randomness shape must reject"
        );

        Ok(())
    }

    #[test]
    fn compact_commitment_body_binary_codec_round_trips_and_rejects_malformed_bodies()
    -> CanonicalResult<()> {
        let request = compact_opening_request();
        let response = compute_compact_vss_commitment_from_opening_request(&request)?;
        let encoded = encode_compact_vss_commitment_body_request(&json!({
            "commitment": response["commitment"].clone(),
        }))?;
        let commitment_body_bytes_hex = encoded["commitmentBodyBytesHex"]
            .as_str()
            .expect("encoded commitment body hex")
            .to_string();

        assert_eq!(encoded["operation"], "encodeCompactVssCommitmentBody");
        assert_eq!(
            encoded["binaryFormat"],
            COMPACT_VSS_COMMITMENT_BINARY_FORMAT
        );
        assert_eq!(encoded["encodedCommitmentByteLength"], json!(384_u64));
        assert_eq!(commitment_body_bytes_hex.len(), 768);

        let metadata = compact_commitment_body_metadata(&response["commitment"])?;
        let decoded = decode_compact_vss_commitment_body_request(&json!({
            "metadata": metadata,
            "commitmentBodyBytesHex": commitment_body_bytes_hex,
        }))?;

        assert_eq!(decoded["operation"], "decodeCompactVssCommitmentBody");
        assert_eq!(decoded["commitment"], response["commitment"]);
        assert_eq!(decoded["commitmentRoot"], response["commitmentRoot"]);

        let metadata = compact_commitment_body_metadata(&response["commitment"])?;
        let short_body_hex = decoded["commitment"]
            .as_object()
            .and_then(|_| encoded["commitmentBodyBytesHex"].as_str())
            .expect("encoded commitment body hex");
        assert!(
            decode_compact_vss_commitment_body_request(&json!({
                "metadata": metadata,
                "commitmentBodyBytesHex": &short_body_hex[..short_body_hex.len() - 16],
            }))
            .is_err(),
            "short compact commitment body must reject"
        );

        let metadata = compact_commitment_body_metadata(&response["commitment"])?;
        let mut out_of_range_body = crate::transcript_core::decode_hex(
            encoded["commitmentBodyBytesHex"]
                .as_str()
                .expect("encoded commitment body hex"),
        )?;
        let first_modulus = response["commitment"]["commitmentLimbs"][0]["modulus"]
            .as_u64()
            .expect("first commitment modulus");
        out_of_range_body[..8].copy_from_slice(&first_modulus.to_le_bytes());
        assert!(
            decode_compact_vss_commitment_body_request(&json!({
                "metadata": metadata,
                "commitmentBodyBytesHex": crate::transcript_core::encode_hex(&out_of_range_body),
            }))
            .is_err(),
            "out-of-range compact commitment coordinate must reject"
        );

        let mut reordered_commitment = response["commitment"].clone();
        reordered_commitment["commitmentLimbs"]
            .as_array_mut()
            .expect("commitment limbs")
            .reverse();
        assert!(
            encode_compact_vss_commitment_body_request(&json!({
                "commitment": reordered_commitment,
            }))
            .is_err(),
            "non-canonical commitment limb order must reject"
        );

        Ok(())
    }

    #[test]
    fn compact_coefficient_commitment_set_command_verifies_bound_roots() -> CanonicalResult<()> {
        let coefficient_set = compact_coefficient_commitment_set()?;
        let verification = verify_compact_vss_coefficient_commitment_set_request(&json!({
            "command": "VerifyCompactVssCoefficientCommitmentSet",
            "coefficientCommitmentSet": coefficient_set,
        }))?;

        assert_eq!(
            verification["operation"],
            "verifyCompactVssCoefficientCommitmentSet"
        );
        assert_eq!(
            verification["coefficientCommitmentRoot"],
            coefficient_set["coefficientCommitmentRoot"]
        );
        assert_eq!(verification["participantCount"], json!(2_u64));
        assert_eq!(verification["rnsLimbCount"], json!(2_u64));
        assert_eq!(verification["thresholdDegree"], json!(2_u64));

        let mut tampered_set = coefficient_set;
        tampered_set["sourceTrusteeRecords"][1]["coefficientCommitments"][2]["coefficientCommitmentRoot"] =
            json!("0".repeat(128));
        assert!(
            verify_compact_vss_coefficient_commitment_set_request(&json!({
                "command": "VerifyCompactVssCoefficientCommitmentSet",
                "coefficientCommitmentSet": tampered_set,
            }))
            .is_err(),
            "tampered compact coefficient commitment root must reject"
        );

        Ok(())
    }

    #[test]
    fn compact_recipient_share_commitment_set_command_verifies_bound_roots() -> CanonicalResult<()>
    {
        let recipient_set = compact_recipient_share_commitment_set()?;
        let verification = verify_compact_vss_recipient_share_commitment_set_request(&json!({
            "command": "VerifyCompactVssRecipientShareCommitmentSet",
            "recipientShareCommitmentSet": recipient_set,
        }))?;

        assert_eq!(
            verification["operation"],
            "verifyCompactVssRecipientShareCommitmentSet"
        );
        assert_eq!(
            verification["recipientShareCommitmentRoot"],
            recipient_set["recipientShareCommitmentRoot"]
        );
        assert_eq!(verification["participantCount"], json!(2_u64));
        assert_eq!(verification["rnsLimbCount"], json!(2_u64));
        assert_eq!(verification["ringDegree"], json!(8_u64));

        let mut tampered_set = recipient_set;
        tampered_set["sourceTrusteeRecords"][0]["recipientShareCommitments"][1]["shareCommitmentRoot"] =
            json!("f".repeat(128));
        assert!(
            verify_compact_vss_recipient_share_commitment_set_request(&json!({
                "command": "VerifyCompactVssRecipientShareCommitmentSet",
                "recipientShareCommitmentSet": tampered_set,
            }))
            .is_err(),
            "tampered compact recipient-share commitment root must reject"
        );

        Ok(())
    }

    #[test]
    fn compact_aggregate_threshold_commitment_set_command_verifies_bound_roots()
    -> CanonicalResult<()> {
        let aggregate_set = compact_aggregate_threshold_commitment_set()?;
        let verification = verify_compact_vss_aggregate_threshold_commitment_set_request(&json!({
            "command": "VerifyCompactVssAggregateThresholdCommitmentSet",
            "aggregateThresholdCommitmentSet": aggregate_set,
        }))?;

        assert_eq!(
            verification["operation"],
            "verifyCompactVssAggregateThresholdCommitmentSet"
        );
        assert_eq!(
            verification["aggregateThresholdCommitmentRoot"],
            aggregate_set["aggregateThresholdCommitmentRoot"]
        );
        assert_eq!(verification["participantCount"], json!(2_u64));
        assert_eq!(verification["rnsLimbCount"], json!(2_u64));
        assert_eq!(verification["ringDegree"], json!(8_u64));

        let mut tampered_set = aggregate_set;
        tampered_set["recipientRecords"][0]["aggregateCommitmentRoot"] = json!("f".repeat(128));
        assert!(
            verify_compact_vss_aggregate_threshold_commitment_set_request(&json!({
                "command": "VerifyCompactVssAggregateThresholdCommitmentSet",
                "aggregateThresholdCommitmentSet": tampered_set,
            }))
            .is_err(),
            "tampered compact aggregate threshold commitment root must reject"
        );

        Ok(())
    }

    #[test]
    fn compact_share_linkage_statement_command_verifies_bound_roots() -> CanonicalResult<()> {
        let coefficient_set = compact_coefficient_commitment_set()?;
        let recipient_set = compact_recipient_share_commitment_set()?;
        let aggregate_set = compact_aggregate_threshold_commitment_set()?;
        let statement = compact_share_linkage_statement_from_evidence(
            &coefficient_set,
            &recipient_set,
            &aggregate_set,
        );
        let verification = verify_compact_vss_share_linkage_statement_request(&json!({
            "command": "VerifyCompactVssShareLinkageStatement",
            "statement": statement.clone(),
            "coefficientCommitmentSet": coefficient_set.clone(),
            "recipientShareCommitmentSet": recipient_set.clone(),
            "aggregateThresholdCommitmentSet": aggregate_set.clone(),
        }))?;

        assert_eq!(
            verification["operation"],
            "verifyCompactVssShareLinkageStatement"
        );
        assert_eq!(verification["statementRoot"], statement["statementRoot"]);
        assert_eq!(
            verification["aggregateThresholdCommitmentRoot"],
            statement["aggregateThresholdCommitmentRoot"]
        );
        assert_eq!(
            verification["proofBatchingRule"],
            "one public share-linkage statement record is bound per source trustee, batching every recipient and target-basis limb for that source"
        );

        let mut forged_source_statement = statement.clone();
        forged_source_statement["sourceStatementRecords"][0]["sourceRecipientShareCommitmentRoot"] =
            json!("0".repeat(128));
        rebind_compact_share_linkage_source_statement_root(
            &mut forged_source_statement["sourceStatementRecords"][0],
        )?;
        rebind_compact_share_linkage_statement_root(&mut forged_source_statement)?;
        assert!(
            verify_compact_vss_share_linkage_statement_request(&json!({
                "command": "VerifyCompactVssShareLinkageStatement",
                "statement": forged_source_statement.clone(),
            }))
            .is_ok(),
            "statement-only linkage verification remains a root-binding check"
        );
        assert!(
            verify_compact_vss_share_linkage_statement_request(&json!({
                "command": "VerifyCompactVssShareLinkageStatement",
                "statement": forged_source_statement,
                "coefficientCommitmentSet": coefficient_set.clone(),
                "recipientShareCommitmentSet": recipient_set.clone(),
                "aggregateThresholdCommitmentSet": aggregate_set.clone(),
            }))
            .is_err(),
            "evidence-backed linkage verification must reject a source root absent from the recipient-share set"
        );

        let mut mismatched_aggregate_set = aggregate_set.clone();
        tamper_compact_aggregate_commitment_body(&mut mismatched_aggregate_set)?;
        assert!(
            verify_compact_vss_aggregate_threshold_commitment_set_request(&json!({
                "command": "VerifyCompactVssAggregateThresholdCommitmentSet",
                "aggregateThresholdCommitmentSet": mismatched_aggregate_set.clone(),
            }))
            .is_ok(),
            "aggregate set verification only checks aggregate body canonical roots"
        );
        let mismatched_statement = compact_share_linkage_statement_from_evidence(
            &coefficient_set,
            &recipient_set,
            &mismatched_aggregate_set,
        );
        let mismatch_error = verify_compact_vss_share_linkage_statement_request(&json!({
            "command": "VerifyCompactVssShareLinkageStatement",
            "statement": mismatched_statement,
            "coefficientCommitmentSet": coefficient_set,
            "recipientShareCommitmentSet": recipient_set,
            "aggregateThresholdCommitmentSet": mismatched_aggregate_set,
        }))
        .expect_err("evidence-backed linkage verification must reject a non-sum aggregate body");
        assert!(
            mismatch_error.to_string().contains("public sum"),
            "aggregate body mismatch should be reported as a public-sum failure: {mismatch_error}"
        );

        let mut tampered_statement = statement;
        tampered_statement["aggregateThresholdCommitmentRoot"] = json!("8".repeat(128));
        assert!(
            verify_compact_vss_share_linkage_statement_request(&json!({
                "command": "VerifyCompactVssShareLinkageStatement",
                "statement": tampered_statement,
            }))
            .is_err(),
            "tampered share-linkage statement root must reject"
        );

        Ok(())
    }

    fn compact_opening_request() -> serde_json::Value {
        json!({
            "command": "ComputeCompactVssCommitmentFromOpening",
            "commitmentRole": "aggregate-threshold-share",
            "commitmentContext": {
                "objectType": "CompactVssAggregateThresholdShareCommitmentContext",
                "objectVersion": 1,
                "ceremonyId": "compact-vss-test",
                "manifestHash": "1".repeat(128),
                "rosterHash": "2".repeat(128),
                "setupProfileHash": "3".repeat(128),
                "qShareHash": "4".repeat(128),
                "carryAwareVssShareRelationProfileHash": "5".repeat(128),
                "commitmentProfileHash": "6".repeat(128),
                "setupEpoch": "setup-epoch",
                "recipientIdentity": "trustee-1",
                "recipientRosterPosition": 0,
                "rnsLimbIndex": 0,
                "rnsPrime": 97,
            },
            "publicMatrixSeedHash": "7".repeat(128),
            "rnsLimbIndex": 0,
            "rnsPrime": 97,
            "ringDegree": 8,
            "messageCoefficients": [1, 2, 3, 4, 5, 6, 7, 8],
            "randomnessByColumn": [
                [0, 1, -1, 2, -2, 3, -3, 4],
                [5, -5, 6, -6, 7, -7, 8, -8]
            ],
        })
    }

    fn compact_commitment_body_metadata(
        commitment: &serde_json::Value,
    ) -> CanonicalResult<serde_json::Value> {
        Ok(json!({
            "commitmentRole": commitment["commitmentRole"].clone(),
            "commitmentContextHash": commitment["commitmentContextHash"].clone(),
            "publicMatrixSeedHash": commitment["publicMatrixSeedHash"].clone(),
            "rnsLimbIndex": commitment["rnsLimbIndex"].clone(),
            "rnsPrime": commitment["rnsPrime"].clone(),
            "ringDegree": commitment["ringDegree"].clone(),
        }))
    }

    pub(in crate::bgv::setup) fn compact_coefficient_commitment_set()
    -> CanonicalResult<serde_json::Value> {
        let mut source_trustee_records = Vec::new();
        for source_trustee_roster_position in 0..2_usize {
            source_trustee_records.push(compact_source_coefficient_record(
                source_trustee_roster_position,
            )?);
        }
        let set_without_root = json!({
            "objectType": "CompactVssCoefficientCommitmentSet",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "profileId": "sealed-lattice-compact-vss-sparse-linear-v1",
            "publicMatrixSeedHash": "7".repeat(128),
            "participantCount": 2,
            "rnsLimbCount": 2,
            "thresholdDegree": 2,
            "ringDegree": 8,
            "sourceTrusteeRecords": source_trustee_records,
        });
        let mut coefficient_set = set_without_root;
        coefficient_set["coefficientCommitmentRoot"] = json!(
            crate::hashing::derive_protocol_hash("VssCoefficientCommitmentRoot", &coefficient_set)
                .expect("compact coefficient set root")
        );

        Ok(coefficient_set)
    }

    fn compact_source_coefficient_record(
        source_trustee_roster_position: usize,
    ) -> CanonicalResult<serde_json::Value> {
        let mut coefficient_commitments = Vec::new();
        for rns_limb_index in 0..compact_test_rns_limb_count() {
            let rns_prime = compact_test_rns_prime(rns_limb_index);
            for shamir_coefficient_index in 0..compact_test_threshold_degree() {
                let computation = compact_test_commitment(
                    "coefficient",
                    rns_limb_index,
                    rns_prime,
                    &[
                        source_trustee_roster_position,
                        rns_limb_index,
                        shamir_coefficient_index,
                        0,
                    ],
                )?;
                coefficient_commitments.push(json!({
                    "objectType": "CompactVssCoefficientCommitment",
                    "objectVersion": 1,
                    "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
                    "sourceTrusteeIdentity": format!("source-{source_trustee_roster_position}"),
                    "sourceTrusteeRosterPosition": source_trustee_roster_position,
                    "publicMatrixSeedHash": "7".repeat(128),
                    "rnsLimbIndex": rns_limb_index,
                    "rnsPrime": rns_prime,
                    "shamirCoefficientIndex": shamir_coefficient_index,
                    "coefficientCommitmentRoot": computation.commitment_root,
                    "coefficientOpeningRoot": computation.opening_root,
                    "commitment": computation.commitment,
                }));
            }
        }
        let source_without_root = json!({
            "objectType": "CompactVssSourceCoefficientCommitments",
            "objectVersion": 1,
            "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
            "sourceTrusteeIdentity": format!("source-{source_trustee_roster_position}"),
            "sourceTrusteeRosterPosition": source_trustee_roster_position,
            "publicMatrixSeedHash": "7".repeat(128),
            "coefficientCommitments": coefficient_commitments,
        });
        let mut source_record = source_without_root;
        source_record["sourceCoefficientCommitmentRoot"] = json!(
            crate::hashing::derive_protocol_hash("VssCoefficientCommitmentRoot", &source_record)
                .expect("compact source coefficient root")
        );

        Ok(source_record)
    }

    fn compact_test_participant_count() -> usize {
        2
    }

    fn compact_test_rns_limb_count() -> usize {
        2
    }

    fn compact_test_threshold_degree() -> usize {
        2
    }

    fn compact_test_ring_degree() -> usize {
        8
    }

    fn compact_test_public_matrix_seed_hash() -> String {
        "7".repeat(128)
    }

    fn compact_test_rns_prime(rns_limb_index: usize) -> u64 {
        if rns_limb_index == 0 { 97 } else { 193 }
    }

    fn compact_test_seed(seed_parts: &[usize]) -> usize {
        seed_parts
            .iter()
            .fold(0_usize, |seed, seed_part| seed * 31 + seed_part + 1)
    }

    fn compact_test_hash_from_seed(seed: usize, domain_offset: usize) -> String {
        let digit = (seed + domain_offset) % 16;
        format!("{digit:x}").repeat(128)
    }

    fn compact_test_message_coefficients(seed: usize, modulus: u64) -> Vec<u64> {
        (0..compact_test_ring_degree())
            .map(|coefficient_index| {
                ((seed as u64)
                    .wrapping_mul(17)
                    .wrapping_add((coefficient_index as u64 + 1) * 19))
                    % modulus
            })
            .collect()
    }

    fn compact_test_randomness_by_column(seed: usize) -> Vec<Vec<i64>> {
        (0..COMPACT_VSS_RANDOMNESS_COLUMN_COUNT)
            .map(|column_index| {
                (0..compact_test_ring_degree())
                    .map(|coefficient_index| {
                        let magnitude =
                            ((seed + column_index * 11 + coefficient_index * 7) % 29) as i64;
                        if (seed + column_index + coefficient_index).is_multiple_of(2) {
                            magnitude
                        } else {
                            -magnitude
                        }
                    })
                    .collect()
            })
            .collect()
    }

    fn compact_test_commitment(
        commitment_role: &str,
        rns_limb_index: usize,
        rns_prime: u64,
        seed_parts: &[usize],
    ) -> CanonicalResult<CompactVssCommitmentComputation> {
        let seed = compact_test_seed(seed_parts);
        let commitment_context = json!({
            "objectType": "CompactVssTestCommitmentContext",
            "objectVersion": 1,
            "commitmentRole": commitment_role,
            "seedHash": compact_test_hash_from_seed(seed, 9),
        });
        let public_matrix_seed_hash = compact_test_public_matrix_seed_hash();
        let message_coefficients = compact_test_message_coefficients(seed, rns_prime);
        let randomness_by_column = compact_test_randomness_by_column(seed);
        let computation =
            compute_compact_vss_commitment_from_opening(CompactVssCommitmentOpeningInput {
                commitment_role,
                commitment_context: &commitment_context,
                public_matrix_seed_hash: &public_matrix_seed_hash,
                rns_limb_index,
                rns_prime,
                ring_degree: compact_test_ring_degree(),
                message_coefficients: &message_coefficients,
                message_coefficient_bound: rns_prime,
                randomness_by_column: &randomness_by_column,
            })?;

        Ok(computation)
    }

    pub(in crate::bgv::setup) fn compact_recipient_share_commitment_set()
    -> CanonicalResult<serde_json::Value> {
        let mut source_trustee_records = Vec::new();
        for source_trustee_roster_position in 0..compact_test_participant_count() {
            source_trustee_records.push(compact_source_recipient_share_record(
                source_trustee_roster_position,
            )?);
        }
        let set_without_root = json!({
            "objectType": "CompactVssRecipientShareCommitmentSet",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
            "publicMatrixSeedHash": compact_test_public_matrix_seed_hash(),
            "participantCount": compact_test_participant_count(),
            "rnsLimbCount": compact_test_rns_limb_count(),
            "ringDegree": compact_test_ring_degree(),
            "sourceTrusteeRecords": source_trustee_records,
        });
        let mut recipient_set = set_without_root;
        recipient_set["recipientShareCommitmentRoot"] = json!(
            crate::hashing::derive_protocol_hash("ThresholdShareCommitmentRoot", &recipient_set)
                .expect("compact recipient-share set root")
        );

        Ok(recipient_set)
    }

    fn compact_source_recipient_share_record(
        source_trustee_roster_position: usize,
    ) -> CanonicalResult<serde_json::Value> {
        let mut recipient_share_commitments = Vec::new();
        for recipient_roster_position in 0..compact_test_participant_count() {
            for rns_limb_index in 0..compact_test_rns_limb_count() {
                recipient_share_commitments.push(compact_recipient_share_commitment_record(
                    source_trustee_roster_position,
                    recipient_roster_position,
                    rns_limb_index,
                )?);
            }
        }
        let source_without_root = json!({
            "objectType": "CompactVssSourceRecipientShareCommitments",
            "objectVersion": 1,
            "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
            "sourceTrusteeIdentity": format!("source-{source_trustee_roster_position}"),
            "sourceTrusteeRosterPosition": source_trustee_roster_position,
            "recipientShareCommitments": recipient_share_commitments,
        });
        let mut source_record = source_without_root;
        source_record["sourceRecipientShareCommitmentRoot"] = json!(
            crate::hashing::derive_protocol_hash("ThresholdShareCommitmentRoot", &source_record)
                .expect("compact source recipient-share root")
        );

        Ok(source_record)
    }

    fn compact_recipient_share_commitment_record(
        source_trustee_roster_position: usize,
        recipient_roster_position: usize,
        rns_limb_index: usize,
    ) -> CanonicalResult<serde_json::Value> {
        let rns_prime = compact_test_rns_prime(rns_limb_index);
        let computation = compact_test_commitment(
            "recipient-share",
            rns_limb_index,
            rns_prime,
            &[
                source_trustee_roster_position,
                recipient_roster_position,
                rns_limb_index,
                1,
            ],
        )?;
        Ok(json!({
            "objectType": "CompactVssRecipientShareCommitment",
            "objectVersion": 1,
            "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
            "sourceTrusteeIdentity": format!("source-{source_trustee_roster_position}"),
            "sourceTrusteeRosterPosition": source_trustee_roster_position,
            "recipientIdentity": format!("recipient-{recipient_roster_position}"),
            "recipientRosterPosition": recipient_roster_position,
            "recipientTrusteePoint": recipient_roster_position + 1,
            "rnsLimbIndex": rns_limb_index,
            "rnsPrime": rns_prime,
            "shareCommitmentRoot": computation.commitment_root,
            "shareOpeningRoot": computation.opening_root,
            "commitment": computation.commitment,
        }))
    }

    fn compact_aggregate_threshold_commitment_set() -> CanonicalResult<serde_json::Value> {
        let recipient_set = compact_recipient_share_commitment_set()?;
        compact_aggregate_threshold_commitment_set_from_recipient_set(&recipient_set)
    }

    pub(in crate::bgv::setup) fn compact_aggregate_threshold_commitment_set_from_recipient_set(
        recipient_set: &serde_json::Value,
    ) -> CanonicalResult<serde_json::Value> {
        let mut recipient_records = Vec::new();
        for recipient_roster_position in 0..compact_test_participant_count() {
            for rns_limb_index in 0..compact_test_rns_limb_count() {
                recipient_records.push(compact_aggregate_threshold_commitment_record(
                    recipient_set,
                    recipient_roster_position,
                    rns_limb_index,
                )?);
            }
        }
        let set_without_root = json!({
            "objectType": "CompactVssAggregateThresholdCommitmentSet",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
            "publicMatrixSeedHash": compact_test_public_matrix_seed_hash(),
            "participantCount": compact_test_participant_count(),
            "rnsLimbCount": compact_test_rns_limb_count(),
            "ringDegree": compact_test_ring_degree(),
            "recipientRecords": recipient_records,
        });
        let mut aggregate_set = set_without_root;
        aggregate_set["aggregateThresholdCommitmentRoot"] = json!(
            crate::hashing::derive_protocol_hash("ThresholdShareCommitmentRoot", &aggregate_set)
                .expect("compact aggregate threshold set root")
        );

        Ok(aggregate_set)
    }

    fn compact_aggregate_threshold_commitment_record(
        recipient_set: &serde_json::Value,
        recipient_roster_position: usize,
        rns_limb_index: usize,
    ) -> CanonicalResult<serde_json::Value> {
        let source_share_records = compact_source_share_records_for_recipient(
            recipient_set,
            recipient_roster_position,
            rns_limb_index,
        )?;
        let rns_prime = compact_test_rns_prime(rns_limb_index);
        let commitment = compact_aggregate_commitment_body(
            recipient_roster_position,
            rns_limb_index,
            rns_prime,
            &source_share_records,
        )?;
        let source_share_commitment_roots = source_share_records
            .iter()
            .map(|source_share_record| source_share_record["shareCommitmentRoot"].clone())
            .collect::<Vec<_>>();
        let source_share_opening_roots = source_share_records
            .iter()
            .map(|source_share_record| source_share_record["shareOpeningRoot"].clone())
            .collect::<Vec<_>>();
        let seed = compact_test_seed(&[recipient_roster_position, rns_limb_index, 5]);

        Ok(json!({
            "objectType": "CompactVssAggregateThresholdCommitment",
            "objectVersion": 1,
            "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
            "recipientIdentity": format!("recipient-{recipient_roster_position}"),
            "recipientRosterPosition": recipient_roster_position,
            "recipientTrusteePoint": recipient_roster_position + 1,
            "rnsLimbIndex": rns_limb_index,
            "rnsPrime": rns_prime,
            "aggregateCommitmentRoot": crate::hashing::derive_protocol_hash(
                "SetupCommitmentRoot",
                &commitment,
            )?,
            "aggregateOpeningRoot": compact_test_hash_from_seed(seed, 0),
            "commitment": commitment,
            "sourceShareCommitmentRoots": source_share_commitment_roots,
            "sourceShareOpeningRoots": source_share_opening_roots,
        }))
    }

    fn compact_source_share_records_for_recipient(
        recipient_set: &serde_json::Value,
        recipient_roster_position: usize,
        rns_limb_index: usize,
    ) -> CanonicalResult<Vec<serde_json::Value>> {
        let recipient_share_record_index = recipient_roster_position
            .checked_mul(compact_test_rns_limb_count())
            .and_then(|offset| offset.checked_add(rns_limb_index))
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "compact VSS fixture recipient-share index overflowed",
                )
            })?;
        let source_records = recipient_set["sourceTrusteeRecords"]
            .as_array()
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "compact VSS fixture recipient source records must be an array",
                )
            })?;
        source_records
            .iter()
            .map(|source_record| {
                let recipient_share_records = source_record["recipientShareCommitments"]
                    .as_array()
                    .ok_or_else(|| {
                        CanonicalError::new(
                            CanonicalErrorCode::InvalidFixture,
                            "compact VSS fixture recipient-share records must be an array",
                        )
                    })?;
                recipient_share_records
                    .get(recipient_share_record_index)
                    .cloned()
                    .ok_or_else(|| {
                        CanonicalError::new(
                            CanonicalErrorCode::MalformedLength,
                            "compact VSS fixture recipient-share record is missing",
                        )
                    })
            })
            .collect()
    }

    fn compact_aggregate_commitment_body(
        recipient_roster_position: usize,
        rns_limb_index: usize,
        rns_prime: u64,
        source_share_records: &[serde_json::Value],
    ) -> CanonicalResult<serde_json::Value> {
        let first_source_share_record = source_share_records.first().ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "compact VSS fixture aggregate body must have source share records",
            )
        })?;
        let first_commitment_limbs = first_source_share_record["commitment"]["commitmentLimbs"]
            .as_array()
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "compact VSS fixture commitment limbs must be an array",
                )
            })?;
        let mut commitment_limbs = Vec::new();
        for (commitment_limb_position, first_limb) in first_commitment_limbs.iter().enumerate() {
            let commitment_modulus_index = first_limb["commitmentModulusIndex"]
                .as_u64()
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "compact VSS fixture commitment modulus index must be an unsigned integer",
                    )
                })?;
            let modulus = first_limb["modulus"].as_u64().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "compact VSS fixture commitment modulus must be an unsigned integer",
                )
            })?;
            let mut summed_coordinates = Vec::new();
            for coordinate_index in 0..COMPACT_VSS_OUTPUT_COORDINATE_COUNT {
                let mut summed_coordinate = 0_u128;
                for source_share_record in source_share_records {
                    let source_limb = source_share_record["commitment"]["commitmentLimbs"]
                        .as_array()
                        .and_then(|limbs| limbs.get(commitment_limb_position))
                        .ok_or_else(|| {
                            CanonicalError::new(
                                CanonicalErrorCode::MalformedLength,
                                "compact VSS fixture source commitment limb is missing",
                            )
                        })?;
                    let coordinate = source_limb["coordinates"]
                        .as_array()
                        .and_then(|coordinates| coordinates.get(coordinate_index))
                        .and_then(serde_json::Value::as_u64)
                        .ok_or_else(|| {
                            CanonicalError::new(
                                CanonicalErrorCode::InvalidFixture,
                                "compact VSS fixture source commitment coordinate must be an unsigned integer",
                            )
                        })?;
                    summed_coordinate =
                        (summed_coordinate + u128::from(coordinate)) % u128::from(modulus);
                }
                summed_coordinates.push(summed_coordinate as u64);
            }
            commitment_limbs.push(json!({
                "commitmentModulusIndex": commitment_modulus_index,
                "modulus": modulus,
                "coordinates": summed_coordinates,
            }));
        }

        let seed = compact_test_seed(&[recipient_roster_position, rns_limb_index, 4]);
        Ok(json!({
            "objectType": "CompactVssCommitment",
            "objectVersion": 1,
            "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
            "commitmentRole": "aggregate-threshold-share",
            "commitmentContextHash": compact_test_hash_from_seed(seed, 0),
            "publicMatrixSeedHash": compact_test_public_matrix_seed_hash(),
            "rnsLimbIndex": rns_limb_index,
            "rnsPrime": rns_prime,
            "ringDegree": compact_test_ring_degree(),
            "outputCoordinateCount": COMPACT_VSS_OUTPUT_COORDINATE_COUNT,
            "randomnessColumnCount": COMPACT_VSS_RANDOMNESS_COLUMN_COUNT,
            "commitmentLimbs": commitment_limbs,
        }))
    }

    pub(in crate::bgv::setup) fn compact_share_linkage_statement_from_evidence(
        coefficient_set: &serde_json::Value,
        recipient_set: &serde_json::Value,
        aggregate_set: &serde_json::Value,
    ) -> serde_json::Value {
        let target_basis_hash =
            crate::bgv::evaluator::top_k::canonical_target_basis_hash().expect("target basis hash");
        let source_statement_records = (0..2_usize)
            .map(|source_trustee_roster_position| {
                let coefficient_source_record =
                    &coefficient_set["sourceTrusteeRecords"][source_trustee_roster_position];
                let recipient_source_record =
                    &recipient_set["sourceTrusteeRecords"][source_trustee_roster_position];
                let coefficient_opening_roots = coefficient_source_record["coefficientCommitments"]
                    .as_array()
                    .expect("coefficient records")
                    .iter()
                    .map(|coefficient_record| {
                        coefficient_record["coefficientOpeningRoot"].clone()
                    })
                    .collect::<Vec<_>>();
                let recipient_share_opening_roots = recipient_source_record
                    ["recipientShareCommitments"]
                    .as_array()
                    .expect("recipient-share records")
                    .iter()
                    .map(|recipient_share_record| {
                        recipient_share_record["shareOpeningRoot"].clone()
                    })
                    .collect::<Vec<_>>();
                let source_statement_without_root = json!({
                    "objectType": "CompactVssShareLinkageSourceStatement",
                    "objectVersion": 1,
                    "setupProfileId": "CollectiveBgvSetup-v1",
                    "profileId": "sealed-lattice-compact-vss-sparse-linear-v1",
                    "ceremonyId": "compact-vss-test",
                    "manifestHash": "1".repeat(128),
                    "rosterHash": "2".repeat(128),
                    "setupProfileHash": "3".repeat(128),
                    "qShareHash": "4".repeat(128),
                    "carryAwareVssShareRelationProfileHash": "5".repeat(128),
                    "commitmentProfileHash": "6".repeat(128),
                    "setupEpoch": "setup-epoch",
                    "publicMatrixSeedHash": "7".repeat(128),
                    "targetBasisHash": target_basis_hash.clone(),
                    "sourceTrusteeIdentity": format!("source-{source_trustee_roster_position}"),
                    "sourceTrusteeRosterPosition": source_trustee_roster_position,
                    "participantCount": 2,
                    "targetRnsLimbCount": 2,
                    "thresholdDegree": 2,
                    "coefficientCommitmentRoot": coefficient_set["coefficientCommitmentRoot"].clone(),
                    "sourceCoefficientCommitmentRoot": coefficient_source_record["sourceCoefficientCommitmentRoot"].clone(),
                    "sourceRecipientShareCommitmentRoot": recipient_source_record["sourceRecipientShareCommitmentRoot"].clone(),
                    "coefficientOpeningRoots": coefficient_opening_roots,
                    "recipientShareOpeningRoots": recipient_share_opening_roots,
                    "aggregateThresholdCommitmentRoot": aggregate_set["aggregateThresholdCommitmentRoot"].clone(),
                    "relation": "recipient share commitments open to Shamir evaluations of the coefficient commitments, and aggregate threshold commitments are the public sum of recipient share commitments",
                    "proofBatchingRule": "one public share-linkage statement record is bound per source trustee, batching every recipient and target-basis limb for that source",
                    "shamirEvaluationRule": "recipient-share commitments must open to the Shamir evaluation of the source trustee coefficient commitments at the recipient trustee point",
                    "aggregateThresholdRule": "aggregate threshold commitments must be the public sum of source-to-recipient share commitments for the same recipient and target-basis limb",
                    "commonKeyRule": "coefficient, recipient-share, and aggregate threshold compact commitments must use the same public matrix seed hash and compact commitment profile",
                });
                let mut source_statement = source_statement_without_root;
                source_statement["sourceStatementRoot"] = json!(
                    crate::hashing::derive_protocol_hash(
                        "SetupProofRecordBindingHash",
                        &source_statement,
                    )
                    .expect("source statement root")
                );
                source_statement
            })
            .collect::<Vec<_>>();
        let statement_without_root = json!({
            "objectType": "CompactVssShareLinkageStatement",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "profileId": "sealed-lattice-compact-vss-sparse-linear-v1",
            "ceremonyId": "compact-vss-test",
            "manifestHash": "1".repeat(128),
            "rosterHash": "2".repeat(128),
            "setupProfileHash": "3".repeat(128),
            "qShareHash": "4".repeat(128),
            "carryAwareVssShareRelationProfileHash": "5".repeat(128),
            "commitmentProfileHash": "6".repeat(128),
            "setupEpoch": "setup-epoch",
            "publicMatrixSeedHash": "7".repeat(128),
            "targetBasisHash": target_basis_hash,
            "participantCount": 2,
            "targetRnsLimbCount": 2,
            "thresholdDegree": 2,
            "coefficientCommitmentRoot": coefficient_set["coefficientCommitmentRoot"].clone(),
            "recipientShareCommitmentRoot": recipient_set["recipientShareCommitmentRoot"].clone(),
            "aggregateThresholdCommitmentRoot": aggregate_set["aggregateThresholdCommitmentRoot"].clone(),
            "relation": "recipient share commitments open to Shamir evaluations of the coefficient commitments, and aggregate threshold commitments are the public sum of recipient share commitments",
            "proofBatchingRule": "one public share-linkage statement record is bound per source trustee, batching every recipient and target-basis limb for that source",
            "shamirEvaluationRule": "recipient-share commitments must open to the Shamir evaluation of the source trustee coefficient commitments at the recipient trustee point",
            "aggregateThresholdRule": "aggregate threshold commitments must be the public sum of source-to-recipient share commitments for the same recipient and target-basis limb",
            "commonKeyRule": "coefficient, recipient-share, and aggregate threshold compact commitments must use the same public matrix seed hash and compact commitment profile",
            "sourceStatementRecords": source_statement_records,
        });

        let mut statement = statement_without_root;
        statement["statementRoot"] = json!(
            crate::hashing::derive_protocol_hash("SetupProofRecordBindingHash", &statement)
                .expect("statement root")
        );
        statement
    }

    fn rebind_compact_share_linkage_source_statement_root(
        source_statement: &mut serde_json::Value,
    ) -> CanonicalResult<()> {
        let mut source_statement_without_root = source_statement
            .as_object()
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "compact VSS share linkage source statement must be an object",
                )
            })?
            .clone();
        source_statement_without_root.remove("sourceStatementRoot");
        source_statement["sourceStatementRoot"] = json!(crate::hashing::derive_protocol_hash(
            "SetupProofRecordBindingHash",
            &serde_json::Value::Object(source_statement_without_root),
        )?);

        Ok(())
    }

    fn rebind_compact_share_linkage_statement_root(
        statement: &mut serde_json::Value,
    ) -> CanonicalResult<()> {
        let mut statement_without_root = statement
            .as_object()
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "compact VSS share linkage statement must be an object",
                )
            })?
            .clone();
        statement_without_root.remove("statementRoot");
        statement["statementRoot"] = json!(crate::hashing::derive_protocol_hash(
            "SetupProofRecordBindingHash",
            &serde_json::Value::Object(statement_without_root),
        )?);

        Ok(())
    }

    fn tamper_compact_aggregate_commitment_body(
        aggregate_set: &mut serde_json::Value,
    ) -> CanonicalResult<()> {
        let aggregate_record = &mut aggregate_set["recipientRecords"][0];
        let modulus = aggregate_record["commitment"]["commitmentLimbs"][0]["modulus"]
            .as_u64()
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "compact VSS fixture aggregate modulus must be an unsigned integer",
                )
            })?;
        let coordinate = aggregate_record["commitment"]["commitmentLimbs"][0]["coordinates"][0]
            .as_u64()
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "compact VSS fixture aggregate coordinate must be an unsigned integer",
                )
            })?;
        aggregate_record["commitment"]["commitmentLimbs"][0]["coordinates"][0] =
            json!((coordinate + 1) % modulus);
        aggregate_record["aggregateCommitmentRoot"] = json!(crate::hashing::derive_protocol_hash(
            "SetupCommitmentRoot",
            &aggregate_record["commitment"],
        )?);
        rebind_compact_aggregate_threshold_commitment_set_root(aggregate_set)
    }

    fn rebind_compact_aggregate_threshold_commitment_set_root(
        aggregate_set: &mut serde_json::Value,
    ) -> CanonicalResult<()> {
        let mut aggregate_set_without_root = aggregate_set
            .as_object()
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "compact VSS aggregate threshold commitment set must be an object",
                )
            })?
            .clone();
        aggregate_set_without_root.remove("aggregateThresholdCommitmentRoot");
        aggregate_set["aggregateThresholdCommitmentRoot"] =
            json!(crate::hashing::derive_protocol_hash(
                "ThresholdShareCommitmentRoot",
                &serde_json::Value::Object(aggregate_set_without_root),
            )?);

        Ok(())
    }
}
