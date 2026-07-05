use super::*;
use crate::bgv::setup_helpers::compare_required_string;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

pub(super) const VSS_PUBLIC_COMMITMENT_BINARY_FORMAT: &str =
    "sealed-lattice-vss-public-commitment-binary-v1";
pub(crate) const VSS_PUBLIC_OUTPUT_COORDINATE_COUNT: usize = 16;
pub(crate) const VSS_PUBLIC_MESSAGE_DIGIT_COUNT: usize = 2;
#[cfg(test)]
pub(crate) const VSS_PUBLIC_MESSAGE_BASE_DIGIT_TRIT_COUNT: usize = 17;
pub(crate) const VSS_PUBLIC_MESSAGE_DIGIT_BASE: u64 = 129_140_163;
pub(crate) const VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT: usize = 2;
pub(in crate::bgv::setup) const VSS_PUBLIC_RANDOMNESS_PROJECTION_WEIGHT: usize = 32;
const VSS_PUBLIC_COMMITMENT_MODULUS_LIMB_INDICES: [usize; 3] = [0, 1, 2];
const VSS_PUBLIC_SAMPLER_DOMAIN: &str = "sealed-lattice-vss-public-commitment/sampler-v1";
const VSS_PUBLIC_MATRIX_RESIDUE_HASH_DOMAIN: &str =
    "sealed-lattice-vss-public-commitment/matrix-residue-v1";
const VSS_PUBLIC_PROJECTION_INDEX_HASH_DOMAIN: &str =
    "sealed-lattice-vss-public-commitment/projection-index-v1";
const VSS_PUBLIC_OPENING_PAYLOAD_HASH_DOMAIN: &str =
    "sealed-lattice-vss-public-commitment/opening-payload-v2";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::setup) struct VssPublicMessageEncodingLayout {
    low_digit_trit_count: usize,
    high_digit_trit_count: usize,
}

impl VssPublicMessageEncodingLayout {
    pub(in crate::bgv::setup) fn digit_trit_count(
        self,
        digit_index: usize,
    ) -> CanonicalResult<usize> {
        match digit_index {
            0 => Ok(self.low_digit_trit_count),
            1 => Ok(self.high_digit_trit_count),
            _ => Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "compact VSS message digit index is outside the selected profile",
            )),
        }
    }

    pub(in crate::bgv::setup) fn total_trit_count(self) -> usize {
        self.low_digit_trit_count + self.high_digit_trit_count
    }

    pub(in crate::bgv::setup) fn encoding_column_count(self) -> usize {
        VSS_PUBLIC_MESSAGE_DIGIT_COUNT + self.total_trit_count()
    }

    pub(in crate::bgv::setup) fn digit_encoding_column(
        self,
        digit_index: usize,
    ) -> CanonicalResult<usize> {
        if digit_index < VSS_PUBLIC_MESSAGE_DIGIT_COUNT {
            Ok(digit_index)
        } else {
            Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "compact VSS message digit index is outside the selected profile",
            ))
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

        let previous_trit_count =
            (0..digit_index).try_fold(0_usize, |sum, previous_digit_index| {
                sum.checked_add(self.digit_trit_count(previous_digit_index)?)
                    .ok_or_else(|| {
                        CanonicalError::new(
                            CanonicalErrorCode::MalformedLength,
                            "compact VSS message trit column offset overflowed",
                        )
                    })
            })?;

        Ok(VSS_PUBLIC_MESSAGE_DIGIT_COUNT + previous_trit_count + trit_index)
    }
}

pub(crate) struct VssPublicCommitmentOpeningInput<'a> {
    pub(crate) commitment_role: &'a str,
    pub(crate) commitment_context: &'a Value,
    pub(crate) public_matrix_seed_hash: &'a str,
    pub(crate) rns_limb_index: usize,
    pub(crate) rns_prime: u64,
    pub(crate) ring_degree: usize,
    pub(crate) message_coefficients: &'a [u64],
    pub(crate) message_digit_columns: &'a [Vec<u64>],
    pub(crate) message_coefficient_bound: u64,
    pub(crate) randomness_by_column: &'a [Vec<i64>],
}

pub(crate) struct VssPublicCommitmentComputation {
    pub(crate) commitment: Value,
    pub(crate) commitment_root: String,
    pub(crate) commitment_context_hash: String,
    pub(crate) opening_root: String,
}

pub(crate) fn compute_vss_public_commitment_from_opening(
    input: VssPublicCommitmentOpeningInput<'_>,
) -> CanonicalResult<VssPublicCommitmentComputation> {
    validate_hash_string(input.public_matrix_seed_hash, "publicMatrixSeedHash")?;
    validate_vss_public_commitment_role(input.commitment_role)?;
    if input.rns_prime == 0 {
        return Err(invalid_vss_public_input("rnsPrime must be positive"));
    }
    if input.ring_degree == 0 {
        return Err(invalid_vss_public_input("ringDegree must be positive"));
    }
    if input.message_coefficient_bound == 0 {
        return Err(invalid_vss_public_input(
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
    }
    let message_digit_columns = vss_public_message_digit_columns_for_opening(
        input.message_coefficients,
        input.message_digit_columns,
        input.message_coefficient_bound,
        input.ring_degree,
    )?;
    validate_vss_public_randomness_columns(
        input.randomness_by_column,
        input.ring_degree,
        None,
        "randomnessByColumn",
    )?;

    let commitment_context_hash = derive_canonical_object_hash(&json!({
        "objectType": "VssPublicCommitmentContext",
        "objectVersion": 1,
        "commitmentRole": input.commitment_role,
        "commitmentContext": input.commitment_context,
    }))?;
    let commitment_limbs = VSS_PUBLIC_COMMITMENT_MODULUS_LIMB_INDICES
        .iter()
        .map(|commitment_modulus_index| {
            let modulus = DATA_PRIMES[*commitment_modulus_index];
            let coordinates = (0..VSS_PUBLIC_OUTPUT_COORDINATE_COUNT)
                .map(|output_coordinate_index| {
                    commitment_coordinate(CommitmentCoordinateInput {
                        public_matrix_seed_hash: input.public_matrix_seed_hash,
                        rns_limb_index: input.rns_limb_index,
                        commitment_modulus_index: *commitment_modulus_index,
                        output_coordinate_index,
                        modulus,
                        message_digit_columns: &message_digit_columns,
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
        "objectType": "VssPublicCommitment",
        "objectVersion": 1,
        "commitmentRole": input.commitment_role,
        "commitmentContextHash": commitment_context_hash,
        "publicMatrixSeedHash": input.public_matrix_seed_hash,
        "rnsLimbIndex": input.rns_limb_index,
        "rnsPrime": input.rns_prime,
        "ringDegree": input.ring_degree,
        "outputCoordinateCount": VSS_PUBLIC_OUTPUT_COORDINATE_COUNT,
        "randomnessColumnCount": VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT,
        "commitmentLimbs": commitment_limbs,
    });
    let commitment_root = derive_canonical_object_hash(&commitment)?;
    let opening_root = derive_canonical_object_hash(&json!({
        "objectType": "VssPublicCommitmentOpening",
        "objectVersion": 1,
        "commitmentRole": input.commitment_role,
        "commitmentContext": input.commitment_context,
        "publicMatrixSeedHash": input.public_matrix_seed_hash,
        "rnsLimbIndex": input.rns_limb_index,
        "rnsPrime": input.rns_prime,
        "ringDegree": input.ring_degree,
        "openingPayloadHash512": vss_public_opening_payload_hash(
            input.message_coefficients,
            &message_digit_columns,
            input.randomness_by_column,
        )?,
    }))?;

    Ok(VssPublicCommitmentComputation {
        commitment,
        commitment_root,
        commitment_context_hash,
        opening_root,
    })
}

pub(crate) fn compute_vss_public_commitment_from_opening_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let computation = compute_vss_public_commitment_from_opening_value(request)?;

    Ok(vss_public_commitment_computation_response(&computation))
}

pub(crate) fn verify_vss_public_coefficient_commitment_set_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let coefficient_set = value_at_path(request, &["coefficientCommitmentSet"])?;
    compare_required_string(
        string_at_path(coefficient_set, &["objectType"])?,
        "VssPublicCoefficientCommitmentSet",
        "compact VSS coefficient commitment set objectType",
    )?;
    compare_required_u64(
        unsigned_at_path(coefficient_set, &["objectVersion"])?,
        1,
        "compact VSS coefficient commitment set objectVersion",
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
        verified_source_trustee_records.push(verify_vss_public_source_coefficient_record(
            VssPublicSourceCoefficientRecordInput {
                source_record,
                expected_roster_position,
                expected_coefficient_count,
                threshold_degree,
                public_matrix_seed_hash,
            },
        )?);
    }

    let expected_set_root = derive_canonical_object_hash(&json!({
        "objectType": "VssPublicCoefficientCommitmentSet",
        "objectVersion": 1,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "participantCount": participant_count,
        "rnsLimbCount": rns_limb_count,
        "thresholdDegree": threshold_degree,
        "ringDegree": ring_degree,
        "sourceTrusteeRecords": verified_source_trustee_records,
    }))?;
    let coefficient_commitment_root =
        hash_at_path(coefficient_set, &["coefficientCommitmentRoot"])?;
    if expected_set_root != coefficient_commitment_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "compact VSS coefficient commitment set root does not match its source records",
        ));
    }

    Ok(json!({
        "ok": true,
        "operation": "verifyVssPublicCoefficientCommitmentSet",
        "coefficientCommitmentRoot": coefficient_commitment_root,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "participantCount": participant_count,
        "rnsLimbCount": rns_limb_count,
        "thresholdDegree": threshold_degree,
        "ringDegree": ring_degree,
    }))
}

pub(crate) fn verify_vss_public_recipient_share_commitment_set_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let recipient_set = value_at_path(request, &["recipientShareCommitmentSet"])?;
    compare_required_string(
        string_at_path(recipient_set, &["objectType"])?,
        "VssPublicRecipientShareCommitmentSet",
        "compact VSS recipient-share commitment set objectType",
    )?;
    compare_required_u64(
        unsigned_at_path(recipient_set, &["objectVersion"])?,
        1,
        "compact VSS recipient-share commitment set objectVersion",
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
        verified_source_trustee_records.push(verify_vss_public_source_recipient_share_record(
            VssPublicSourceRecipientShareRecordInput {
                source_record,
                expected_source_roster_position: expected_roster_position,
                expected_recipient_share_count,
                rns_limb_count,
                public_matrix_seed_hash,
            },
        )?);
    }

    let expected_set_root = derive_canonical_object_hash(&json!({
        "objectType": "VssPublicRecipientShareCommitmentSet",
        "objectVersion": 1,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "participantCount": participant_count,
        "rnsLimbCount": rns_limb_count,
        "ringDegree": ring_degree,
        "sourceTrusteeRecords": verified_source_trustee_records,
    }))?;
    let recipient_share_commitment_root =
        hash_at_path(recipient_set, &["recipientShareCommitmentRoot"])?;
    if expected_set_root != recipient_share_commitment_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "compact VSS recipient-share commitment set root does not match its source records",
        ));
    }

    Ok(json!({
        "ok": true,
        "operation": "verifyVssPublicRecipientShareCommitmentSet",
        "recipientShareCommitmentRoot": recipient_share_commitment_root,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "participantCount": participant_count,
        "rnsLimbCount": rns_limb_count,
        "ringDegree": ring_degree,
    }))
}

pub(crate) fn verify_vss_public_aggregate_threshold_commitment_set_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let aggregate_set = value_at_path(request, &["aggregateThresholdCommitmentSet"])?;
    compare_required_string(
        string_at_path(aggregate_set, &["objectType"])?,
        "VssPublicAggregateThresholdCommitmentSet",
        "compact VSS aggregate threshold commitment set objectType",
    )?;
    compare_required_u64(
        unsigned_at_path(aggregate_set, &["objectVersion"])?,
        1,
        "compact VSS aggregate threshold commitment set objectVersion",
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
        verified_recipient_records.push(verify_vss_public_aggregate_threshold_record(
            VssPublicAggregateThresholdRecordInput {
                recipient_record,
                expected_recipient_roster_position: recipient_record_index / rns_limb_count,
                expected_rns_limb_index: recipient_record_index % rns_limb_count,
                participant_count,
                public_matrix_seed_hash,
            },
        )?);
    }

    let expected_set_root = derive_canonical_object_hash(&json!({
        "objectType": "VssPublicAggregateThresholdCommitmentSet",
        "objectVersion": 1,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "participantCount": participant_count,
        "rnsLimbCount": rns_limb_count,
        "ringDegree": ring_degree,
        "recipientRecords": verified_recipient_records,
    }))?;
    let aggregate_threshold_commitment_root =
        hash_at_path(aggregate_set, &["aggregateThresholdCommitmentRoot"])?;
    if expected_set_root != aggregate_threshold_commitment_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "compact VSS aggregate threshold commitment set root does not match its recipient records",
        ));
    }

    Ok(json!({
        "ok": true,
        "operation": "verifyVssPublicAggregateThresholdCommitmentSet",
        "aggregateThresholdCommitmentRoot": aggregate_threshold_commitment_root,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "participantCount": participant_count,
        "rnsLimbCount": rns_limb_count,
        "ringDegree": ring_degree,
    }))
}

pub(crate) fn verify_vss_share_linkage_statement_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let statement = value_at_path(request, &["statement"])?;
    compare_required_string(
        string_at_path(statement, &["objectType"])?,
        "VssShareLinkageStatement",
        "compact VSS share linkage statement objectType",
    )?;
    compare_required_u64(
        unsigned_at_path(statement, &["objectVersion"])?,
        1,
        "compact VSS share linkage statement objectVersion",
    )?;
    let ceremony_id = read_non_empty_string(statement, "ceremonyId")?;
    let setup_epoch = read_non_empty_string(statement, "setupEpoch")?;
    let manifest_hash = hash_at_path(statement, &["manifestHash"])?;
    let roster_hash = hash_at_path(statement, &["rosterHash"])?;
    let setup_parameters_hash = hash_at_path(statement, &["setupParametersHash"])?;
    let public_matrix_seed_hash = hash_at_path(statement, &["publicMatrixSeedHash"])?;
    let target_basis_hash = hash_at_path(statement, &["targetBasisHash"])?;
    let ring_degree = read_positive_usize_at_path(
        statement,
        &["ringDegree"],
        "compact VSS share linkage statement ringDegree",
    )?;
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
        verified_source_statement_records.push(verify_vss_share_linkage_source_statement(
            VssShareLinkageSourceStatementInput {
                source_statement_record,
                expected_source_position,
                statement: VssShareLinkageStatementBinding {
                    ceremony_id,
                    manifest_hash,
                    roster_hash,
                    setup_parameters_hash,
                    setup_epoch,
                    public_matrix_seed_hash,
                    target_basis_hash,
                    ring_degree,
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
        "objectType": "VssShareLinkageStatement",
        "objectVersion": 1,
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupParametersHash": setup_parameters_hash,
        "setupEpoch": setup_epoch,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "targetBasisHash": target_basis_hash,
        "ringDegree": ring_degree,
        "participantCount": participant_count,
        "targetRnsLimbCount": target_rns_limb_count,
        "thresholdDegree": threshold_degree,
        "coefficientCommitmentRoot": coefficient_commitment_root,
        "recipientShareCommitmentRoot": recipient_share_commitment_root,
        "aggregateThresholdCommitmentRoot": aggregate_threshold_commitment_root,
        "sourceStatementRecords": verified_source_statement_records,
    });
    let expected_statement_root = derive_canonical_object_hash(&statement_without_root)?;
    if expected_statement_root != statement_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "compact VSS share linkage statement root does not match its bound public roots",
        ));
    }
    verify_vss_share_linkage_evidence(VssShareLinkageEvidenceInput {
        request,
        statement: VssShareLinkageStatementBinding {
            ceremony_id,
            manifest_hash,
            roster_hash,
            setup_parameters_hash,
            setup_epoch,
            public_matrix_seed_hash,
            target_basis_hash,
            ring_degree,
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
        "operation": "verifyVssShareLinkageStatement",
        "statementRoot": statement_root,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "targetBasisHash": target_basis_hash,
        "ringDegree": ring_degree,
        "participantCount": participant_count,
        "targetRnsLimbCount": target_rns_limb_count,
        "thresholdDegree": threshold_degree,
        "coefficientCommitmentRoot": coefficient_commitment_root,
        "recipientShareCommitmentRoot": recipient_share_commitment_root,
        "aggregateThresholdCommitmentRoot": aggregate_threshold_commitment_root,
    }))
}

struct VssShareLinkageStatementBinding<'a> {
    ceremony_id: &'a str,
    manifest_hash: &'a str,
    roster_hash: &'a str,
    setup_parameters_hash: &'a str,
    setup_epoch: &'a str,
    public_matrix_seed_hash: &'a str,
    target_basis_hash: &'a str,
    ring_degree: usize,
    participant_count: usize,
    target_rns_limb_count: usize,
    threshold_degree: usize,
    coefficient_commitment_root: &'a str,
    aggregate_threshold_commitment_root: &'a str,
}

struct VssShareLinkageSourceStatementInput<'a> {
    source_statement_record: &'a Value,
    expected_source_position: usize,
    statement: VssShareLinkageStatementBinding<'a>,
}

struct VssShareLinkageEvidenceInput<'a> {
    request: &'a Value,
    statement: VssShareLinkageStatementBinding<'a>,
    recipient_share_commitment_root: &'a str,
    verified_source_statement_records: &'a [Value],
}

fn verify_vss_share_linkage_evidence(
    input: VssShareLinkageEvidenceInput<'_>,
) -> CanonicalResult<()> {
    let (
        Some(coefficient_commitment_set),
        Some(recipient_share_commitment_set),
        Some(aggregate_threshold_commitment_set),
    ) = (
        input.request.get("coefficientCommitmentSet"),
        input.request.get("recipientShareCommitmentSet"),
        input.request.get("aggregateThresholdCommitmentSet"),
    )
    else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "compact VSS share linkage evidence verification requires coefficient, recipient-share, and aggregate-threshold commitment sets",
        ));
    };

    verify_vss_share_linkage_evidence_sets(
        input,
        coefficient_commitment_set,
        recipient_share_commitment_set,
        aggregate_threshold_commitment_set,
    )
}

fn verify_vss_share_linkage_evidence_sets(
    input: VssShareLinkageEvidenceInput<'_>,
    coefficient_commitment_set: &Value,
    recipient_share_commitment_set: &Value,
    aggregate_threshold_commitment_set: &Value,
) -> CanonicalResult<()> {
    let coefficient_verification = verify_vss_public_coefficient_commitment_set_request(&json!({
        "coefficientCommitmentSet": coefficient_commitment_set,
    }))?;
    let recipient_verification =
        verify_vss_public_recipient_share_commitment_set_request(&json!({
            "recipientShareCommitmentSet": recipient_share_commitment_set,
        }))?;
    let aggregate_verification =
        verify_vss_public_aggregate_threshold_commitment_set_request(&json!({
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
            unsigned_at_path(verification, &["ringDegree"])?,
            input.statement.ring_degree as u64,
            &format!("compact VSS share linkage evidence {description} ringDegree"),
        )?;
        compare_required_u64(
            unsigned_at_path(verification, &["rnsLimbCount"])?,
            input.statement.target_rns_limb_count as u64,
            &format!("compact VSS share linkage evidence {description} rnsLimbCount"),
        )?;
    }
    compare_required_string(
        hash_at_path(&coefficient_verification, &["publicMatrixSeedHash"])?,
        input.statement.public_matrix_seed_hash,
        "compact VSS share linkage evidence coefficient publicMatrixSeedHash",
    )?;
    compare_required_u64(
        unsigned_at_path(&coefficient_verification, &["participantCount"])?,
        input.statement.participant_count as u64,
        "compact VSS share linkage evidence coefficient participantCount",
    )?;
    compare_required_u64(
        unsigned_at_path(&coefficient_verification, &["ringDegree"])?,
        input.statement.ring_degree as u64,
        "compact VSS share linkage evidence coefficient ringDegree",
    )?;
    let coefficient_rns_limb_count = usize_at_path(&coefficient_verification, &["rnsLimbCount"])?;
    if coefficient_rns_limb_count < input.statement.target_rns_limb_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "compact VSS share linkage coefficient evidence must cover the target basis",
        ));
    }
    compare_required_u64(
        unsigned_at_path(&coefficient_verification, &["thresholdDegree"])?,
        input.statement.threshold_degree as u64,
        "compact VSS share linkage evidence coefficient thresholdDegree",
    )?;
    verify_vss_public_aggregate_threshold_public_sums(
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
        let target_coefficient_record_count = input
            .statement
            .target_rns_limb_count
            .checked_mul(input.statement.threshold_degree)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "compact VSS share linkage target coefficient count overflowed",
                )
            })?;
        if source_statement_coefficient_opening_roots.len() != target_coefficient_record_count {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "compact VSS share linkage evidence coefficient opening roots must cover the source statement",
            ));
        }
        for (opening_root_index, coefficient_record) in coefficient_records
            .iter()
            .take(target_coefficient_record_count)
            .enumerate()
        {
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

fn verify_vss_public_aggregate_threshold_public_sums(
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
                        CanonicalErrorCode::ComponentMismatch,
                        "compact VSS aggregate threshold commitment body is not the public sum of recipient-share commitments",
                    ));
                }
            }
        }
    }

    Ok(())
}

fn verify_vss_share_linkage_source_statement(
    input: VssShareLinkageSourceStatementInput<'_>,
) -> CanonicalResult<Value> {
    compare_required_string(
        string_at_path(input.source_statement_record, &["objectType"])?,
        "VssShareLinkageSourceStatement",
        "compact VSS share linkage source statement objectType",
    )?;
    compare_required_u64(
        unsigned_at_path(input.source_statement_record, &["objectVersion"])?,
        1,
        "compact VSS share linkage source statement objectVersion",
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
        hash_at_path(input.source_statement_record, &["setupParametersHash"])?,
        input.statement.setup_parameters_hash,
        "compact VSS share linkage source statement setupParametersHash",
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
        unsigned_at_path(input.source_statement_record, &["ringDegree"])?,
        input.statement.ring_degree as u64,
        "compact VSS share linkage source statement ringDegree",
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
    let expected_source_statement = json!({
        "objectType": "VssShareLinkageSourceStatement",
        "objectVersion": 1,
        "ceremonyId": input.statement.ceremony_id,
        "manifestHash": input.statement.manifest_hash,
        "rosterHash": input.statement.roster_hash,
        "setupParametersHash": input.statement.setup_parameters_hash,
        "setupEpoch": input.statement.setup_epoch,
        "publicMatrixSeedHash": input.statement.public_matrix_seed_hash,
        "targetBasisHash": input.statement.target_basis_hash,
        "sourceTrusteeIdentity": source_trustee_identity,
        "sourceTrusteeRosterPosition": input.expected_source_position,
        "ringDegree": input.statement.ring_degree,
        "participantCount": input.statement.participant_count,
        "targetRnsLimbCount": input.statement.target_rns_limb_count,
        "thresholdDegree": input.statement.threshold_degree,
        "coefficientCommitmentRoot": input.statement.coefficient_commitment_root,
        "sourceCoefficientCommitmentRoot": source_coefficient_commitment_root,
        "sourceRecipientShareCommitmentRoot": source_recipient_share_commitment_root,
        "coefficientOpeningRoots": verified_coefficient_opening_roots,
        "recipientShareOpeningRoots": verified_recipient_share_opening_roots,
        "aggregateThresholdCommitmentRoot": input.statement.aggregate_threshold_commitment_root,
    });
    let source_statement_root =
        hash_at_path(input.source_statement_record, &["sourceStatementRoot"])?;
    let expected_source_statement_root = derive_canonical_object_hash(&expected_source_statement)?;
    if expected_source_statement_root != source_statement_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "compact VSS share linkage source statement root does not match its bound roots",
        ));
    }

    let mut verified_source_statement = expected_source_statement;
    verified_source_statement["sourceStatementRoot"] = json!(source_statement_root);

    Ok(verified_source_statement)
}

struct VssPublicSourceCoefficientRecordInput<'a> {
    source_record: &'a Value,
    expected_roster_position: usize,
    expected_coefficient_count: usize,
    threshold_degree: usize,
    public_matrix_seed_hash: &'a str,
}

fn verify_vss_public_source_coefficient_record(
    input: VssPublicSourceCoefficientRecordInput<'_>,
) -> CanonicalResult<Value> {
    compare_required_string(
        string_at_path(input.source_record, &["objectType"])?,
        "VssPublicSourceCoefficientCommitments",
        "compact VSS source coefficient commitments objectType",
    )?;
    compare_required_u64(
        unsigned_at_path(input.source_record, &["objectVersion"])?,
        1,
        "compact VSS source coefficient commitments objectVersion",
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
        verified_coefficient_commitments.push(verify_vss_public_coefficient_record(
            VssPublicCoefficientRecordInput {
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

    let expected_source_root = derive_canonical_object_hash(&json!({
        "objectType": "VssPublicSourceCoefficientCommitments",
        "objectVersion": 1,
        "sourceTrusteeIdentity": source_trustee_identity,
        "sourceTrusteeRosterPosition": input.expected_roster_position,
        "publicMatrixSeedHash": input.public_matrix_seed_hash,
        "coefficientCommitments": verified_coefficient_commitments,
    }))?;
    let source_coefficient_commitment_root =
        hash_at_path(input.source_record, &["sourceCoefficientCommitmentRoot"])?;
    if expected_source_root != source_coefficient_commitment_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "compact VSS source coefficient commitment root does not match its records",
        ));
    }

    Ok(json!({
        "objectType": "VssPublicSourceCoefficientCommitments",
        "objectVersion": 1,
        "sourceTrusteeIdentity": source_trustee_identity,
        "sourceTrusteeRosterPosition": input.expected_roster_position,
        "publicMatrixSeedHash": input.public_matrix_seed_hash,
        "coefficientCommitments": verified_coefficient_commitments,
        "sourceCoefficientCommitmentRoot": source_coefficient_commitment_root,
    }))
}

struct VssPublicCoefficientRecordInput<'a> {
    coefficient_record: &'a Value,
    source_trustee_identity: &'a str,
    source_trustee_roster_position: usize,
    expected_rns_limb_index: usize,
    expected_shamir_coefficient_index: usize,
    public_matrix_seed_hash: &'a str,
}

struct VssPublicCommitmentBodyInput<'a> {
    commitment: &'a Value,
    expected_commitment_role: &'a str,
    expected_commitment_root: &'a str,
    expected_public_matrix_seed_hash: &'a str,
    expected_rns_limb_index: usize,
    expected_rns_prime: u64,
    field_name: &'a str,
}

pub(crate) fn validate_standalone_vss_public_commitment_body(
    commitment: &Value,
    field_name: &str,
) -> CanonicalResult<Value> {
    compare_required_string(
        string_at_path(commitment, &["objectType"])?,
        "VssPublicCommitment",
        &format!("{field_name} objectType"),
    )?;
    compare_required_u64(
        unsigned_at_path(commitment, &["objectVersion"])?,
        1,
        &format!("{field_name} objectVersion"),
    )?;
    validate_vss_public_commitment_role(string_at_path(commitment, &["commitmentRole"])?)?;
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
        VSS_PUBLIC_OUTPUT_COORDINATE_COUNT as u64,
        &format!("{field_name} outputCoordinateCount"),
    )?;
    compare_required_u64(
        unsigned_at_path(commitment, &["randomnessColumnCount"])?,
        VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT as u64,
        &format!("{field_name} randomnessColumnCount"),
    )?;
    let commitment_limbs = array_at_path(commitment, &["commitmentLimbs"])?;
    if commitment_limbs.len() != VSS_PUBLIC_COMMITMENT_MODULUS_LIMB_INDICES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{field_name} commitmentLimbs must cover the compact commitment modulus limbs"),
        ));
    }
    for (limb_position, commitment_limb) in commitment_limbs.iter().enumerate() {
        let expected_commitment_modulus_index =
            VSS_PUBLIC_COMMITMENT_MODULUS_LIMB_INDICES[limb_position];
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
        if coordinates.len() != VSS_PUBLIC_OUTPUT_COORDINATE_COUNT {
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

fn verify_vss_public_commitment_body(
    input: VssPublicCommitmentBodyInput<'_>,
) -> CanonicalResult<Value> {
    let commitment =
        validate_standalone_vss_public_commitment_body(input.commitment, input.field_name)?;
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
    let commitment_root = derive_canonical_object_hash(&commitment)?;
    if commitment_root != input.expected_commitment_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            format!(
                "{} canonical root must match the containing record",
                input.field_name
            ),
        ));
    }

    Ok(commitment)
}

fn verify_vss_public_coefficient_record(
    input: VssPublicCoefficientRecordInput<'_>,
) -> CanonicalResult<Value> {
    compare_required_string(
        string_at_path(input.coefficient_record, &["objectType"])?,
        "VssPublicCoefficientCommitment",
        "compact VSS coefficient commitment objectType",
    )?;
    compare_required_u64(
        unsigned_at_path(input.coefficient_record, &["objectVersion"])?,
        1,
        "compact VSS coefficient commitment objectVersion",
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
    let commitment = verify_vss_public_commitment_body(VssPublicCommitmentBodyInput {
        commitment: value_at_path(input.coefficient_record, &["commitment"])?,
        expected_commitment_role: "coefficient",
        expected_commitment_root: coefficient_commitment_root,
        expected_public_matrix_seed_hash: input.public_matrix_seed_hash,
        expected_rns_limb_index: input.expected_rns_limb_index,
        expected_rns_prime: rns_prime,
        field_name: "compact VSS coefficient commitment commitment",
    })?;

    Ok(json!({
        "objectType": "VssPublicCoefficientCommitment",
        "objectVersion": 1,
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

struct VssPublicSourceRecipientShareRecordInput<'a> {
    source_record: &'a Value,
    expected_source_roster_position: usize,
    expected_recipient_share_count: usize,
    rns_limb_count: usize,
    public_matrix_seed_hash: &'a str,
}

fn verify_vss_public_source_recipient_share_record(
    input: VssPublicSourceRecipientShareRecordInput<'_>,
) -> CanonicalResult<Value> {
    compare_required_string(
        string_at_path(input.source_record, &["objectType"])?,
        "VssPublicSourceRecipientShareCommitments",
        "compact VSS source recipient-share commitments objectType",
    )?;
    compare_required_u64(
        unsigned_at_path(input.source_record, &["objectVersion"])?,
        1,
        "compact VSS source recipient-share commitments objectVersion",
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
        verified_recipient_share_commitments.push(verify_vss_public_recipient_share_record(
            VssPublicRecipientShareRecordInput {
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

    let expected_source_root = derive_canonical_object_hash(&json!({
        "objectType": "VssPublicSourceRecipientShareCommitments",
        "objectVersion": 1,
        "sourceTrusteeIdentity": source_trustee_identity,
        "sourceTrusteeRosterPosition": input.expected_source_roster_position,
        "recipientShareCommitments": verified_recipient_share_commitments,
    }))?;
    let source_recipient_share_commitment_root =
        hash_at_path(input.source_record, &["sourceRecipientShareCommitmentRoot"])?;
    if expected_source_root != source_recipient_share_commitment_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "compact VSS source recipient-share commitment root does not match its records",
        ));
    }

    Ok(json!({
        "objectType": "VssPublicSourceRecipientShareCommitments",
        "objectVersion": 1,
        "sourceTrusteeIdentity": source_trustee_identity,
        "sourceTrusteeRosterPosition": input.expected_source_roster_position,
        "recipientShareCommitments": verified_recipient_share_commitments,
        "sourceRecipientShareCommitmentRoot": source_recipient_share_commitment_root,
    }))
}

struct VssPublicRecipientShareRecordInput<'a> {
    recipient_share_record: &'a Value,
    source_trustee_identity: &'a str,
    source_trustee_roster_position: usize,
    expected_recipient_roster_position: usize,
    expected_rns_limb_index: usize,
    public_matrix_seed_hash: &'a str,
}

fn verify_vss_public_recipient_share_record(
    input: VssPublicRecipientShareRecordInput<'_>,
) -> CanonicalResult<Value> {
    compare_required_string(
        string_at_path(input.recipient_share_record, &["objectType"])?,
        "VssPublicRecipientShareCommitment",
        "compact VSS recipient-share commitment objectType",
    )?;
    compare_required_u64(
        unsigned_at_path(input.recipient_share_record, &["objectVersion"])?,
        1,
        "compact VSS recipient-share commitment objectVersion",
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
    let commitment = verify_vss_public_commitment_body(VssPublicCommitmentBodyInput {
        commitment: value_at_path(input.recipient_share_record, &["commitment"])?,
        expected_commitment_role: "recipient-share",
        expected_commitment_root: share_commitment_root,
        expected_public_matrix_seed_hash: input.public_matrix_seed_hash,
        expected_rns_limb_index: input.expected_rns_limb_index,
        expected_rns_prime: rns_prime,
        field_name: "compact VSS recipient-share commitment commitment",
    })?;

    Ok(json!({
        "objectType": "VssPublicRecipientShareCommitment",
        "objectVersion": 1,
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

struct VssPublicAggregateThresholdRecordInput<'a> {
    recipient_record: &'a Value,
    expected_recipient_roster_position: usize,
    expected_rns_limb_index: usize,
    participant_count: usize,
    public_matrix_seed_hash: &'a str,
}

fn verify_vss_public_aggregate_threshold_record(
    input: VssPublicAggregateThresholdRecordInput<'_>,
) -> CanonicalResult<Value> {
    compare_required_string(
        string_at_path(input.recipient_record, &["objectType"])?,
        "VssPublicAggregateThresholdCommitment",
        "compact VSS aggregate threshold commitment objectType",
    )?;
    compare_required_u64(
        unsigned_at_path(input.recipient_record, &["objectVersion"])?,
        1,
        "compact VSS aggregate threshold commitment objectVersion",
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
    let commitment = verify_vss_public_commitment_body(VssPublicCommitmentBodyInput {
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
        "objectType": "VssPublicAggregateThresholdCommitment",
        "objectVersion": 1,
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

pub(crate) fn read_vss_public_randomness_by_column(
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
    if columns.len() != VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT {
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

    validate_vss_public_randomness_columns(
        &randomness_by_column,
        ring_degree,
        active_limb_modulus,
        field_name,
    )?;

    Ok(randomness_by_column)
}

fn compute_vss_public_commitment_from_opening_value(
    opening: &Value,
) -> CanonicalResult<VssPublicCommitmentComputation> {
    let commitment_role = string_at_path(opening, &["commitmentRole"])?;
    let commitment_context = value_at_path(opening, &["commitmentContext"])?;
    let public_matrix_seed_hash = hash_at_path(opening, &["publicMatrixSeedHash"])?;
    let rns_limb_index = usize_at_path(opening, &["rnsLimbIndex"])?;
    let rns_prime = unsigned_at_path(opening, &["rnsPrime"])?;
    let ring_degree = usize_at_path(opening, &["ringDegree"])?;
    let message_coefficient_bound =
        read_optional_u64(opening, "messageCoefficientBound")?.unwrap_or(rns_prime);
    let message_coefficients = read_vss_public_message_coefficients(
        opening,
        "messageCoefficients",
        ring_degree,
        message_coefficient_bound,
    )?;
    let message_digit_columns =
        read_vss_public_message_digit_columns(opening, "messageDigitColumns", ring_degree)?;
    let randomness_by_column =
        read_vss_public_randomness_by_column(opening, "randomnessByColumn", ring_degree, None)?;

    compute_vss_public_commitment_from_opening(VssPublicCommitmentOpeningInput {
        commitment_role,
        commitment_context,
        public_matrix_seed_hash,
        rns_limb_index,
        rns_prime,
        ring_degree,
        message_coefficients: &message_coefficients,
        message_digit_columns: &message_digit_columns,
        message_coefficient_bound,
        randomness_by_column: &randomness_by_column,
    })
}

fn vss_public_commitment_computation_response(
    computation: &VssPublicCommitmentComputation,
) -> Value {
    json!({
        "ok": true,
        "operation": "computeVssPublicCommitmentFromOpening",
        "commitment": computation.commitment,
        "commitmentRoot": computation.commitment_root,
        "openingRoot": computation.opening_root,
        "commitmentContextHash": computation.commitment_context_hash,
        "encodedCommitmentByteLength": vss_public_encoded_commitment_byte_length(),
    })
}

fn read_vss_public_message_coefficients(
    value: &Value,
    field_name: &str,
    ring_degree: usize,
    message_coefficient_bound: u64,
) -> CanonicalResult<Vec<u64>> {
    if message_coefficient_bound == 0 {
        return Err(invalid_vss_public_input(
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

fn read_vss_public_message_digit_columns(
    value: &Value,
    field_name: &str,
    ring_degree: usize,
) -> CanonicalResult<Vec<Vec<u64>>> {
    let columns_value = value.get(field_name).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{field_name} must be an array"),
        )
    })?;
    let columns = columns_value.as_array().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{field_name} must be an array"),
        )
    })?;
    if columns.len() != VSS_PUBLIC_MESSAGE_DIGIT_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{field_name} must contain the selected message digit count"),
        ));
    }

    columns
        .iter()
        .enumerate()
        .map(|(digit_index, column)| {
            let values = column.as_array().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!("{field_name}.{digit_index} must be an array"),
                )
            })?;
            if values.len() != ring_degree {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    format!("{field_name}.{digit_index} length must match ringDegree"),
                ));
            }

            values
                .iter()
                .enumerate()
                .map(|(coefficient_index, value)| {
                    value.as_u64().ok_or_else(|| {
                        CanonicalError::new(
                            CanonicalErrorCode::InvalidFixture,
                            format!(
                                "{field_name}.{digit_index}.{coefficient_index} must be a non-negative integer"
                            ),
                        )
                    })
                })
                .collect()
        })
        .collect::<CanonicalResult<Vec<_>>>()
}

fn vss_public_message_digit_columns_for_opening(
    message_coefficients: &[u64],
    message_digit_columns: &[Vec<u64>],
    message_coefficient_bound: u64,
    ring_degree: usize,
) -> CanonicalResult<Vec<Vec<u64>>> {
    if message_digit_columns.len() != VSS_PUBLIC_MESSAGE_DIGIT_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "compact VSS messageDigitColumns must contain the selected message digit count",
        ));
    }
    for (digit_index, column) in message_digit_columns.iter().enumerate() {
        if column.len() != ring_degree {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                format!(
                    "compact VSS messageDigitColumns.{digit_index} length must match ringDegree"
                ),
            ));
        }
    }
    let columns = message_digit_columns.to_vec();

    let digit_weights = (0..VSS_PUBLIC_MESSAGE_DIGIT_COUNT)
        .map(|digit_index| {
            u128::from(VSS_PUBLIC_MESSAGE_DIGIT_BASE)
                .checked_pow(digit_index as u32)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "compact VSS message digit weight overflowed",
                    )
                })
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    for (coefficient_index, expected_coefficient) in message_coefficients.iter().enumerate() {
        let mut decoded = 0_u128;
        for (digit_index, column) in columns.iter().enumerate() {
            decoded = decoded
                .checked_add(u128::from(column[coefficient_index]) * digit_weights[digit_index])
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "compact VSS message digit column decoding overflowed",
                    )
                })?;
        }
        if decoded != u128::from(*expected_coefficient)
            || decoded >= u128::from(message_coefficient_bound)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "compact VSS message digit columns do not decode to messageCoefficients.{coefficient_index}"
                ),
            ));
        }
    }

    Ok(columns)
}

fn validate_vss_public_commitment_role(commitment_role: &str) -> CanonicalResult<()> {
    match commitment_role {
        "coefficient"
        | "recipient-share"
        | "aggregate-threshold-share"
        | "target-decryption-smudging-polynomial-coefficient" => Ok(()),
        _ => Err(invalid_vss_public_input(
            "compact VSS commitment role is not supported",
        )),
    }
}

fn compare_required_u64(actual: u64, expected: u64, description: &str) -> CanonicalResult<()> {
    if actual != expected {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
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

fn validate_vss_public_randomness_columns(
    randomness_by_column: &[Vec<i64>],
    ring_degree: usize,
    active_limb_modulus: Option<u64>,
    field_name: &str,
) -> CanonicalResult<()> {
    if randomness_by_column.len() != VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT {
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

struct CommitmentCoordinateInput<'a> {
    public_matrix_seed_hash: &'a str,
    rns_limb_index: usize,
    commitment_modulus_index: usize,
    output_coordinate_index: usize,
    modulus: u64,
    message_digit_columns: &'a [Vec<u64>],
    randomness_by_column: &'a [Vec<i64>],
}

fn commitment_coordinate(input: CommitmentCoordinateInput<'_>) -> CanonicalResult<u64> {
    let mut accumulator = 0_u128;
    let ring_degree = input.message_digit_columns[0].len();
    for digit_index in 0..VSS_PUBLIC_MESSAGE_DIGIT_COUNT {
        let input_column = vss_public_message_digit_column_label_str(digit_index)?;
        let projection_terms = cached_projection_terms(ProjectionTermsInput {
            public_matrix_seed_hash: input.public_matrix_seed_hash,
            rns_limb_index: input.rns_limb_index,
            commitment_modulus_index: input.commitment_modulus_index,
            output_coordinate_index: input.output_coordinate_index,
            input_column,
            ring_degree,
            modulus: input.modulus,
        })?;
        for &(ring_coefficient_index, matrix_residue) in projection_terms.iter() {
            accumulator = add_product_mod(
                accumulator,
                input.message_digit_columns[digit_index][ring_coefficient_index] % input.modulus,
                matrix_residue,
                input.modulus,
            );
        }
    }
    for (randomness_column_index, randomness_column) in
        input.randomness_by_column.iter().enumerate()
    {
        let input_column = vss_public_randomness_column_label(randomness_column_index)?;
        let projection_terms = cached_projection_terms(ProjectionTermsInput {
            public_matrix_seed_hash: input.public_matrix_seed_hash,
            rns_limb_index: input.rns_limb_index,
            commitment_modulus_index: input.commitment_modulus_index,
            output_coordinate_index: input.output_coordinate_index,
            input_column,
            ring_degree: randomness_column.len(),
            modulus: input.modulus,
        })?;
        for &(ring_coefficient_index, matrix_residue) in projection_terms.iter() {
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

pub(in crate::bgv::setup) fn vss_public_message_digit_column_label(
    digit_index: usize,
) -> CanonicalResult<String> {
    Ok(vss_public_message_digit_column_label_str(digit_index)?.to_string())
}

fn vss_public_message_digit_column_label_str(digit_index: usize) -> CanonicalResult<&'static str> {
    match digit_index {
        0 => Ok("message:0"),
        1 => Ok("message:1"),
        _ => Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "compact VSS message digit index is outside the selected profile",
        )),
    }
}

fn is_vss_public_message_digit_column_label(input_column: &str) -> bool {
    (0..VSS_PUBLIC_MESSAGE_DIGIT_COUNT).any(|digit_index| {
        vss_public_message_digit_column_label_str(digit_index)
            .map(|message_column| message_column == input_column)
            .unwrap_or(false)
    })
}

pub(in crate::bgv::setup) fn vss_public_coordinate_count_per_commitment() -> usize {
    VSS_PUBLIC_COMMITMENT_MODULUS_LIMB_INDICES.len() * VSS_PUBLIC_OUTPUT_COORDINATE_COUNT
}

pub(in crate::bgv::setup) fn vss_public_message_coverage_terms_per_coordinate(
    ring_degree: usize,
) -> CanonicalResult<usize> {
    let coordinate_count = vss_public_coordinate_count_per_commitment();
    ring_degree
        .checked_add(coordinate_count - 1)
        .map(|adjusted| adjusted / coordinate_count)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "compact VSS message coverage term count overflowed",
            )
        })
}

fn vss_public_commitment_modulus_position(
    commitment_modulus_index: usize,
) -> CanonicalResult<usize> {
    VSS_PUBLIC_COMMITMENT_MODULUS_LIMB_INDICES
        .iter()
        .position(|candidate_index| *candidate_index == commitment_modulus_index)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "compact VSS commitment modulus index is outside the selected profile",
            )
        })
}

fn vss_public_covered_message_ring_coefficient_index(
    commitment_modulus_index: usize,
    output_coordinate_index: usize,
    coverage_term_index: usize,
) -> CanonicalResult<usize> {
    let commitment_modulus_position =
        vss_public_commitment_modulus_position(commitment_modulus_index)?;
    let coordinate_index = commitment_modulus_position
        .checked_mul(VSS_PUBLIC_OUTPUT_COORDINATE_COUNT)
        .and_then(|value| value.checked_add(output_coordinate_index))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "compact VSS message coverage coordinate index overflowed",
            )
        })?;
    coverage_term_index
        .checked_mul(vss_public_coordinate_count_per_commitment())
        .and_then(|value| value.checked_add(coordinate_index))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "compact VSS message coverage coefficient index overflowed",
            )
        })
}

fn vss_public_randomness_column_label(column_index: usize) -> CanonicalResult<&'static str> {
    match column_index {
        0 => Ok("randomness:0"),
        1 => Ok("randomness:1"),
        _ => Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "compact VSS randomness column index is outside the selected profile",
        )),
    }
}

pub(in crate::bgv::setup) fn vss_public_message_digit_weight(
    digit_index: usize,
    modulus: u64,
) -> CanonicalResult<u64> {
    if digit_index >= VSS_PUBLIC_MESSAGE_DIGIT_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "compact VSS message digit index is outside the selected profile",
        ));
    }
    let mut weight = 1_u128;
    for _ in 0..digit_index {
        weight = (weight * u128::from(VSS_PUBLIC_MESSAGE_DIGIT_BASE)) % u128::from(modulus);
    }

    Ok(weight as u64)
}

pub(in crate::bgv::setup) fn vss_public_message_digits(
    coefficient: u64,
) -> CanonicalResult<[u64; VSS_PUBLIC_MESSAGE_DIGIT_COUNT]> {
    let maximum_coefficient = u128::from(VSS_PUBLIC_MESSAGE_DIGIT_BASE)
        .checked_pow(VSS_PUBLIC_MESSAGE_DIGIT_COUNT as u32)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "compact VSS message digit range overflowed",
            )
        })?;
    if u128::from(coefficient) >= maximum_coefficient {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "compact VSS message coefficient exceeds the full-message coordinate range",
        ));
    }

    let mut remaining = coefficient;
    let mut digits = [0_u64; VSS_PUBLIC_MESSAGE_DIGIT_COUNT];
    for digit in &mut digits {
        *digit = remaining % VSS_PUBLIC_MESSAGE_DIGIT_BASE;
        remaining /= VSS_PUBLIC_MESSAGE_DIGIT_BASE;
    }
    if remaining != 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "compact VSS message coefficient did not fit the selected digit range",
        ));
    }

    Ok(digits)
}

#[cfg(test)]
pub(crate) fn vss_public_canonical_message_digit_columns(
    message_coefficients: &[u64],
    ring_degree: usize,
) -> CanonicalResult<Vec<Vec<u64>>> {
    if message_coefficients.len() != ring_degree {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "compact VSS message coefficient count must match ringDegree",
        ));
    }
    let mut columns = vec![vec![0_u64; ring_degree]; VSS_PUBLIC_MESSAGE_DIGIT_COUNT];
    for (coefficient_index, coefficient) in message_coefficients.iter().enumerate() {
        for (digit_index, digit) in vss_public_message_digits(*coefficient)?
            .into_iter()
            .enumerate()
        {
            columns[digit_index][coefficient_index] = digit;
        }
    }

    Ok(columns)
}

pub(in crate::bgv::setup) fn vss_public_message_digit_only_encoding_layout()
-> VssPublicMessageEncodingLayout {
    VssPublicMessageEncodingLayout {
        low_digit_trit_count: 0,
        high_digit_trit_count: 0,
    }
}

pub(in crate::bgv::setup) fn vss_public_message_digit_bound(
    message_bound_exclusive: u64,
    digit_index: usize,
) -> CanonicalResult<u64> {
    if message_bound_exclusive == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "compact VSS message coefficient bound must be positive",
        ));
    }
    let maximum_coefficient = u128::from(VSS_PUBLIC_MESSAGE_DIGIT_BASE)
        .checked_pow(VSS_PUBLIC_MESSAGE_DIGIT_COUNT as u32)
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

    match digit_index {
        0 => Ok(message_bound_exclusive.min(VSS_PUBLIC_MESSAGE_DIGIT_BASE)),
        1 => {
            let high_digit_bound = u128::from(message_bound_exclusive)
                .div_ceil(u128::from(VSS_PUBLIC_MESSAGE_DIGIT_BASE));
            u64::try_from(high_digit_bound).map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "compact VSS high digit bound overflowed",
                )
            })
        }
        _ => Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "compact VSS message digit index is outside the selected profile",
        )),
    }
}

pub(in crate::bgv::setup) fn vss_public_message_encoding_layout(
    message_bound_exclusive: u64,
) -> CanonicalResult<VssPublicMessageEncodingLayout> {
    if message_bound_exclusive == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "compact VSS message coefficient bound must be positive",
        ));
    }
    let maximum_coefficient = u128::from(VSS_PUBLIC_MESSAGE_DIGIT_BASE)
        .checked_pow(VSS_PUBLIC_MESSAGE_DIGIT_COUNT as u32)
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
    let low_digit_bound =
        u128::from(message_bound_exclusive).min(u128::from(VSS_PUBLIC_MESSAGE_DIGIT_BASE));
    let high_digit_bound =
        u128::from(message_bound_exclusive).div_ceil(u128::from(VSS_PUBLIC_MESSAGE_DIGIT_BASE));
    let low_digit_trit_count = vss_public_trit_count_for_bound(low_digit_bound)?;
    let high_digit_trit_count = vss_public_trit_count_for_bound(high_digit_bound)?;
    Ok(VssPublicMessageEncodingLayout {
        low_digit_trit_count,
        high_digit_trit_count,
    })
}

fn vss_public_trit_count_for_bound(bound_exclusive: u128) -> CanonicalResult<usize> {
    if bound_exclusive == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "compact VSS trit bound must be positive",
        ));
    }
    let mut represented_bound = 1_u128;
    let mut trit_count = 0_usize;
    while represented_bound < bound_exclusive {
        represented_bound = represented_bound.checked_mul(3).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "compact VSS trit bound overflowed",
            )
        })?;
        trit_count = trit_count.checked_add(1).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "compact VSS trit count overflowed",
            )
        })?;
    }

    Ok(trit_count)
}

pub(in crate::bgv::setup) fn vss_public_message_digit_trits_for_count(
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

#[derive(Clone, Copy)]
pub(in crate::bgv::setup) struct ProjectionTermsInput<'a> {
    pub(in crate::bgv::setup) public_matrix_seed_hash: &'a str,
    pub(in crate::bgv::setup) rns_limb_index: usize,
    pub(in crate::bgv::setup) commitment_modulus_index: usize,
    pub(in crate::bgv::setup) output_coordinate_index: usize,
    pub(in crate::bgv::setup) input_column: &'a str,
    pub(in crate::bgv::setup) ring_degree: usize,
    pub(in crate::bgv::setup) modulus: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ProjectionTermCacheKey {
    public_matrix_seed_hash: String,
    rns_limb_index: usize,
    commitment_modulus_index: usize,
    output_coordinate_index: usize,
    input_column: String,
    ring_degree: usize,
    modulus: u64,
}

impl ProjectionTermCacheKey {
    fn from_input(input: ProjectionTermsInput<'_>) -> Self {
        Self {
            public_matrix_seed_hash: input.public_matrix_seed_hash.to_owned(),
            rns_limb_index: input.rns_limb_index,
            commitment_modulus_index: input.commitment_modulus_index,
            output_coordinate_index: input.output_coordinate_index,
            input_column: input.input_column.to_owned(),
            ring_degree: input.ring_degree,
            modulus: input.modulus,
        }
    }
}

type ProjectionTerm = (usize, u64);
type ProjectionTermCache = HashMap<ProjectionTermCacheKey, Arc<[ProjectionTerm]>>;

static PROJECTION_TERM_CACHE: OnceLock<Mutex<ProjectionTermCache>> = OnceLock::new();

pub(in crate::bgv::setup) fn projection_terms(
    input: ProjectionTermsInput<'_>,
) -> CanonicalResult<Vec<ProjectionTerm>> {
    Ok(cached_projection_terms(input)?.as_ref().to_vec())
}

fn cached_projection_terms(
    input: ProjectionTermsInput<'_>,
) -> CanonicalResult<Arc<[ProjectionTerm]>> {
    let cache_key = ProjectionTermCacheKey::from_input(input);
    let cache = PROJECTION_TERM_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(cached_terms) = cache
        .lock()
        .map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "compact VSS projection-term cache is unavailable",
            )
        })?
        .get(&cache_key)
        .cloned()
    {
        return Ok(cached_terms);
    }

    let term_count = if is_vss_public_message_digit_column_label(input.input_column) {
        vss_public_message_coverage_terms_per_coordinate(input.ring_degree)?
    } else {
        VSS_PUBLIC_RANDOMNESS_PROJECTION_WEIGHT
    };
    let mut terms = Vec::with_capacity(term_count);
    for projection_term_index in 0..term_count {
        let ring_coefficient_index = if is_vss_public_message_digit_column_label(input.input_column)
        {
            let scheduled_index = vss_public_covered_message_ring_coefficient_index(
                input.commitment_modulus_index,
                input.output_coordinate_index,
                projection_term_index,
            )?;
            if scheduled_index >= input.ring_degree {
                continue;
            }
            scheduled_index
        } else {
            sample_projection_index(SampleProjectionInput {
                public_matrix_seed_hash: input.public_matrix_seed_hash,
                rns_limb_index: input.rns_limb_index,
                commitment_modulus_index: input.commitment_modulus_index,
                output_coordinate_index: input.output_coordinate_index,
                input_column: input.input_column,
                projection_term_index,
                ring_degree: input.ring_degree,
            })?
        };
        let matrix_residue = sample_matrix_residue(SampleMatrixInput {
            public_matrix_seed_hash: input.public_matrix_seed_hash,
            rns_limb_index: input.rns_limb_index,
            commitment_modulus_index: input.commitment_modulus_index,
            output_coordinate_index: input.output_coordinate_index,
            input_column: input.input_column,
            projection_term_index,
            modulus: input.modulus,
        })?;
        terms.push((ring_coefficient_index, matrix_residue));
    }
    let computed_terms: Arc<[ProjectionTerm]> = Arc::from(terms.into_boxed_slice());

    let mut cache_guard = cache.lock().map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "compact VSS projection-term cache is unavailable",
        )
    })?;
    let cached_terms = cache_guard
        .entry(cache_key)
        .or_insert_with(|| Arc::clone(&computed_terms));

    Ok(Arc::clone(cached_terms))
}

struct SampleMatrixInput<'a> {
    public_matrix_seed_hash: &'a str,
    rns_limb_index: usize,
    commitment_modulus_index: usize,
    output_coordinate_index: usize,
    input_column: &'a str,
    projection_term_index: usize,
    modulus: u64,
}

fn sample_matrix_residue(input: SampleMatrixInput<'_>) -> CanonicalResult<u64> {
    let modulus = u128::from(input.modulus);
    let limit = (1_u128 << 64) - ((1_u128 << 64) % modulus);
    let mut block_index = 0_usize;
    loop {
        let mut preimage = sampler_preimage_prefix(&input);
        push_sampler_u64_field(&mut preimage, input.modulus);
        push_sampler_usize_field(&mut preimage, block_index);
        let digest = hash512(
            VSS_PUBLIC_MATRIX_RESIDUE_HASH_DOMAIN,
            &[preimage.as_slice()],
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

struct SampleProjectionInput<'a> {
    public_matrix_seed_hash: &'a str,
    rns_limb_index: usize,
    commitment_modulus_index: usize,
    output_coordinate_index: usize,
    input_column: &'a str,
    projection_term_index: usize,
    ring_degree: usize,
}

fn sample_projection_index(input: SampleProjectionInput<'_>) -> CanonicalResult<usize> {
    let modulus = input.ring_degree as u128;
    let limit = (1_u128 << 64) - ((1_u128 << 64) % modulus);
    let mut block_index = 0_usize;
    loop {
        let mut preimage = sampler_preimage_prefix(&input);
        push_sampler_usize_field(&mut preimage, input.ring_degree);
        push_sampler_usize_field(&mut preimage, block_index);
        let digest = hash512(
            VSS_PUBLIC_PROJECTION_INDEX_HASH_DOMAIN,
            &[preimage.as_slice()],
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

trait SamplerInput {
    fn public_matrix_seed_hash(&self) -> &str;
    fn rns_limb_index(&self) -> usize;
    fn commitment_modulus_index(&self) -> usize;
    fn output_coordinate_index(&self) -> usize;
    fn input_column(&self) -> &str;
    fn projection_term_index(&self) -> usize;
}

impl SamplerInput for SampleMatrixInput<'_> {
    fn public_matrix_seed_hash(&self) -> &str {
        self.public_matrix_seed_hash
    }

    fn rns_limb_index(&self) -> usize {
        self.rns_limb_index
    }

    fn commitment_modulus_index(&self) -> usize {
        self.commitment_modulus_index
    }

    fn output_coordinate_index(&self) -> usize {
        self.output_coordinate_index
    }

    fn input_column(&self) -> &str {
        self.input_column
    }

    fn projection_term_index(&self) -> usize {
        self.projection_term_index
    }
}

impl SamplerInput for SampleProjectionInput<'_> {
    fn public_matrix_seed_hash(&self) -> &str {
        self.public_matrix_seed_hash
    }

    fn rns_limb_index(&self) -> usize {
        self.rns_limb_index
    }

    fn commitment_modulus_index(&self) -> usize {
        self.commitment_modulus_index
    }

    fn output_coordinate_index(&self) -> usize {
        self.output_coordinate_index
    }

    fn input_column(&self) -> &str {
        self.input_column
    }

    fn projection_term_index(&self) -> usize {
        self.projection_term_index
    }
}

fn sampler_preimage_prefix(input: &impl SamplerInput) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(
        input.public_matrix_seed_hash().len()
            + VSS_PUBLIC_SAMPLER_DOMAIN.len()
            + input.input_column().len()
            + 96,
    );
    push_sampler_bytes_field(&mut preimage, input.public_matrix_seed_hash().as_bytes());
    push_sampler_bytes_field(&mut preimage, VSS_PUBLIC_SAMPLER_DOMAIN.as_bytes());
    push_sampler_usize_field(&mut preimage, input.rns_limb_index());
    push_sampler_usize_field(&mut preimage, input.commitment_modulus_index());
    push_sampler_usize_field(&mut preimage, input.output_coordinate_index());
    push_sampler_bytes_field(&mut preimage, input.input_column().as_bytes());
    push_sampler_usize_field(&mut preimage, input.projection_term_index());

    preimage
}

fn push_sampler_bytes_field(preimage: &mut Vec<u8>, field: &[u8]) {
    if !preimage.is_empty() {
        preimage.push(b'|');
    }
    preimage.extend_from_slice(field);
}

fn push_sampler_usize_field(preimage: &mut Vec<u8>, value: usize) {
    push_sampler_u64_field(preimage, value as u64);
}

fn push_sampler_u64_field(preimage: &mut Vec<u8>, value: u64) {
    if !preimage.is_empty() {
        preimage.push(b'|');
    }
    let mut remaining = value;
    if remaining == 0 {
        preimage.push(b'0');
        return;
    }
    let mut digits = [0_u8; 20];
    let mut digit_count = 0_usize;
    while remaining > 0 {
        digits[digit_count] = b'0' + (remaining % 10) as u8;
        remaining /= 10;
        digit_count += 1;
    }
    for digit in digits[..digit_count].iter().rev() {
        preimage.push(*digit);
    }
}

fn add_product_mod(accumulator: u128, left: u64, right: u64, modulus: u64) -> u128 {
    (accumulator + (u128::from(left) * u128::from(right))) % u128::from(modulus)
}

fn signed_integer_to_residue(value: i64, modulus: u64) -> u64 {
    i128::from(value).rem_euclid(i128::from(modulus)) as u64
}

fn vss_public_opening_payload_hash(
    message_coefficients: &[u64],
    message_digit_columns: &[Vec<u64>],
    randomness_by_column: &[Vec<i64>],
) -> CanonicalResult<String> {
    let word_count = 3_usize
        .checked_add(message_coefficients.len())
        .and_then(|count| {
            message_digit_columns
                .iter()
                .try_fold(count, |total, column| {
                    total.checked_add(1)?.checked_add(column.len())
                })
        })
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
    bytes.extend((message_digit_columns.len() as u64).to_le_bytes());
    for column in message_digit_columns {
        bytes.extend((column.len() as u64).to_le_bytes());
        for digit in column {
            bytes.extend(digit.to_le_bytes());
        }
    }
    bytes.extend((randomness_by_column.len() as u64).to_le_bytes());
    for column in randomness_by_column {
        bytes.extend((column.len() as u64).to_le_bytes());
        for coefficient in column {
            bytes.extend(coefficient.to_le_bytes());
        }
    }

    Ok(hash512_hex(
        VSS_PUBLIC_OPENING_PAYLOAD_HASH_DOMAIN,
        &[&bytes],
    ))
}

fn vss_public_encoded_commitment_byte_length() -> usize {
    VSS_PUBLIC_COMMITMENT_MODULUS_LIMB_INDICES.len() * VSS_PUBLIC_OUTPUT_COORDINATE_COUNT * 8
}

fn invalid_vss_public_input(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

#[cfg(test)]
pub(in crate::bgv::setup) mod tests {
    use serde_json::json;

    use super::{
        VSS_PUBLIC_MESSAGE_BASE_DIGIT_TRIT_COUNT, VSS_PUBLIC_MESSAGE_DIGIT_BASE,
        VSS_PUBLIC_OUTPUT_COORDINATE_COUNT, VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT,
        VssPublicCommitmentComputation, VssPublicCommitmentOpeningInput,
        compute_vss_public_commitment_from_opening,
        compute_vss_public_commitment_from_opening_request,
        verify_vss_public_aggregate_threshold_commitment_set_request,
        verify_vss_public_coefficient_commitment_set_request,
        verify_vss_public_recipient_share_commitment_set_request,
        verify_vss_share_linkage_statement_request, vss_public_canonical_message_digit_columns,
        vss_public_encoded_commitment_byte_length, vss_public_message_encoding_layout,
    };
    use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

    #[test]
    fn message_encoding_layout_uses_digit_bounds_for_trit_columns() -> CanonicalResult<()> {
        let small_layout = vss_public_message_encoding_layout(33)?;
        assert_eq!(small_layout.digit_trit_count(0)?, 4);
        assert_eq!(small_layout.digit_trit_count(1)?, 0);
        assert_eq!(small_layout.encoding_column_count(), 6);

        let full_low_digit_layout = vss_public_message_encoding_layout(
            VSS_PUBLIC_MESSAGE_DIGIT_BASE
                .checked_mul(2)
                .and_then(|value| value.checked_add(1))
                .expect("test bound fits u64"),
        )?;
        assert_eq!(
            full_low_digit_layout.digit_trit_count(0)?,
            VSS_PUBLIC_MESSAGE_BASE_DIGIT_TRIT_COUNT
        );
        assert_eq!(full_low_digit_layout.digit_trit_count(1)?, 1);

        Ok(())
    }

    #[test]
    fn commitment_command_verifies_and_rejects_tampering() -> CanonicalResult<()> {
        let request = opening_request();
        let response = compute_vss_public_commitment_from_opening_request(&request)?;

        assert_eq!(
            response["operation"],
            "computeVssPublicCommitmentFromOpening"
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

        let mut tampered_opening = opening_request();
        tampered_opening["messageCoefficients"][3] = json!(12_u64);
        assert!(
            compute_vss_public_commitment_from_opening_request(&tampered_opening).is_err(),
            "tampered compact opening must reject"
        );

        let mut wrong_shape = opening_request();
        wrong_shape["randomnessByColumn"][0] = json!([0, 1]);
        assert!(
            compute_vss_public_commitment_from_opening_request(&wrong_shape).is_err(),
            "wrong compact randomness shape must reject"
        );

        let mut missing_digit_columns = opening_request();
        missing_digit_columns
            .as_object_mut()
            .expect("compact opening request")
            .remove("messageDigitColumns");
        assert!(
            compute_vss_public_commitment_from_opening_request(&missing_digit_columns).is_err(),
            "compact opening command must require message digit columns"
        );

        Ok(())
    }

    #[test]
    fn commitment_opening_root_binds_explicit_message_digit_columns() -> CanonicalResult<()> {
        let carried_message = VSS_PUBLIC_MESSAGE_DIGIT_BASE + 7;
        let mut request = opening_request();
        request["messageCoefficientBound"] = json!(VSS_PUBLIC_MESSAGE_DIGIT_BASE * 2);
        request["messageCoefficients"][2] = json!(carried_message);
        request["messageDigitColumns"] = json!([
            [1_u64, 2, carried_message, 4, 5, 6, 7, 8],
            [0_u64, 0, 0, 0, 0, 0, 0, 0],
        ]);
        let response = compute_vss_public_commitment_from_opening_request(&request)?;

        let mut canonical_digits_request = request.clone();
        canonical_digits_request["messageDigitColumns"] =
            json!([[1_u64, 2, 7, 4, 5, 6, 7, 8], [0_u64, 0, 1, 0, 0, 0, 0, 0],]);
        let canonical_digits_response =
            compute_vss_public_commitment_from_opening_request(&canonical_digits_request)?;
        assert_ne!(
            response["commitmentRoot"],
            canonical_digits_response["commitmentRoot"]
        );
        assert_ne!(
            response["openingRoot"],
            canonical_digits_response["openingRoot"]
        );

        let mut mismatched_digits_request = request;
        mismatched_digits_request["messageDigitColumns"][0][2] = json!(carried_message - 1);
        assert!(
            compute_vss_public_commitment_from_opening_request(&mismatched_digits_request).is_err(),
            "explicit compact VSS message digit columns must decode to the declared message coefficients"
        );

        Ok(())
    }

    #[test]
    fn coefficient_commitment_set_command_verifies_bound_roots() -> CanonicalResult<()> {
        let coefficient_set = coefficient_commitment_set()?;
        let verification = verify_vss_public_coefficient_commitment_set_request(&json!({
            "command": "VerifyVssPublicCoefficientCommitmentSet",
            "coefficientCommitmentSet": coefficient_set,
        }))?;

        assert_eq!(
            verification["operation"],
            "verifyVssPublicCoefficientCommitmentSet"
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
            verify_vss_public_coefficient_commitment_set_request(&json!({
                "command": "VerifyVssPublicCoefficientCommitmentSet",
                "coefficientCommitmentSet": tampered_set,
            }))
            .is_err(),
            "tampered compact coefficient commitment root must reject"
        );

        Ok(())
    }

    #[test]
    fn recipient_share_commitment_set_command_verifies_bound_roots() -> CanonicalResult<()> {
        let recipient_set = recipient_share_commitment_set()?;
        let verification = verify_vss_public_recipient_share_commitment_set_request(&json!({
            "command": "VerifyVssPublicRecipientShareCommitmentSet",
            "recipientShareCommitmentSet": recipient_set,
        }))?;

        assert_eq!(
            verification["operation"],
            "verifyVssPublicRecipientShareCommitmentSet"
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
            verify_vss_public_recipient_share_commitment_set_request(&json!({
                "command": "VerifyVssPublicRecipientShareCommitmentSet",
                "recipientShareCommitmentSet": tampered_set,
            }))
            .is_err(),
            "tampered compact recipient-share commitment root must reject"
        );

        Ok(())
    }

    #[test]
    fn aggregate_threshold_commitment_set_command_verifies_bound_roots() -> CanonicalResult<()> {
        let aggregate_set = aggregate_threshold_commitment_set()?;
        let verification = verify_vss_public_aggregate_threshold_commitment_set_request(&json!({
            "command": "VerifyVssPublicAggregateThresholdCommitmentSet",
            "aggregateThresholdCommitmentSet": aggregate_set,
        }))?;

        assert_eq!(
            verification["operation"],
            "verifyVssPublicAggregateThresholdCommitmentSet"
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
            verify_vss_public_aggregate_threshold_commitment_set_request(&json!({
                "command": "VerifyVssPublicAggregateThresholdCommitmentSet",
                "aggregateThresholdCommitmentSet": tampered_set,
            }))
            .is_err(),
            "tampered compact aggregate threshold commitment root must reject"
        );

        Ok(())
    }

    #[test]
    fn share_linkage_statement_command_verifies_bound_roots() -> CanonicalResult<()> {
        let coefficient_set = coefficient_commitment_set()?;
        let recipient_set = recipient_share_commitment_set()?;
        let aggregate_set = aggregate_threshold_commitment_set()?;
        let statement =
            share_linkage_statement_from_evidence(&coefficient_set, &recipient_set, &aggregate_set);
        let verification = verify_vss_share_linkage_statement_request(&json!({
            "command": "VerifyVssShareLinkageStatement",
            "statement": statement.clone(),
            "coefficientCommitmentSet": coefficient_set.clone(),
            "recipientShareCommitmentSet": recipient_set.clone(),
            "aggregateThresholdCommitmentSet": aggregate_set.clone(),
        }))?;

        assert_eq!(verification["operation"], "verifyVssShareLinkageStatement");
        assert_eq!(verification["statementRoot"], statement["statementRoot"]);
        assert_eq!(
            verification["aggregateThresholdCommitmentRoot"],
            statement["aggregateThresholdCommitmentRoot"]
        );

        let mut forged_source_statement = statement.clone();
        forged_source_statement["sourceStatementRecords"][0]["sourceRecipientShareCommitmentRoot"] =
            json!("0".repeat(128));
        rebind_share_linkage_source_statement_root(
            &mut forged_source_statement["sourceStatementRecords"][0],
        )?;
        rebind_share_linkage_statement_root(&mut forged_source_statement)?;
        let missing_evidence_error = verify_vss_share_linkage_statement_request(&json!({
            "command": "VerifyVssShareLinkageStatement",
            "statement": forged_source_statement.clone(),
        }))
        .expect_err("compact share-linkage statement verification must require evidence sets");
        assert!(
            missing_evidence_error
                .to_string()
                .contains("requires coefficient, recipient-share, and aggregate-threshold"),
            "missing compact share-linkage evidence should report the required evidence sets: {missing_evidence_error}"
        );
        assert!(
            verify_vss_share_linkage_statement_request(&json!({
                "command": "VerifyVssShareLinkageStatement",
                "statement": forged_source_statement,
                "coefficientCommitmentSet": coefficient_set.clone(),
                "recipientShareCommitmentSet": recipient_set.clone(),
                "aggregateThresholdCommitmentSet": aggregate_set.clone(),
            }))
            .is_err(),
            "evidence-backed linkage verification must reject a source root absent from the recipient-share set"
        );

        let mut mismatched_aggregate_set = aggregate_set.clone();
        tamper_aggregate_commitment_body(&mut mismatched_aggregate_set)?;
        assert!(
            verify_vss_public_aggregate_threshold_commitment_set_request(&json!({
                "command": "VerifyVssPublicAggregateThresholdCommitmentSet",
                "aggregateThresholdCommitmentSet": mismatched_aggregate_set.clone(),
            }))
            .is_ok(),
            "aggregate set verification only checks aggregate body canonical roots"
        );
        let mismatched_statement = share_linkage_statement_from_evidence(
            &coefficient_set,
            &recipient_set,
            &mismatched_aggregate_set,
        );
        let mismatch_error = verify_vss_share_linkage_statement_request(&json!({
            "command": "VerifyVssShareLinkageStatement",
            "statement": mismatched_statement,
            "coefficientCommitmentSet": coefficient_set.clone(),
            "recipientShareCommitmentSet": recipient_set.clone(),
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
            verify_vss_share_linkage_statement_request(&json!({
                "command": "VerifyVssShareLinkageStatement",
                "statement": tampered_statement,
                "coefficientCommitmentSet": coefficient_set,
                "recipientShareCommitmentSet": recipient_set,
                "aggregateThresholdCommitmentSet": aggregate_set,
            }))
            .is_err(),
            "tampered share-linkage statement root must reject"
        );

        Ok(())
    }

    fn opening_request() -> serde_json::Value {
        json!({
            "command": "ComputeVssPublicCommitmentFromOpening",
            "commitmentRole": "aggregate-threshold-share",
            "commitmentContext": {
                "objectType": "VssPublicAggregateThresholdShareCommitmentContext",
                "objectVersion": 1,
                "ceremonyId": "compact-vss-test",
                "manifestHash": "1".repeat(128),
                "rosterHash": "2".repeat(128),
                "setupParametersHash": "3".repeat(128),
                "qShareHash": "4".repeat(128),
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
            "messageDigitColumns": [
                [1, 2, 3, 4, 5, 6, 7, 8],
                [0, 0, 0, 0, 0, 0, 0, 0]
            ],
            "randomnessByColumn": [
                [0, 1, -1, 2, -2, 3, -3, 4],
                [5, -5, 6, -6, 7, -7, 8, -8]
            ],
        })
    }

    // Small final check for the VSS compaction: the public commitment body is a
    // fixed set of field residues (three commitment limbs times sixteen output
    // coordinates), independent of the ring degree, whereas an uncompacted VSS
    // coefficient commitment stores one residue per ring coefficient. The
    // constant-size property is the point of the compaction; the reduction
    // against the first-profile ring is measured and printed, never gated on.
    #[test]
    fn vss_public_commitment_body_is_constant_size_across_ring_degrees() -> CanonicalResult<()> {
        let mut encoded_byte_lengths = Vec::new();
        for ring_degree in [8_usize, 64] {
            let message_coefficients: Vec<u64> =
                (0..ring_degree).map(|index| (index % 7) as u64).collect();
            let low_digit_column = message_coefficients.clone();
            let high_digit_column = vec![0_u64; ring_degree];
            let randomness_first: Vec<i64> = (0..ring_degree)
                .map(|index| ((index % 3) as i64) - 1)
                .collect();
            let randomness_second: Vec<i64> = (0..ring_degree)
                .map(|index| 1 - ((index % 3) as i64))
                .collect();
            let request = json!({
                "commitmentRole": "aggregate-threshold-share",
                "commitmentContext": {
                    "objectType": "VssPublicAggregateThresholdShareCommitmentContext",
                    "objectVersion": 1,
                    "ceremonyId": "compact-vss-measurement",
                    "manifestHash": "1".repeat(128),
                    "rosterHash": "2".repeat(128),
                    "setupParametersHash": "3".repeat(128),
                    "qShareHash": "4".repeat(128),
                    "setupEpoch": "setup-epoch",
                    "recipientIdentity": "trustee-1",
                    "recipientRosterPosition": 0,
                    "rnsLimbIndex": 0,
                    "rnsPrime": 97,
                },
                "publicMatrixSeedHash": "7".repeat(128),
                "rnsLimbIndex": 0,
                "rnsPrime": 97,
                "ringDegree": ring_degree,
                "messageCoefficients": message_coefficients,
                "messageDigitColumns": [low_digit_column, high_digit_column],
                "randomnessByColumn": [randomness_first, randomness_second],
            });
            compute_vss_public_commitment_from_opening_request(&request)?;
            encoded_byte_lengths.push(vss_public_encoded_commitment_byte_length() as u64);
        }

        assert_eq!(
            encoded_byte_lengths[0], encoded_byte_lengths[1],
            "compact commitment body must be a constant size independent of the ring degree"
        );
        let compact_body_bytes = encoded_byte_lengths[0];
        // Model an uncompacted VSS coefficient commitment over the first-profile
        // ring: one ~6-byte residue per ring coefficient per commitment limb.
        let modeled_full_bytes_per_commitment =
            crate::bgv::parameters::POLYNOMIAL_DEGREE as u64 * 3 * 6;
        println!(
            "sealed-lattice-compact-vss-measurement compact-body-bytes={compact_body_bytes} modeled-full-bytes-per-commitment={modeled_full_bytes_per_commitment} reduction={}x",
            modeled_full_bytes_per_commitment / compact_body_bytes.max(1)
        );

        Ok(())
    }

    pub(in crate::bgv::setup) fn coefficient_commitment_set() -> CanonicalResult<serde_json::Value>
    {
        let mut source_trustee_records = Vec::new();
        for source_trustee_roster_position in 0..2_usize {
            source_trustee_records.push(source_coefficient_record(source_trustee_roster_position)?);
        }
        let set_without_root = json!({
            "objectType": "VssPublicCoefficientCommitmentSet",
            "objectVersion": 1,
            "publicMatrixSeedHash": "7".repeat(128),
            "participantCount": 2,
            "rnsLimbCount": 2,
            "thresholdDegree": 2,
            "ringDegree": 8,
            "sourceTrusteeRecords": source_trustee_records,
        });
        let mut coefficient_set = set_without_root;
        coefficient_set["coefficientCommitmentRoot"] = json!(
            crate::hashing::derive_canonical_object_hash(&coefficient_set)
                .expect("compact coefficient set root")
        );

        Ok(coefficient_set)
    }

    fn source_coefficient_record(
        source_trustee_roster_position: usize,
    ) -> CanonicalResult<serde_json::Value> {
        let mut coefficient_commitments = Vec::new();
        for rns_limb_index in 0..test_rns_limb_count() {
            let rns_prime = test_rns_prime(rns_limb_index);
            for shamir_coefficient_index in 0..test_threshold_degree() {
                let computation = test_commitment(
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
                    "objectType": "VssPublicCoefficientCommitment",
                    "objectVersion": 1,
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
            "objectType": "VssPublicSourceCoefficientCommitments",
            "objectVersion": 1,
            "sourceTrusteeIdentity": format!("source-{source_trustee_roster_position}"),
            "sourceTrusteeRosterPosition": source_trustee_roster_position,
            "publicMatrixSeedHash": "7".repeat(128),
            "coefficientCommitments": coefficient_commitments,
        });
        let mut source_record = source_without_root;
        source_record["sourceCoefficientCommitmentRoot"] = json!(
            crate::hashing::derive_canonical_object_hash(&source_record)
                .expect("compact source coefficient root")
        );

        Ok(source_record)
    }

    fn test_participant_count() -> usize {
        2
    }

    fn test_rns_limb_count() -> usize {
        2
    }

    fn test_threshold_degree() -> usize {
        2
    }

    fn test_ring_degree() -> usize {
        8
    }

    fn test_public_matrix_seed_hash() -> String {
        "7".repeat(128)
    }

    fn test_rns_prime(rns_limb_index: usize) -> u64 {
        if rns_limb_index == 0 { 97 } else { 193 }
    }

    fn test_seed(seed_parts: &[usize]) -> usize {
        seed_parts
            .iter()
            .fold(0_usize, |seed, seed_part| seed * 31 + seed_part + 1)
    }

    fn test_hash_from_seed(seed: usize, domain_offset: usize) -> String {
        let digit = (seed + domain_offset) % 16;
        format!("{digit:x}").repeat(128)
    }

    fn test_message_coefficients(seed: usize, modulus: u64) -> Vec<u64> {
        (0..test_ring_degree())
            .map(|coefficient_index| {
                ((seed as u64)
                    .wrapping_mul(17)
                    .wrapping_add((coefficient_index as u64 + 1) * 19))
                    % modulus
            })
            .collect()
    }

    fn test_randomness_by_column(seed: usize) -> Vec<Vec<i64>> {
        (0..VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT)
            .map(|column_index| {
                (0..test_ring_degree())
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

    fn test_commitment(
        commitment_role: &str,
        rns_limb_index: usize,
        rns_prime: u64,
        seed_parts: &[usize],
    ) -> CanonicalResult<VssPublicCommitmentComputation> {
        let seed = test_seed(seed_parts);
        let commitment_context = json!({
            "objectType": "VssPublicTestCommitmentContext",
            "objectVersion": 1,
            "commitmentRole": commitment_role,
            "seedHash": test_hash_from_seed(seed, 9),
        });
        let public_matrix_seed_hash = test_public_matrix_seed_hash();
        let message_coefficients = test_message_coefficients(seed, rns_prime);
        let message_digit_columns =
            vss_public_canonical_message_digit_columns(&message_coefficients, test_ring_degree())?;
        let randomness_by_column = test_randomness_by_column(seed);
        let computation =
            compute_vss_public_commitment_from_opening(VssPublicCommitmentOpeningInput {
                commitment_role,
                commitment_context: &commitment_context,
                public_matrix_seed_hash: &public_matrix_seed_hash,
                rns_limb_index,
                rns_prime,
                ring_degree: test_ring_degree(),
                message_coefficients: &message_coefficients,
                message_digit_columns: &message_digit_columns,
                message_coefficient_bound: rns_prime,
                randomness_by_column: &randomness_by_column,
            })?;

        Ok(computation)
    }

    pub(in crate::bgv::setup) fn recipient_share_commitment_set()
    -> CanonicalResult<serde_json::Value> {
        let mut source_trustee_records = Vec::new();
        for source_trustee_roster_position in 0..test_participant_count() {
            source_trustee_records.push(source_recipient_share_record(
                source_trustee_roster_position,
            )?);
        }
        let set_without_root = json!({
            "objectType": "VssPublicRecipientShareCommitmentSet",
            "objectVersion": 1,
            "publicMatrixSeedHash": test_public_matrix_seed_hash(),
            "participantCount": test_participant_count(),
            "rnsLimbCount": test_rns_limb_count(),
            "ringDegree": test_ring_degree(),
            "sourceTrusteeRecords": source_trustee_records,
        });
        let mut recipient_set = set_without_root;
        recipient_set["recipientShareCommitmentRoot"] = json!(
            crate::hashing::derive_canonical_object_hash(&recipient_set)
                .expect("compact recipient-share set root")
        );

        Ok(recipient_set)
    }

    fn source_recipient_share_record(
        source_trustee_roster_position: usize,
    ) -> CanonicalResult<serde_json::Value> {
        let mut recipient_share_commitments = Vec::new();
        for recipient_roster_position in 0..test_participant_count() {
            for rns_limb_index in 0..test_rns_limb_count() {
                recipient_share_commitments.push(recipient_share_commitment_record(
                    source_trustee_roster_position,
                    recipient_roster_position,
                    rns_limb_index,
                )?);
            }
        }
        let source_without_root = json!({
            "objectType": "VssPublicSourceRecipientShareCommitments",
            "objectVersion": 1,
            "sourceTrusteeIdentity": format!("source-{source_trustee_roster_position}"),
            "sourceTrusteeRosterPosition": source_trustee_roster_position,
            "recipientShareCommitments": recipient_share_commitments,
        });
        let mut source_record = source_without_root;
        source_record["sourceRecipientShareCommitmentRoot"] = json!(
            crate::hashing::derive_canonical_object_hash(&source_record)
                .expect("compact source recipient-share root")
        );

        Ok(source_record)
    }

    fn recipient_share_commitment_record(
        source_trustee_roster_position: usize,
        recipient_roster_position: usize,
        rns_limb_index: usize,
    ) -> CanonicalResult<serde_json::Value> {
        let rns_prime = test_rns_prime(rns_limb_index);
        let computation = test_commitment(
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
            "objectType": "VssPublicRecipientShareCommitment",
            "objectVersion": 1,
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

    fn aggregate_threshold_commitment_set() -> CanonicalResult<serde_json::Value> {
        let recipient_set = recipient_share_commitment_set()?;
        aggregate_threshold_commitment_set_from_recipient_set(&recipient_set)
    }

    pub(in crate::bgv::setup) fn aggregate_threshold_commitment_set_from_recipient_set(
        recipient_set: &serde_json::Value,
    ) -> CanonicalResult<serde_json::Value> {
        let mut recipient_records = Vec::new();
        for recipient_roster_position in 0..test_participant_count() {
            for rns_limb_index in 0..test_rns_limb_count() {
                recipient_records.push(aggregate_threshold_commitment_record(
                    recipient_set,
                    recipient_roster_position,
                    rns_limb_index,
                )?);
            }
        }
        let set_without_root = json!({
            "objectType": "VssPublicAggregateThresholdCommitmentSet",
            "objectVersion": 1,
            "publicMatrixSeedHash": test_public_matrix_seed_hash(),
            "participantCount": test_participant_count(),
            "rnsLimbCount": test_rns_limb_count(),
            "ringDegree": test_ring_degree(),
            "recipientRecords": recipient_records,
        });
        let mut aggregate_set = set_without_root;
        aggregate_set["aggregateThresholdCommitmentRoot"] = json!(
            crate::hashing::derive_canonical_object_hash(&aggregate_set)
                .expect("compact aggregate threshold set root")
        );

        Ok(aggregate_set)
    }

    fn aggregate_threshold_commitment_record(
        recipient_set: &serde_json::Value,
        recipient_roster_position: usize,
        rns_limb_index: usize,
    ) -> CanonicalResult<serde_json::Value> {
        let source_share_records = source_share_records_for_recipient(
            recipient_set,
            recipient_roster_position,
            rns_limb_index,
        )?;
        let rns_prime = test_rns_prime(rns_limb_index);
        let commitment = aggregate_commitment_body(
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
        let seed = test_seed(&[recipient_roster_position, rns_limb_index, 5]);

        Ok(json!({
            "objectType": "VssPublicAggregateThresholdCommitment",
            "objectVersion": 1,
            "recipientIdentity": format!("recipient-{recipient_roster_position}"),
            "recipientRosterPosition": recipient_roster_position,
            "recipientTrusteePoint": recipient_roster_position + 1,
            "rnsLimbIndex": rns_limb_index,
            "rnsPrime": rns_prime,
            "aggregateCommitmentRoot": crate::hashing::derive_canonical_object_hash(&commitment,
            )?,
            "aggregateOpeningRoot": test_hash_from_seed(seed, 0),
            "commitment": commitment,
            "sourceShareCommitmentRoots": source_share_commitment_roots,
            "sourceShareOpeningRoots": source_share_opening_roots,
        }))
    }

    fn source_share_records_for_recipient(
        recipient_set: &serde_json::Value,
        recipient_roster_position: usize,
        rns_limb_index: usize,
    ) -> CanonicalResult<Vec<serde_json::Value>> {
        let recipient_share_record_index = recipient_roster_position
            .checked_mul(test_rns_limb_count())
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

    fn aggregate_commitment_body(
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
            for coordinate_index in 0..VSS_PUBLIC_OUTPUT_COORDINATE_COUNT {
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

        let seed = test_seed(&[recipient_roster_position, rns_limb_index, 4]);
        Ok(json!({
            "objectType": "VssPublicCommitment",
            "objectVersion": 1,
            "commitmentRole": "aggregate-threshold-share",
            "commitmentContextHash": test_hash_from_seed(seed, 0),
            "publicMatrixSeedHash": test_public_matrix_seed_hash(),
            "rnsLimbIndex": rns_limb_index,
            "rnsPrime": rns_prime,
            "ringDegree": test_ring_degree(),
            "outputCoordinateCount": VSS_PUBLIC_OUTPUT_COORDINATE_COUNT,
            "randomnessColumnCount": VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT,
            "commitmentLimbs": commitment_limbs,
        }))
    }

    pub(in crate::bgv::setup) fn share_linkage_statement_from_evidence(
        coefficient_set: &serde_json::Value,
        recipient_set: &serde_json::Value,
        aggregate_set: &serde_json::Value,
    ) -> serde_json::Value {
        // The primitive statement verifier binds targetBasisHash as data; the
        // canonical-basis check lives in the same-secret bridge, so any
        // well-formed deterministic hash serves the fixture here.
        let target_basis_hash = crate::hashing::hash512_hex(
            "sealed-lattice-compact-vss-test/target-basis",
            &[b"target-basis"],
        );
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
                    "objectType": "VssShareLinkageSourceStatement",
                    "objectVersion": 1,
                    "ceremonyId": "compact-vss-test",
                    "manifestHash": "1".repeat(128),
                    "rosterHash": "2".repeat(128),
                    "setupParametersHash": "3".repeat(128),
                    "setupEpoch": "setup-epoch",
                    "publicMatrixSeedHash": "7".repeat(128),
                    "targetBasisHash": target_basis_hash.clone(),
                    "sourceTrusteeIdentity": format!("source-{source_trustee_roster_position}"),
                    "sourceTrusteeRosterPosition": source_trustee_roster_position,
                    "ringDegree": 8,
                    "participantCount": 2,
                    "targetRnsLimbCount": 2,
                    "thresholdDegree": 2,
                    "coefficientCommitmentRoot": coefficient_set["coefficientCommitmentRoot"].clone(),
                    "sourceCoefficientCommitmentRoot": coefficient_source_record["sourceCoefficientCommitmentRoot"].clone(),
                    "sourceRecipientShareCommitmentRoot": recipient_source_record["sourceRecipientShareCommitmentRoot"].clone(),
                    "coefficientOpeningRoots": coefficient_opening_roots,
                    "recipientShareOpeningRoots": recipient_share_opening_roots,
                    "aggregateThresholdCommitmentRoot": aggregate_set["aggregateThresholdCommitmentRoot"].clone(),
                });
                let mut source_statement = source_statement_without_root;
                source_statement["sourceStatementRoot"] = json!(
                    crate::hashing::derive_canonical_object_hash(&source_statement,
                    )
                    .expect("source statement root")
                );
                source_statement
            })
            .collect::<Vec<_>>();
        let statement_without_root = json!({
            "objectType": "VssShareLinkageStatement",
            "objectVersion": 1,
            "ceremonyId": "compact-vss-test",
            "manifestHash": "1".repeat(128),
            "rosterHash": "2".repeat(128),
            "setupParametersHash": "3".repeat(128),
            "setupEpoch": "setup-epoch",
            "publicMatrixSeedHash": "7".repeat(128),
            "targetBasisHash": target_basis_hash,
            "ringDegree": 8,
            "participantCount": 2,
            "targetRnsLimbCount": 2,
            "thresholdDegree": 2,
            "coefficientCommitmentRoot": coefficient_set["coefficientCommitmentRoot"].clone(),
            "recipientShareCommitmentRoot": recipient_set["recipientShareCommitmentRoot"].clone(),
            "aggregateThresholdCommitmentRoot": aggregate_set["aggregateThresholdCommitmentRoot"].clone(),
            "sourceStatementRecords": source_statement_records,
        });

        let mut statement = statement_without_root;
        statement["statementRoot"] = json!(
            crate::hashing::derive_canonical_object_hash(&statement).expect("statement root")
        );
        statement
    }

    fn rebind_share_linkage_source_statement_root(
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
        source_statement["sourceStatementRoot"] =
            json!(crate::hashing::derive_canonical_object_hash(
                &serde_json::Value::Object(source_statement_without_root),
            )?);

        Ok(())
    }

    fn rebind_share_linkage_statement_root(
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
        statement["statementRoot"] = json!(crate::hashing::derive_canonical_object_hash(
            &serde_json::Value::Object(statement_without_root),
        )?);

        Ok(())
    }

    fn tamper_aggregate_commitment_body(
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
        aggregate_record["aggregateCommitmentRoot"] = json!(
            crate::hashing::derive_canonical_object_hash(&aggregate_record["commitment"],)?
        );
        rebind_aggregate_threshold_commitment_set_root(aggregate_set)
    }

    fn rebind_aggregate_threshold_commitment_set_root(
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
            json!(crate::hashing::derive_canonical_object_hash(
                &serde_json::Value::Object(aggregate_set_without_root),
            )?);

        Ok(())
    }
}
