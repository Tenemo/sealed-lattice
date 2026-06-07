use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use crate::{
    bgv::{
        profile::{DATA_PRIMES, POLYNOMIAL_DEGREE},
        validation::reject_unexpected_bgv_request_fields,
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::derive_protocol_hash,
};

use super::{
    accepted_setup::{
        COLLECTIVE_BGV_SETUP_PROFILE_ID, accepted_q_share_hash, accepted_setup_profile_hash,
    },
    commitment::{
        SetupCommitmentValue, parse_setup_commitment_full_value, setup_commitment_profile_hash,
        setup_commitment_root,
    },
    private_vss_share_proof::{
        PrivateVssShareLnpProofGenerationInput, PrivateVssShareLnpProofVerificationInput,
        PrivateVssShareLnpProofWitness, private_vss_share_lnp_proof_record,
        verify_private_vss_share_lnp_relation_proof,
    },
    sharing::canonical_trustee_point,
    vss::carry_aware_vss_share_relation_profile_hash,
};

const PRIVATE_VSS_ENVELOPE_OBJECT_TYPE: &str = "PrivateVssShareEnvelope";
const PRIVATE_VSS_LIMB_OPENING_OBJECT_TYPE: &str = "PrivateVssShareLimbOpening";
const VSS_SOURCE_TRUSTEE_COMMITMENT_OBJECT_TYPE: &str = "VssSourceTrusteeCoefficientCommitments";
const VSS_COEFFICIENT_COMMITMENT_MATERIAL_OBJECT_TYPE: &str = "VssCoefficientCommitmentMaterial";
const FIRST_PROFILE_DECRYPTION_THRESHOLD: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
struct PrivateVssRefusal {
    reason_code: &'static str,
    message: String,
    object_path: String,
}

impl PrivateVssRefusal {
    fn new(
        reason_code: &'static str,
        message: impl Into<String>,
        object_path: impl Into<String>,
    ) -> Self {
        Self {
            reason_code,
            message: message.into(),
            object_path: object_path.into(),
        }
    }

    fn to_value(&self) -> Value {
        json!({
            "reasonCode": self.reason_code,
            "message": self.message,
            "objectPath": self.object_path,
        })
    }
}

struct SourceTrusteeCommitmentBinding {
    source_trustee_identity: String,
    source_trustee_roster_position: u64,
    source_trustee_commitment_root: String,
    coefficient_commitment_roots: BTreeMap<(usize, u64), String>,
}

struct CoefficientCommitmentBinding {
    commitment_root: String,
    commitment: SetupCommitmentValue,
}

type CoefficientCommitmentCoordinate = (usize, u64);
type CoefficientCommitmentBindingsByCoordinate =
    BTreeMap<CoefficientCommitmentCoordinate, CoefficientCommitmentBinding>;
type CoefficientCommitmentMaterialRecordsVerification =
    Result<CoefficientCommitmentBindingsByCoordinate, PrivateVssRefusal>;

struct PrivateEnvelopeBinding {
    private_envelope_hash: String,
    private_envelope_aad_hash: String,
    recipient_identity: String,
    recipient_roster_position: u64,
}

struct LimbVerification {
    rns_limb_index: usize,
    rns_prime: u64,
    ring_degree: usize,
    coefficient_commitment_roots: Vec<String>,
    share_values_hash: String,
    private_vss_share_proof_hash: String,
    proof_statement_root: String,
    limb_verification_root: String,
}

pub(crate) fn verify_private_vss_share_envelope_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    reject_unexpected_bgv_request_fields(
        request,
        &[
            "setupContext",
            "publicMatrixSeedHash",
            "sourceTrusteeCoefficientCommitmentRecord",
            "sourceTrusteeCoefficientCommitmentMaterialRecords",
            "privateEnvelope",
            "transportedPrivateVssShareProofMaterial",
            "expectedPrivateEnvelopeHash",
            "expectedLocalVerificationRoot",
        ],
        "verifyPrivateVssShareEnvelope",
    )?;

    match verify_private_vss_share_envelope_inner(request)? {
        Ok(response) => Ok(response),
        Err(refusal) => Ok(verification_response(
            false,
            "refused",
            None,
            None,
            Vec::new(),
            vec![refusal],
        )),
    }
}

pub(crate) fn generate_private_vss_share_proof_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    reject_unexpected_bgv_request_fields(
        request,
        &[
            "setupContext",
            "publicMatrixSeedHash",
            "privateEnvelopeAadHash",
            "sourceTrusteeCoefficientCommitmentRecord",
            "sourceTrusteeCoefficientCommitmentMaterialRecords",
            "recipientIdentity",
            "recipientRosterPosition",
            "rnsLimbIndex",
            "rnsPrime",
            "ringDegree",
            "shareValues",
            "coefficientCommitmentRoots",
            "coefficientMessagesByShamirIndex",
            "openingRandomnessByShamirIndex",
            "proofRandomnessSource",
            "proofRandomnessSeedHex",
        ],
        "generatePrivateVssShareProof",
    )?;

    let setup_context = object_field(
        request,
        "setupContext",
        "setupContext",
        "setupContextMissing",
        "setupContext must be provided for private VSS proof generation",
    )
    .map_err(private_vss_refusal_to_error)?;
    if let Err(refusal) = verify_setup_context(setup_context)? {
        return Err(private_vss_refusal_to_error(refusal));
    }
    let public_matrix_seed_hash = hash_string_field(
        request,
        "publicMatrixSeedHash",
        "publicMatrixSeedHash",
        "publicMatrixSeedHashMissing",
        "publicMatrixSeedHash must be provided for private VSS proof generation",
    )
    .map_err(private_vss_refusal_to_error)?;
    validate_hash_string(public_matrix_seed_hash, "publicMatrixSeedHash")?;
    let private_envelope_aad_hash = hash_string_field(
        request,
        "privateEnvelopeAadHash",
        "privateEnvelopeAadHash",
        "privateEnvelopeAadHashMissing",
        "privateEnvelopeAadHash must be provided for private VSS proof generation",
    )
    .map_err(private_vss_refusal_to_error)?;
    validate_hash_string(private_envelope_aad_hash, "privateEnvelopeAadHash")?;

    let source_trustee_record = object_field(
        request,
        "sourceTrusteeCoefficientCommitmentRecord",
        "sourceTrusteeCoefficientCommitmentRecord",
        "sourceTrusteeCommitmentRecordMissing",
        "sourceTrusteeCoefficientCommitmentRecord must be provided for private VSS proof generation",
    )
    .map_err(private_vss_refusal_to_error)?;
    let source_trustee_binding = verify_source_trustee_commitment_record(
        source_trustee_record,
        setup_context,
        public_matrix_seed_hash,
    )?
    .map_err(private_vss_refusal_to_error)?;
    let material_records = array_field(
        request,
        "sourceTrusteeCoefficientCommitmentMaterialRecords",
        "sourceTrusteeCoefficientCommitmentMaterialRecords",
        "sourceTrusteeCommitmentMaterialMissing",
        "sourceTrusteeCoefficientCommitmentMaterialRecords must be provided for private VSS proof generation",
    )
    .map_err(private_vss_refusal_to_error)?;
    let coefficient_commitments = verify_coefficient_commitment_material_records(
        material_records,
        setup_context,
        public_matrix_seed_hash,
        &source_trustee_binding,
    )?
    .map_err(private_vss_refusal_to_error)?;

    let recipient_identity = string_field(
        request,
        "recipientIdentity",
        "recipientIdentity",
        "recipientIdentityMissing",
        "recipientIdentity must be provided for private VSS proof generation",
    )
    .map_err(private_vss_refusal_to_error)?;
    let recipient_roster_position = u64_field(
        request,
        "recipientRosterPosition",
        "recipientRosterPosition",
        "recipientRosterPositionMissing",
        "recipientRosterPosition must be provided for private VSS proof generation",
    )
    .map_err(private_vss_refusal_to_error)?;
    if recipient_roster_position >= 10 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "recipientRosterPosition is outside the first accepted profile roster",
        ));
    }
    let rns_limb_index = usize_field(
        request,
        "rnsLimbIndex",
        "rnsLimbIndex",
        "rnsLimbIndexMissing",
        "rnsLimbIndex must be provided for private VSS proof generation",
    )
    .map_err(private_vss_refusal_to_error)?;
    let rns_prime = u64_field(
        request,
        "rnsPrime",
        "rnsPrime",
        "rnsPrimeMissing",
        "rnsPrime must be provided for private VSS proof generation",
    )
    .map_err(private_vss_refusal_to_error)?;
    if DATA_PRIMES.get(rns_limb_index) != Some(&rns_prime) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "rnsPrime must match Q_share at rnsLimbIndex",
        ));
    }
    let ring_degree = usize_field(
        request,
        "ringDegree",
        "ringDegree",
        "ringDegreeMissing",
        "ringDegree must be provided for private VSS proof generation",
    )
    .map_err(private_vss_refusal_to_error)?;
    if ring_degree == 0 || ring_degree > POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "ringDegree is outside the selected setup profile",
        ));
    }
    let share_values = u64_vector_field(
        request,
        "shareValues",
        "shareValues",
        "shareValuesMissing",
        "shareValues must be provided for private VSS proof generation",
    )
    .map_err(private_vss_refusal_to_error)?;
    if share_values.len() != ring_degree || share_values.iter().any(|value| *value >= rns_prime) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "shareValues must be canonical Q_share residues with length ringDegree",
        ));
    }
    let coefficient_commitment_roots = hash_vector_field(
        request,
        "coefficientCommitmentRoots",
        "coefficientCommitmentRoots",
        "coefficientCommitmentRootsMissing",
        "coefficientCommitmentRoots must be provided for private VSS proof generation",
    )
    .map_err(private_vss_refusal_to_error)?;
    if coefficient_commitment_roots.len() != FIRST_PROFILE_DECRYPTION_THRESHOLD {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "coefficientCommitmentRoots must bind every first-profile Shamir coefficient",
        ));
    }
    let mut coefficient_commitment_values = Vec::with_capacity(FIRST_PROFILE_DECRYPTION_THRESHOLD);
    for (shamir_coefficient_index, commitment_root) in
        coefficient_commitment_roots.iter().enumerate()
    {
        let shamir_coefficient_index = shamir_coefficient_index as u64;
        if source_trustee_binding
            .coefficient_commitment_roots
            .get(&(rns_limb_index, shamir_coefficient_index))
            .map(String::as_str)
            != Some(commitment_root.as_str())
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "coefficientCommitmentRoots must match the public source trustee commitment record",
            ));
        }
        let Some(material_binding) =
            coefficient_commitments.get(&(rns_limb_index, shamir_coefficient_index))
        else {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "sourceTrusteeCoefficientCommitmentMaterialRecords must include the requested proof limb",
            ));
        };
        if material_binding.commitment_root != *commitment_root {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "coefficient commitment material root must match coefficientCommitmentRoots",
            ));
        }
        coefficient_commitment_values.push(material_binding.commitment.clone());
    }

    let coefficient_messages_by_shamir_index = u64_matrix_field(
        request,
        "coefficientMessagesByShamirIndex",
        "coefficientMessagesByShamirIndex",
        "coefficientMessagesMissing",
        "coefficientMessagesByShamirIndex must be provided for private VSS proof generation",
    )?;
    let opening_randomness_by_shamir_index = i128_matrix3_field(
        request,
        "openingRandomnessByShamirIndex",
        "openingRandomnessByShamirIndex",
        "openingRandomnessMissing",
        "openingRandomnessByShamirIndex must be provided for private VSS proof generation",
    )?;
    let carry_witnesses = derive_private_vss_carry_witnesses(
        rns_prime,
        recipient_roster_position,
        ring_degree,
        &share_values,
        &coefficient_messages_by_shamir_index,
    )?;
    let proof_randomness_seed_hex = string_field(
        request,
        "proofRandomnessSeedHex",
        "proofRandomnessSeedHex",
        "proofRandomnessSeedMissing",
        "proofRandomnessSeedHex must be provided for private VSS proof generation",
    )
    .map_err(private_vss_refusal_to_error)?;
    let proof_randomness_source = request
        .get("proofRandomnessSource")
        .and_then(Value::as_str)
        .unwrap_or("fresh-csprng");
    if !matches!(
        proof_randomness_source,
        "fresh-csprng" | "development-deterministic-fixture"
    ) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "proofRandomnessSource must be fresh-csprng or development-deterministic-fixture",
        ));
    }
    let share_values_hash = derive_protocol_hash(
        "PrivateVssLocalVerificationRoot",
        &json!({
            "objectType": "PrivateVssShareValueVector",
            "objectVersion": 1,
            "rnsLimbIndex": rns_limb_index,
            "rnsPrime": rns_prime,
            "shareValues": share_values,
        }),
    )?;
    let proof_record =
        private_vss_share_lnp_proof_record(PrivateVssShareLnpProofGenerationInput {
            setup_context,
            public_matrix_seed_hash,
            private_envelope_aad_hash,
            source_trustee_identity: &source_trustee_binding.source_trustee_identity,
            source_trustee_roster_position: source_trustee_binding.source_trustee_roster_position,
            recipient_identity,
            recipient_roster_position,
            source_trustee_commitment_root: &source_trustee_binding.source_trustee_commitment_root,
            rns_limb_index,
            rns_prime,
            ring_degree,
            coefficient_commitment_roots: &coefficient_commitment_roots,
            share_values: &share_values,
            share_values_hash: &share_values_hash,
            coefficient_commitments: &coefficient_commitment_values,
            witness: &PrivateVssShareLnpProofWitness {
                coefficient_messages_by_shamir_index,
                opening_randomness_by_shamir_index,
                carry_witnesses,
            },
            proof_randomness_seed_hex,
        })?;

    Ok(json!({
        "ok": true,
        "operation": "generatePrivateVssShareProof",
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "sourceTrusteeIdentity": source_trustee_binding.source_trustee_identity,
        "sourceTrusteeRosterPosition": source_trustee_binding.source_trustee_roster_position,
        "recipientIdentity": recipient_identity,
        "recipientRosterPosition": recipient_roster_position,
        "rnsLimbIndex": rns_limb_index,
        "rnsPrime": rns_prime,
        "ringDegree": ring_degree,
        "shareValuesHash": share_values_hash,
        "privateVssShareProof": proof_record,
        "proofRandomness": {
            "source": proof_randomness_source,
            "seedBytes": 64,
            "retention": "proof randomness seed material is consumed for proof generation and is not returned"
        }
    }))
}

fn verify_private_vss_share_envelope_inner(
    request: &Value,
) -> CanonicalResult<Result<Value, PrivateVssRefusal>> {
    let setup_context = match object_field(
        request,
        "setupContext",
        "setupContext",
        "setupContextMissing",
        "setupContext must be provided for private VSS verification",
    ) {
        Ok(setup_context) => setup_context,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if let Err(refusal) = verify_setup_context(setup_context)? {
        return Ok(Err(refusal));
    }

    let public_matrix_seed_hash = match hash_string_field(
        request,
        "publicMatrixSeedHash",
        "publicMatrixSeedHash",
        "publicMatrixSeedHashMissing",
        "publicMatrixSeedHash must be provided for private VSS verification",
    ) {
        Ok(public_matrix_seed_hash) => public_matrix_seed_hash,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let source_trustee_record = match object_field(
        request,
        "sourceTrusteeCoefficientCommitmentRecord",
        "sourceTrusteeCoefficientCommitmentRecord",
        "sourceTrusteeCommitmentRecordMissing",
        "sourceTrusteeCoefficientCommitmentRecord must be provided for private VSS verification",
    ) {
        Ok(source_trustee_record) => source_trustee_record,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let private_envelope = match object_field(
        request,
        "privateEnvelope",
        "privateEnvelope",
        "privateEnvelopeMissing",
        "privateEnvelope must be provided for private VSS verification",
    ) {
        Ok(private_envelope) => private_envelope,
        Err(refusal) => return Ok(Err(refusal)),
    };

    let source_trustee_binding = match verify_source_trustee_commitment_record(
        source_trustee_record,
        setup_context,
        public_matrix_seed_hash,
    )? {
        Ok(source_trustee_binding) => source_trustee_binding,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let material_records = match array_field(
        request,
        "sourceTrusteeCoefficientCommitmentMaterialRecords",
        "sourceTrusteeCoefficientCommitmentMaterialRecords",
        "sourceTrusteeCommitmentMaterialMissing",
        "sourceTrusteeCoefficientCommitmentMaterialRecords must provide full public commitment material for private VSS verification",
    ) {
        Ok(material_records) => material_records,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let coefficient_commitments = match verify_coefficient_commitment_material_records(
        material_records,
        setup_context,
        public_matrix_seed_hash,
        &source_trustee_binding,
    )? {
        Ok(coefficient_commitments) => coefficient_commitments,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let envelope_binding = match verify_private_envelope_header(
        private_envelope,
        setup_context,
        public_matrix_seed_hash,
        &source_trustee_binding,
    )? {
        Ok(envelope_binding) => envelope_binding,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let limb_verifications = match verify_private_envelope_limbs(
        private_envelope,
        request.get("transportedPrivateVssShareProofMaterial"),
        setup_context,
        public_matrix_seed_hash,
        &source_trustee_binding,
        &coefficient_commitments,
        &envelope_binding,
    )? {
        Ok(limb_verifications) => limb_verifications,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let ring_degree = limb_verifications
        .first()
        .map(|verification| verification.ring_degree)
        .unwrap_or(0);
    let ring_degree_status = if ring_degree == POLYNOMIAL_DEGREE {
        "profile-ring"
    } else {
        "development-reduced-ring"
    };

    let local_verification_record = local_verification_record(
        setup_context,
        public_matrix_seed_hash,
        &source_trustee_binding,
        &envelope_binding,
        ring_degree,
        ring_degree_status,
        &limb_verifications,
    )?;
    let local_verification_root = derive_protocol_hash(
        "PrivateVssLocalVerificationRoot",
        &local_verification_record,
    )?;

    if let Some(expected_private_envelope_hash) = request
        .get("expectedPrivateEnvelopeHash")
        .and_then(Value::as_str)
    {
        validate_hash_string(
            expected_private_envelope_hash,
            "expectedPrivateEnvelopeHash",
        )?;
        if expected_private_envelope_hash != envelope_binding.private_envelope_hash {
            return Ok(Err(PrivateVssRefusal::new(
                "expectedPrivateEnvelopeHashMismatch",
                "computed private envelope hash does not match expectedPrivateEnvelopeHash",
                "expectedPrivateEnvelopeHash",
            )));
        }
    }
    if let Some(expected_local_verification_root) = request
        .get("expectedLocalVerificationRoot")
        .and_then(Value::as_str)
    {
        validate_hash_string(
            expected_local_verification_root,
            "expectedLocalVerificationRoot",
        )?;
        if expected_local_verification_root != local_verification_root {
            return Ok(Err(PrivateVssRefusal::new(
                "expectedLocalVerificationRootMismatch",
                "computed private VSS local verification root does not match expectedLocalVerificationRoot",
                "expectedLocalVerificationRoot",
            )));
        }
    }

    let mut response = verification_response(
        true,
        "accepted",
        Some(envelope_binding.private_envelope_hash),
        Some(local_verification_root),
        limb_verifications
            .into_iter()
            .map(limb_verification_value)
            .collect(),
        Vec::new(),
    );
    response["ringDegree"] = json!(ring_degree);
    response["ringDegreeStatus"] = json!(ring_degree_status);
    response["verifiedRnsLimbCount"] = json!(DATA_PRIMES.len());
    response["verifiedShamirCoefficientCommitmentCount"] =
        json!(DATA_PRIMES.len() * FIRST_PROFILE_DECRYPTION_THRESHOLD);
    response["verifiedPrivateVssShareProofCount"] = json!(DATA_PRIMES.len());

    Ok(Ok(response))
}

fn verify_setup_context(setup_context: &Value) -> CanonicalResult<Result<(), PrivateVssRefusal>> {
    for field_name in setup_context_field_names() {
        if setup_context.get(field_name).is_none() {
            return Ok(Err(PrivateVssRefusal::new(
                "setupContextFieldMissing",
                format!("setupContext.{field_name} is required"),
                format!("setupContext.{field_name}"),
            )));
        }
    }
    for field_name in [
        "manifestHash",
        "rosterHash",
        "setupProfileHash",
        "qShareHash",
        "carryAwareVssShareRelationProfileHash",
        "commitmentProfileHash",
    ] {
        let hash = match hash_string_field(
            setup_context,
            field_name,
            &format!("setupContext.{field_name}"),
            "setupContextHashMalformed",
            format!("setupContext.{field_name} must be a protocol hash"),
        ) {
            Ok(hash) => hash,
            Err(refusal) => return Ok(Err(refusal)),
        };
        validate_hash_string(hash, &format!("setupContext.{field_name}"))?;
    }
    if string_field(
        setup_context,
        "ceremonyId",
        "setupContext.ceremonyId",
        "setupContextCeremonyMissing",
        "setupContext.ceremonyId must be a non-empty string",
    )
    .is_err()
    {
        return Ok(Err(PrivateVssRefusal::new(
            "setupContextCeremonyMissing",
            "setupContext.ceremonyId must be a non-empty string",
            "setupContext.ceremonyId",
        )));
    }
    if string_field(
        setup_context,
        "setupEpoch",
        "setupContext.setupEpoch",
        "setupContextEpochMissing",
        "setupContext.setupEpoch must be a non-empty string",
    )
    .is_err()
    {
        return Ok(Err(PrivateVssRefusal::new(
            "setupContextEpochMissing",
            "setupContext.setupEpoch must be a non-empty string",
            "setupContext.setupEpoch",
        )));
    }

    if setup_context
        .get("setupProfileHash")
        .and_then(Value::as_str)
        != Some(accepted_setup_profile_hash()?.as_str())
    {
        return Ok(Err(PrivateVssRefusal::new(
            "setupProfileHashMismatch",
            "setupContext.setupProfileHash does not match CollectiveBgvSetup-v1",
            "setupContext.setupProfileHash",
        )));
    }
    if setup_context.get("qShareHash").and_then(Value::as_str)
        != Some(accepted_q_share_hash()?.as_str())
    {
        return Ok(Err(PrivateVssRefusal::new(
            "qShareHashMismatch",
            "setupContext.qShareHash does not match the accepted Q_share prime list",
            "setupContext.qShareHash",
        )));
    }
    if setup_context
        .get("carryAwareVssShareRelationProfileHash")
        .and_then(Value::as_str)
        != Some(carry_aware_vss_share_relation_profile_hash()?.as_str())
    {
        return Ok(Err(PrivateVssRefusal::new(
            "carryAwareVssRelationProfileHashMismatch",
            "setupContext.carryAwareVssShareRelationProfileHash does not match the accepted carry-aware VSS relation profile",
            "setupContext.carryAwareVssShareRelationProfileHash",
        )));
    }
    if setup_context
        .get("commitmentProfileHash")
        .and_then(Value::as_str)
        != Some(setup_commitment_profile_hash()?.as_str())
    {
        return Ok(Err(PrivateVssRefusal::new(
            "commitmentProfileHashMismatch",
            "setupContext.commitmentProfileHash does not match the accepted setup commitment profile",
            "setupContext.commitmentProfileHash",
        )));
    }

    Ok(Ok(()))
}

fn verify_source_trustee_commitment_record(
    source_trustee_record: &Value,
    setup_context: &Value,
    public_matrix_seed_hash: &str,
) -> CanonicalResult<Result<SourceTrusteeCommitmentBinding, PrivateVssRefusal>> {
    if source_trustee_record
        .get("objectType")
        .and_then(Value::as_str)
        != Some(VSS_SOURCE_TRUSTEE_COMMITMENT_OBJECT_TYPE)
    {
        return Ok(Err(PrivateVssRefusal::new(
            "sourceTrusteeCommitmentRecordTypeMismatch",
            "sourceTrusteeCoefficientCommitmentRecord.objectType must be VssSourceTrusteeCoefficientCommitments",
            "sourceTrusteeCoefficientCommitmentRecord.objectType",
        )));
    }
    if source_trustee_record
        .get("objectVersion")
        .and_then(Value::as_u64)
        != Some(1)
    {
        return Ok(Err(PrivateVssRefusal::new(
            "sourceTrusteeCommitmentRecordVersionMismatch",
            "sourceTrusteeCoefficientCommitmentRecord.objectVersion must be 1",
            "sourceTrusteeCoefficientCommitmentRecord.objectVersion",
        )));
    }
    if let Err(refusal) = compare_context_fields(
        source_trustee_record,
        setup_context,
        "sourceTrusteeCoefficientCommitmentRecord",
    ) {
        return Ok(Err(refusal));
    }
    if source_trustee_record
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(public_matrix_seed_hash)
    {
        return Ok(Err(PrivateVssRefusal::new(
            "sourceTrusteeCommitmentPublicMatrixSeedMismatch",
            "sourceTrusteeCoefficientCommitmentRecord.publicMatrixSeedHash must match publicMatrixSeedHash",
            "sourceTrusteeCoefficientCommitmentRecord.publicMatrixSeedHash",
        )));
    }
    let source_trustee_identity = match string_field(
        source_trustee_record,
        "sourceTrusteeIdentity",
        "sourceTrusteeCoefficientCommitmentRecord.sourceTrusteeIdentity",
        "sourceTrusteeIdentityMissing",
        "sourceTrusteeCoefficientCommitmentRecord.sourceTrusteeIdentity is required",
    ) {
        Ok(source_trustee_identity) => source_trustee_identity.to_string(),
        Err(refusal) => return Ok(Err(refusal)),
    };
    let source_trustee_roster_position = match u64_field(
        source_trustee_record,
        "sourceTrusteeRosterPosition",
        "sourceTrusteeCoefficientCommitmentRecord.sourceTrusteeRosterPosition",
        "sourceTrusteeRosterPositionMissing",
        "sourceTrusteeCoefficientCommitmentRecord.sourceTrusteeRosterPosition is required",
    ) {
        Ok(source_trustee_roster_position) => source_trustee_roster_position,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let coefficient_commitments = match array_field(
        source_trustee_record,
        "coefficientCommitments",
        "sourceTrusteeCoefficientCommitmentRecord.coefficientCommitments",
        "sourceTrusteeCoefficientCommitmentsMissing",
        "sourceTrusteeCoefficientCommitmentRecord.coefficientCommitments is required",
    ) {
        Ok(coefficient_commitments) => coefficient_commitments,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let expected_coefficient_count = DATA_PRIMES.len() * FIRST_PROFILE_DECRYPTION_THRESHOLD;
    if coefficient_commitments.len() != expected_coefficient_count {
        return Ok(Err(PrivateVssRefusal::new(
            "sourceTrusteeCoefficientCommitmentCountMismatch",
            "sourceTrusteeCoefficientCommitmentRecord.coefficientCommitments must contain every Q_share limb and Shamir coefficient",
            "sourceTrusteeCoefficientCommitmentRecord.coefficientCommitments",
        )));
    }

    let mut seen_coordinates = BTreeSet::new();
    let mut coefficient_commitment_roots = BTreeMap::new();
    for coefficient_record in coefficient_commitments {
        let rns_limb_index = match usize_field(
            coefficient_record,
            "rnsLimbIndex",
            "sourceTrusteeCoefficientCommitmentRecord.coefficientCommitments.rnsLimbIndex",
            "sourceTrusteeCoefficientRnsLimbMissing",
            "source trustee coefficient commitment must bind rnsLimbIndex",
        ) {
            Ok(rns_limb_index) => rns_limb_index,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let rns_prime = match u64_field(
            coefficient_record,
            "rnsPrime",
            "sourceTrusteeCoefficientCommitmentRecord.coefficientCommitments.rnsPrime",
            "sourceTrusteeCoefficientRnsPrimeMissing",
            "source trustee coefficient commitment must bind rnsPrime",
        ) {
            Ok(rns_prime) => rns_prime,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if DATA_PRIMES.get(rns_limb_index) != Some(&rns_prime) {
            return Ok(Err(PrivateVssRefusal::new(
                "sourceTrusteeCoefficientRnsPrimeMismatch",
                "source trustee coefficient commitment rnsPrime must match Q_share at rnsLimbIndex",
                "sourceTrusteeCoefficientCommitmentRecord.coefficientCommitments.rnsPrime",
            )));
        }
        let shamir_coefficient_index = match u64_field(
            coefficient_record,
            "shamirCoefficientIndex",
            "sourceTrusteeCoefficientCommitmentRecord.coefficientCommitments.shamirCoefficientIndex",
            "sourceTrusteeCoefficientShamirIndexMissing",
            "source trustee coefficient commitment must bind shamirCoefficientIndex",
        ) {
            Ok(shamir_coefficient_index) => shamir_coefficient_index,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if shamir_coefficient_index >= FIRST_PROFILE_DECRYPTION_THRESHOLD as u64 {
            return Ok(Err(PrivateVssRefusal::new(
                "sourceTrusteeCoefficientShamirIndexInvalid",
                "source trustee coefficient commitment shamirCoefficientIndex is outside the accepted threshold degree",
                "sourceTrusteeCoefficientCommitmentRecord.coefficientCommitments.shamirCoefficientIndex",
            )));
        }
        if !seen_coordinates.insert((rns_limb_index, shamir_coefficient_index)) {
            return Ok(Err(PrivateVssRefusal::new(
                "sourceTrusteeCoefficientCommitmentDuplicate",
                "source trustee coefficient commitments must have distinct limb/coefficient coordinates",
                "sourceTrusteeCoefficientCommitmentRecord.coefficientCommitments",
            )));
        }
        let commitment_root = match hash_string_field(
            coefficient_record,
            "commitmentRoot",
            "sourceTrusteeCoefficientCommitmentRecord.coefficientCommitments.commitmentRoot",
            "sourceTrusteeCoefficientCommitmentRootMissing",
            "source trustee coefficient commitment must bind commitmentRoot",
        ) {
            Ok(commitment_root) => commitment_root.to_string(),
            Err(refusal) => return Ok(Err(refusal)),
        };
        coefficient_commitment_roots
            .insert((rns_limb_index, shamir_coefficient_index), commitment_root);
    }

    let source_trustee_commitment_root = match hash_string_field(
        source_trustee_record,
        "sourceTrusteeCommitmentRoot",
        "sourceTrusteeCoefficientCommitmentRecord.sourceTrusteeCommitmentRoot",
        "sourceTrusteeCommitmentRootMissing",
        "sourceTrusteeCoefficientCommitmentRecord.sourceTrusteeCommitmentRoot is required",
    ) {
        Ok(source_trustee_commitment_root) => source_trustee_commitment_root.to_string(),
        Err(refusal) => return Ok(Err(refusal)),
    };
    let mut root_input = source_trustee_record.clone();
    root_input
        .as_object_mut()
        .expect("source trustee commitment record object was checked")
        .remove("sourceTrusteeCommitmentRoot");
    let expected_source_trustee_commitment_root =
        derive_protocol_hash("VssCoefficientCommitmentRoot", &root_input)?;
    if source_trustee_commitment_root != expected_source_trustee_commitment_root {
        return Ok(Err(PrivateVssRefusal::new(
            "sourceTrusteeCommitmentRootMismatch",
            "sourceTrusteeCommitmentRoot does not match the canonical source trustee coefficient commitment record",
            "sourceTrusteeCoefficientCommitmentRecord.sourceTrusteeCommitmentRoot",
        )));
    }

    Ok(Ok(SourceTrusteeCommitmentBinding {
        source_trustee_identity,
        source_trustee_roster_position,
        source_trustee_commitment_root,
        coefficient_commitment_roots,
    }))
}

fn verify_coefficient_commitment_material_records(
    material_records: &[Value],
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    source_trustee_binding: &SourceTrusteeCommitmentBinding,
) -> CanonicalResult<CoefficientCommitmentMaterialRecordsVerification> {
    let expected_coefficient_count = DATA_PRIMES.len() * FIRST_PROFILE_DECRYPTION_THRESHOLD;
    if material_records.len() != expected_coefficient_count {
        return Ok(Err(PrivateVssRefusal::new(
            "sourceTrusteeCommitmentMaterialCountMismatch",
            "sourceTrusteeCoefficientCommitmentMaterialRecords must contain full public commitment material for every Q_share limb and Shamir coefficient",
            "sourceTrusteeCoefficientCommitmentMaterialRecords",
        )));
    }

    let mut bindings = BTreeMap::new();
    for material_record in material_records {
        let binding = match verify_coefficient_commitment_material_record(
            material_record,
            setup_context,
            public_matrix_seed_hash,
            source_trustee_binding,
        )? {
            Ok(binding) => binding,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let coordinate = (
            binding.commitment.source_rns_limb_index,
            binding.commitment.shamir_coefficient_index,
        );
        if bindings.insert(coordinate, binding).is_some() {
            return Ok(Err(PrivateVssRefusal::new(
                "sourceTrusteeCommitmentMaterialDuplicate",
                "sourceTrusteeCoefficientCommitmentMaterialRecords must have distinct limb/coefficient coordinates",
                "sourceTrusteeCoefficientCommitmentMaterialRecords",
            )));
        }
    }

    for rns_limb_index in 0..DATA_PRIMES.len() {
        for shamir_coefficient_index in 0..FIRST_PROFILE_DECRYPTION_THRESHOLD as u64 {
            if !bindings.contains_key(&(rns_limb_index, shamir_coefficient_index)) {
                return Ok(Err(PrivateVssRefusal::new(
                    "sourceTrusteeCommitmentMaterialCoverageMismatch",
                    "sourceTrusteeCoefficientCommitmentMaterialRecords must cover every Q_share limb and Shamir coefficient",
                    "sourceTrusteeCoefficientCommitmentMaterialRecords",
                )));
            }
        }
    }

    Ok(Ok(bindings))
}

fn verify_coefficient_commitment_material_record(
    material_record: &Value,
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    source_trustee_binding: &SourceTrusteeCommitmentBinding,
) -> CanonicalResult<Result<CoefficientCommitmentBinding, PrivateVssRefusal>> {
    if material_record.get("objectType").and_then(Value::as_str)
        != Some(VSS_COEFFICIENT_COMMITMENT_MATERIAL_OBJECT_TYPE)
    {
        return Ok(Err(PrivateVssRefusal::new(
            "sourceTrusteeCommitmentMaterialTypeMismatch",
            "coefficient commitment material objectType must be VssCoefficientCommitmentMaterial",
            "sourceTrusteeCoefficientCommitmentMaterialRecords.objectType",
        )));
    }
    if material_record.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Err(PrivateVssRefusal::new(
            "sourceTrusteeCommitmentMaterialVersionMismatch",
            "coefficient commitment material objectVersion must be 1",
            "sourceTrusteeCoefficientCommitmentMaterialRecords.objectVersion",
        )));
    }
    if let Err(refusal) = compare_context_fields(
        material_record,
        setup_context,
        "sourceTrusteeCoefficientCommitmentMaterialRecords",
    ) {
        return Ok(Err(refusal));
    }
    if material_record
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(public_matrix_seed_hash)
    {
        return Ok(Err(PrivateVssRefusal::new(
            "sourceTrusteeCommitmentMaterialPublicMatrixSeedMismatch",
            "coefficient commitment material publicMatrixSeedHash must match publicMatrixSeedHash",
            "sourceTrusteeCoefficientCommitmentMaterialRecords.publicMatrixSeedHash",
        )));
    }
    if material_record
        .get("sourceTrusteeIdentity")
        .and_then(Value::as_str)
        != Some(source_trustee_binding.source_trustee_identity.as_str())
        || material_record
            .get("sourceTrusteeRosterPosition")
            .and_then(Value::as_u64)
            != Some(source_trustee_binding.source_trustee_roster_position)
    {
        return Ok(Err(PrivateVssRefusal::new(
            "sourceTrusteeCommitmentMaterialSourceTrusteeMismatch",
            "coefficient commitment material source trustee binding must match sourceTrusteeCoefficientCommitmentRecord",
            "sourceTrusteeCoefficientCommitmentMaterialRecords.sourceTrusteeIdentity",
        )));
    }

    let rns_limb_index = match usize_field(
        material_record,
        "rnsLimbIndex",
        "sourceTrusteeCoefficientCommitmentMaterialRecords.rnsLimbIndex",
        "sourceTrusteeCommitmentMaterialRnsLimbMissing",
        "coefficient commitment material must bind rnsLimbIndex",
    ) {
        Ok(rns_limb_index) => rns_limb_index,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let rns_prime = match u64_field(
        material_record,
        "rnsPrime",
        "sourceTrusteeCoefficientCommitmentMaterialRecords.rnsPrime",
        "sourceTrusteeCommitmentMaterialRnsPrimeMissing",
        "coefficient commitment material must bind rnsPrime",
    ) {
        Ok(rns_prime) => rns_prime,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if DATA_PRIMES.get(rns_limb_index) != Some(&rns_prime) {
        return Ok(Err(PrivateVssRefusal::new(
            "sourceTrusteeCommitmentMaterialRnsPrimeMismatch",
            "coefficient commitment material rnsPrime must match Q_share at rnsLimbIndex",
            "sourceTrusteeCoefficientCommitmentMaterialRecords.rnsPrime",
        )));
    }
    let shamir_coefficient_index = match u64_field(
        material_record,
        "shamirCoefficientIndex",
        "sourceTrusteeCoefficientCommitmentMaterialRecords.shamirCoefficientIndex",
        "sourceTrusteeCommitmentMaterialShamirIndexMissing",
        "coefficient commitment material must bind shamirCoefficientIndex",
    ) {
        Ok(shamir_coefficient_index) => shamir_coefficient_index,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if shamir_coefficient_index >= FIRST_PROFILE_DECRYPTION_THRESHOLD as u64 {
        return Ok(Err(PrivateVssRefusal::new(
            "sourceTrusteeCommitmentMaterialShamirIndexInvalid",
            "coefficient commitment material shamirCoefficientIndex is outside the accepted threshold degree",
            "sourceTrusteeCoefficientCommitmentMaterialRecords.shamirCoefficientIndex",
        )));
    }
    let commitment_root = match hash_string_field(
        material_record,
        "commitmentRoot",
        "sourceTrusteeCoefficientCommitmentMaterialRecords.commitmentRoot",
        "sourceTrusteeCommitmentMaterialRootMissing",
        "coefficient commitment material must bind commitmentRoot",
    ) {
        Ok(commitment_root) => commitment_root.to_string(),
        Err(refusal) => return Ok(Err(refusal)),
    };
    if source_trustee_binding
        .coefficient_commitment_roots
        .get(&(rns_limb_index, shamir_coefficient_index))
        .map(String::as_str)
        != Some(commitment_root.as_str())
    {
        return Ok(Err(PrivateVssRefusal::new(
            "sourceTrusteeCommitmentMaterialRootMismatch",
            "coefficient commitment material root must match the source trustee coefficient commitment record",
            "sourceTrusteeCoefficientCommitmentMaterialRecords.commitmentRoot",
        )));
    }
    let commitment_value = match object_field(
        material_record,
        "commitment",
        "sourceTrusteeCoefficientCommitmentMaterialRecords.commitment",
        "sourceTrusteeCommitmentMaterialCommitmentMissing",
        "coefficient commitment material must include the full public commitment",
    ) {
        Ok(commitment_value) => commitment_value,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let commitment = match parse_setup_commitment_full_value(commitment_value) {
        Ok(commitment) => commitment,
        Err(error) => {
            return Ok(Err(PrivateVssRefusal::new(
                "sourceTrusteeCommitmentMaterialInvalid",
                error.message,
                "sourceTrusteeCoefficientCommitmentMaterialRecords.commitment",
            )));
        }
    };
    if commitment.source_rns_limb_index != rns_limb_index
        || commitment.source_message_modulus != rns_prime
        || commitment.shamir_coefficient_index != shamir_coefficient_index
    {
        return Ok(Err(PrivateVssRefusal::new(
            "sourceTrusteeCommitmentMaterialDomainMismatch",
            "full setup commitment domain must match its material wrapper",
            "sourceTrusteeCoefficientCommitmentMaterialRecords.commitment",
        )));
    }
    let computed_commitment_root = setup_commitment_root(&commitment)?;
    if commitment_root != computed_commitment_root {
        return Ok(Err(PrivateVssRefusal::new(
            "sourceTrusteeCommitmentMaterialRootMismatch",
            "full setup commitment material does not match commitmentRoot",
            "sourceTrusteeCoefficientCommitmentMaterialRecords.commitment",
        )));
    }

    Ok(Ok(CoefficientCommitmentBinding {
        commitment_root,
        commitment,
    }))
}

fn verify_private_envelope_header(
    private_envelope: &Value,
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    source_trustee_binding: &SourceTrusteeCommitmentBinding,
) -> CanonicalResult<Result<PrivateEnvelopeBinding, PrivateVssRefusal>> {
    if private_envelope.get("objectType").and_then(Value::as_str)
        != Some(PRIVATE_VSS_ENVELOPE_OBJECT_TYPE)
    {
        return Ok(Err(PrivateVssRefusal::new(
            "privateEnvelopeTypeMismatch",
            "privateEnvelope.objectType must be PrivateVssShareEnvelope",
            "privateEnvelope.objectType",
        )));
    }
    if private_envelope
        .get("objectVersion")
        .and_then(Value::as_u64)
        != Some(1)
    {
        return Ok(Err(PrivateVssRefusal::new(
            "privateEnvelopeVersionMismatch",
            "privateEnvelope.objectVersion must be 1",
            "privateEnvelope.objectVersion",
        )));
    }
    if let Some((field_name, object_path)) =
        find_private_vss_coefficient_leakage(private_envelope, "privateEnvelope")
    {
        return Ok(Err(PrivateVssRefusal::new(
            "privateVssEnvelopeLeaksCoefficientOpening",
            format!("private VSS envelope must not include {field_name}"),
            object_path,
        )));
    }
    if let Some((reason_code, field_name, object_path)) =
        find_private_vss_plaintext_witness_leakage(private_envelope, "privateEnvelope")
    {
        return Ok(Err(PrivateVssRefusal::new(
            reason_code,
            format!(
                "private VSS envelope must not disclose {field_name}; it must be a proof witness"
            ),
            object_path,
        )));
    }
    if let Err(refusal) = reject_unexpected_fields(
        private_envelope,
        &[
            "objectType",
            "objectVersion",
            "ceremonyId",
            "manifestHash",
            "rosterHash",
            "setupProfileHash",
            "qShareHash",
            "carryAwareVssShareRelationProfileHash",
            "commitmentProfileHash",
            "setupEpoch",
            "publicMatrixSeedHash",
            "privateEnvelopeAadHash",
            "sourceTrusteeIdentity",
            "sourceTrusteeRosterPosition",
            "recipientIdentity",
            "recipientRosterPosition",
            "sourceTrusteeCommitmentRoot",
            "rnsShareOpenings",
        ],
        "privateEnvelope",
    ) {
        return Ok(Err(refusal));
    }
    if let Err(refusal) = compare_context_fields(private_envelope, setup_context, "privateEnvelope")
    {
        return Ok(Err(refusal));
    }
    if private_envelope
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(public_matrix_seed_hash)
    {
        return Ok(Err(PrivateVssRefusal::new(
            "privateEnvelopePublicMatrixSeedMismatch",
            "privateEnvelope.publicMatrixSeedHash must match publicMatrixSeedHash",
            "privateEnvelope.publicMatrixSeedHash",
        )));
    }

    let source_trustee_identity = match string_field(
        private_envelope,
        "sourceTrusteeIdentity",
        "privateEnvelope.sourceTrusteeIdentity",
        "privateEnvelopeSourceTrusteeMissing",
        "privateEnvelope.sourceTrusteeIdentity is required",
    ) {
        Ok(source_trustee_identity) => source_trustee_identity.to_string(),
        Err(refusal) => return Ok(Err(refusal)),
    };
    let source_trustee_roster_position = match u64_field(
        private_envelope,
        "sourceTrusteeRosterPosition",
        "privateEnvelope.sourceTrusteeRosterPosition",
        "privateEnvelopeSourceTrusteePositionMissing",
        "privateEnvelope.sourceTrusteeRosterPosition is required",
    ) {
        Ok(source_trustee_roster_position) => source_trustee_roster_position,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if source_trustee_identity != source_trustee_binding.source_trustee_identity
        || source_trustee_roster_position != source_trustee_binding.source_trustee_roster_position
    {
        return Ok(Err(PrivateVssRefusal::new(
            "privateEnvelopeSourceTrusteeMismatch",
            "privateEnvelope source trustee binding must match sourceTrusteeCoefficientCommitmentRecord",
            "privateEnvelope.sourceTrusteeIdentity",
        )));
    }
    if private_envelope
        .get("sourceTrusteeCommitmentRoot")
        .and_then(Value::as_str)
        != Some(
            source_trustee_binding
                .source_trustee_commitment_root
                .as_str(),
        )
    {
        return Ok(Err(PrivateVssRefusal::new(
            "privateEnvelopeSourceTrusteeCommitmentRootMismatch",
            "privateEnvelope.sourceTrusteeCommitmentRoot must match the accepted source trustee commitment root",
            "privateEnvelope.sourceTrusteeCommitmentRoot",
        )));
    }

    let recipient_identity = match string_field(
        private_envelope,
        "recipientIdentity",
        "privateEnvelope.recipientIdentity",
        "privateEnvelopeRecipientMissing",
        "privateEnvelope.recipientIdentity is required",
    ) {
        Ok(recipient_identity) => recipient_identity.to_string(),
        Err(refusal) => return Ok(Err(refusal)),
    };
    let recipient_roster_position = match u64_field(
        private_envelope,
        "recipientRosterPosition",
        "privateEnvelope.recipientRosterPosition",
        "privateEnvelopeRecipientPositionMissing",
        "privateEnvelope.recipientRosterPosition is required",
    ) {
        Ok(recipient_roster_position) => recipient_roster_position,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if recipient_roster_position >= 10 {
        return Ok(Err(PrivateVssRefusal::new(
            "privateEnvelopeRecipientPositionInvalid",
            "privateEnvelope.recipientRosterPosition is outside the first accepted profile roster",
            "privateEnvelope.recipientRosterPosition",
        )));
    }
    let private_envelope_aad_hash = match hash_string_field(
        private_envelope,
        "privateEnvelopeAadHash",
        "privateEnvelope.privateEnvelopeAadHash",
        "privateEnvelopeAadHashMissing",
        "privateEnvelope.privateEnvelopeAadHash is required",
    ) {
        Ok(private_envelope_aad_hash) => private_envelope_aad_hash.to_string(),
        Err(refusal) => return Ok(Err(refusal)),
    };
    validate_hash_string(
        &private_envelope_aad_hash,
        "privateEnvelope.privateEnvelopeAadHash",
    )?;
    let private_envelope_hash =
        derive_protocol_hash("PrivateVssShareEnvelopeHash", private_envelope)?;

    Ok(Ok(PrivateEnvelopeBinding {
        private_envelope_hash,
        private_envelope_aad_hash,
        recipient_identity,
        recipient_roster_position,
    }))
}

fn verify_private_envelope_limbs(
    private_envelope: &Value,
    transported_proof_material: Option<&Value>,
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    source_trustee_binding: &SourceTrusteeCommitmentBinding,
    coefficient_commitments: &BTreeMap<(usize, u64), CoefficientCommitmentBinding>,
    envelope_binding: &PrivateEnvelopeBinding,
) -> CanonicalResult<Result<Vec<LimbVerification>, PrivateVssRefusal>> {
    let rns_share_openings = match array_field(
        private_envelope,
        "rnsShareOpenings",
        "privateEnvelope.rnsShareOpenings",
        "privateEnvelopeOpeningsMissing",
        "privateEnvelope.rnsShareOpenings is required",
    ) {
        Ok(rns_share_openings) => rns_share_openings,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if rns_share_openings.len() != DATA_PRIMES.len() {
        return Ok(Err(PrivateVssRefusal::new(
            "privateEnvelopeRnsOpeningCountMismatch",
            "privateEnvelope.rnsShareOpenings must contain one opening for every accepted Q_share limb",
            "privateEnvelope.rnsShareOpenings",
        )));
    }

    let mut seen_limbs = BTreeSet::new();
    let mut ring_degree: Option<usize> = None;
    let mut limb_verifications = Vec::with_capacity(DATA_PRIMES.len());
    for limb_opening in rns_share_openings {
        let limb_verification = match verify_private_envelope_limb(
            limb_opening,
            transported_proof_material,
            setup_context,
            public_matrix_seed_hash,
            source_trustee_binding,
            coefficient_commitments,
            envelope_binding,
        )? {
            Ok(limb_verification) => limb_verification,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if !seen_limbs.insert(limb_verification.rns_limb_index) {
            return Ok(Err(PrivateVssRefusal::new(
                "privateEnvelopeRnsOpeningDuplicate",
                "privateEnvelope.rnsShareOpenings must have distinct rnsLimbIndex values",
                "privateEnvelope.rnsShareOpenings",
            )));
        }
        match ring_degree {
            Some(expected_ring_degree) if expected_ring_degree != limb_verification.ring_degree => {
                return Ok(Err(PrivateVssRefusal::new(
                    "privateEnvelopeRingDegreeMismatch",
                    "all private VSS limb openings must use the same ring degree",
                    "privateEnvelope.rnsShareOpenings",
                )));
            }
            Some(_) => {}
            None => ring_degree = Some(limb_verification.ring_degree),
        }
        limb_verifications.push(limb_verification);
    }
    limb_verifications.sort_by_key(|verification| verification.rns_limb_index);

    Ok(Ok(limb_verifications))
}

fn verify_private_envelope_limb(
    limb_opening: &Value,
    transported_proof_material: Option<&Value>,
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    source_trustee_binding: &SourceTrusteeCommitmentBinding,
    coefficient_commitments: &BTreeMap<(usize, u64), CoefficientCommitmentBinding>,
    envelope_binding: &PrivateEnvelopeBinding,
) -> CanonicalResult<Result<LimbVerification, PrivateVssRefusal>> {
    if limb_opening.get("objectType").and_then(Value::as_str)
        != Some(PRIVATE_VSS_LIMB_OPENING_OBJECT_TYPE)
    {
        return Ok(Err(PrivateVssRefusal::new(
            "privateVssLimbOpeningTypeMismatch",
            "private VSS limb opening objectType must be PrivateVssShareLimbOpening",
            "privateEnvelope.rnsShareOpenings.objectType",
        )));
    }
    if limb_opening.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Err(PrivateVssRefusal::new(
            "privateVssLimbOpeningVersionMismatch",
            "private VSS limb opening objectVersion must be 1",
            "privateEnvelope.rnsShareOpenings.objectVersion",
        )));
    }
    if let Err(refusal) = reject_unexpected_fields(
        limb_opening,
        &[
            "objectType",
            "objectVersion",
            "rnsLimbIndex",
            "rnsPrime",
            "shareValues",
            "coefficientCommitmentRoots",
            "privateVssShareProof",
        ],
        "privateEnvelope.rnsShareOpenings",
    ) {
        return Ok(Err(refusal));
    }
    let rns_limb_index = match usize_field(
        limb_opening,
        "rnsLimbIndex",
        "privateEnvelope.rnsShareOpenings.rnsLimbIndex",
        "privateVssLimbIndexMissing",
        "private VSS limb opening must bind rnsLimbIndex",
    ) {
        Ok(rns_limb_index) => rns_limb_index,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let rns_prime = match u64_field(
        limb_opening,
        "rnsPrime",
        "privateEnvelope.rnsShareOpenings.rnsPrime",
        "privateVssRnsPrimeMissing",
        "private VSS limb opening must bind rnsPrime",
    ) {
        Ok(rns_prime) => rns_prime,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if DATA_PRIMES.get(rns_limb_index) != Some(&rns_prime) {
        return Ok(Err(PrivateVssRefusal::new(
            "privateVssRnsPrimeMismatch",
            "private VSS limb opening rnsPrime must match Q_share at rnsLimbIndex",
            "privateEnvelope.rnsShareOpenings.rnsPrime",
        )));
    }

    let share_values = match u64_vector_field(
        limb_opening,
        "shareValues",
        "privateEnvelope.rnsShareOpenings.shareValues",
        "privateVssShareValuesMissing",
        "private VSS limb opening must include shareValues",
    ) {
        Ok(share_values) => share_values,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let ring_degree = share_values.len();
    if ring_degree == 0 {
        return Ok(Err(PrivateVssRefusal::new(
            "privateVssShareValuesEmpty",
            "private VSS share vector must be non-empty",
            "privateEnvelope.rnsShareOpenings.shareValues",
        )));
    }

    let coefficient_commitment_roots = match hash_vector_field(
        limb_opening,
        "coefficientCommitmentRoots",
        "privateEnvelope.rnsShareOpenings.coefficientCommitmentRoots",
        "privateVssCoefficientCommitmentRootsMissing",
        "private VSS limb opening must bind coefficientCommitmentRoots",
    ) {
        Ok(coefficient_commitment_roots) => coefficient_commitment_roots,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if coefficient_commitment_roots.len() != FIRST_PROFILE_DECRYPTION_THRESHOLD {
        return Ok(Err(PrivateVssRefusal::new(
            "privateVssCoefficientCommitmentRootCountMismatch",
            "private VSS limb opening must bind every Shamir coefficient commitment root",
            "privateEnvelope.rnsShareOpenings.coefficientCommitmentRoots",
        )));
    }

    let mut coefficient_commitment_values = Vec::with_capacity(FIRST_PROFILE_DECRYPTION_THRESHOLD);
    for (shamir_coefficient_index, commitment_root) in
        coefficient_commitment_roots.iter().enumerate()
    {
        let shamir_coefficient_index = shamir_coefficient_index as u64;
        if source_trustee_binding
            .coefficient_commitment_roots
            .get(&(rns_limb_index, shamir_coefficient_index))
            .map(String::as_str)
            != Some(commitment_root.as_str())
        {
            return Ok(Err(PrivateVssRefusal::new(
                "privateVssCoefficientCommitmentRootMismatch",
                "private VSS limb coefficientCommitmentRoots must match the public source trustee commitment record",
                "privateEnvelope.rnsShareOpenings.coefficientCommitmentRoots",
            )));
        }
        let Some(material_binding) =
            coefficient_commitments.get(&(rns_limb_index, shamir_coefficient_index))
        else {
            return Ok(Err(PrivateVssRefusal::new(
                "privateVssCoefficientCommitmentMaterialMissing",
                "private VSS limb references coefficient commitment material that was not provided",
                "sourceTrusteeCoefficientCommitmentMaterialRecords",
            )));
        };
        if material_binding.commitment_root != *commitment_root {
            return Ok(Err(PrivateVssRefusal::new(
                "privateVssCoefficientCommitmentMaterialRootMismatch",
                "coefficient commitment material root must match private envelope root reference",
                "sourceTrusteeCoefficientCommitmentMaterialRecords.commitmentRoot",
            )));
        }
        coefficient_commitment_values.push(material_binding.commitment.clone());
    }

    let private_vss_share_proof = match object_field(
        limb_opening,
        "privateVssShareProof",
        "privateEnvelope.rnsShareOpenings.privateVssShareProof",
        "privateVssShareProofMissing",
        "private VSS limb opening must include a recipient-local zero-knowledge privateVssShareProof",
    ) {
        Ok(private_vss_share_proof) => private_vss_share_proof,
        Err(refusal) => return Ok(Err(refusal)),
    };

    let share_values_hash = derive_protocol_hash(
        "PrivateVssLocalVerificationRoot",
        &json!({
            "objectType": "PrivateVssShareValueVector",
            "objectVersion": 1,
            "rnsLimbIndex": rns_limb_index,
            "rnsPrime": rns_prime,
            "shareValues": share_values,
        }),
    )?;
    let proof_verification = match verify_private_vss_share_lnp_relation_proof(
        PrivateVssShareLnpProofVerificationInput {
            setup_context,
            public_matrix_seed_hash,
            private_envelope_aad_hash: &envelope_binding.private_envelope_aad_hash,
            source_trustee_identity: &source_trustee_binding.source_trustee_identity,
            source_trustee_roster_position: source_trustee_binding.source_trustee_roster_position,
            recipient_identity: &envelope_binding.recipient_identity,
            recipient_roster_position: envelope_binding.recipient_roster_position,
            source_trustee_commitment_root: &source_trustee_binding.source_trustee_commitment_root,
            rns_limb_index,
            rns_prime,
            ring_degree,
            coefficient_commitment_roots: &coefficient_commitment_roots,
            share_values: &share_values,
            share_values_hash: &share_values_hash,
            coefficient_commitments: &coefficient_commitment_values,
            proof_record: private_vss_share_proof,
            transported_proof_material,
        },
    ) {
        Ok(verification) => verification,
        Err(error) => {
            return Ok(Err(PrivateVssRefusal::new(
                "privateVssShareProofVerificationFailed",
                error.message,
                "privateEnvelope.rnsShareOpenings.privateVssShareProof",
            )));
        }
    };
    let limb_verification_record = json!({
        "objectType": "PrivateVssLimbVerification",
        "objectVersion": 1,
        "rnsLimbIndex": rns_limb_index,
        "rnsPrime": rns_prime,
        "ringDegree": ring_degree,
        "coefficientCommitmentRoots": coefficient_commitment_roots,
        "shareValuesHash": share_values_hash,
        "privateVssShareProofHash": proof_verification.proof_bytes_hash,
        "proofStatementRoot": proof_verification.proof_statement_root,
        "proofMaterialRoot": proof_verification.proof_material_root,
        "statementHash": proof_verification.statement_hash_hex,
        "relationCommitmentHash": proof_verification.relation_commitment_hash_hex,
        "tboxCommitmentPrefixHash": proof_verification.tbox_commitment_prefix_hash,
        "challenge": proof_verification.challenge,
        "proofSizeBytes": proof_verification.proof_size_bytes,
    });
    let limb_verification_root =
        derive_protocol_hash("PrivateVssLocalVerificationRoot", &limb_verification_record)?;

    Ok(Ok(LimbVerification {
        rns_limb_index,
        rns_prime,
        ring_degree,
        coefficient_commitment_roots,
        share_values_hash,
        private_vss_share_proof_hash: proof_verification.proof_bytes_hash,
        proof_statement_root: proof_verification.proof_statement_root,
        limb_verification_root,
    }))
}

fn local_verification_record(
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    source_trustee_binding: &SourceTrusteeCommitmentBinding,
    envelope_binding: &PrivateEnvelopeBinding,
    ring_degree: usize,
    ring_degree_status: &str,
    limb_verifications: &[LimbVerification],
) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "PrivateVssLocalVerification",
        "objectVersion": 1,
        "ceremonyId": string_field(
            setup_context,
            "ceremonyId",
            "setupContext.ceremonyId",
            "setupContextCeremonyMissing",
            "setupContext.ceremonyId is required",
        ).map_err(refusal_to_error)?,
        "manifestHash": string_field(
            setup_context,
            "manifestHash",
            "setupContext.manifestHash",
            "setupContextHashMissing",
            "setupContext.manifestHash is required",
        ).map_err(refusal_to_error)?,
        "rosterHash": string_field(
            setup_context,
            "rosterHash",
            "setupContext.rosterHash",
            "setupContextHashMissing",
            "setupContext.rosterHash is required",
        ).map_err(refusal_to_error)?,
        "setupProfileHash": string_field(
            setup_context,
            "setupProfileHash",
            "setupContext.setupProfileHash",
            "setupContextHashMissing",
            "setupContext.setupProfileHash is required",
        ).map_err(refusal_to_error)?,
        "qShareHash": string_field(
            setup_context,
            "qShareHash",
            "setupContext.qShareHash",
            "setupContextHashMissing",
            "setupContext.qShareHash is required",
        ).map_err(refusal_to_error)?,
        "carryAwareVssShareRelationProfileHash": string_field(
            setup_context,
            "carryAwareVssShareRelationProfileHash",
            "setupContext.carryAwareVssShareRelationProfileHash",
            "setupContextHashMissing",
            "setupContext.carryAwareVssShareRelationProfileHash is required",
        ).map_err(refusal_to_error)?,
        "commitmentProfileHash": string_field(
            setup_context,
            "commitmentProfileHash",
            "setupContext.commitmentProfileHash",
            "setupContextHashMissing",
            "setupContext.commitmentProfileHash is required",
        ).map_err(refusal_to_error)?,
        "setupEpoch": string_field(
            setup_context,
            "setupEpoch",
            "setupContext.setupEpoch",
            "setupContextEpochMissing",
            "setupContext.setupEpoch is required",
        ).map_err(refusal_to_error)?,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "privateEnvelopeHash": envelope_binding.private_envelope_hash,
        "privateEnvelopeAadHash": envelope_binding.private_envelope_aad_hash,
        "sourceTrusteeIdentity": source_trustee_binding.source_trustee_identity,
        "sourceTrusteeRosterPosition": source_trustee_binding.source_trustee_roster_position,
        "recipientIdentity": envelope_binding.recipient_identity,
        "recipientRosterPosition": envelope_binding.recipient_roster_position,
        "sourceTrusteeCommitmentRoot": source_trustee_binding.source_trustee_commitment_root,
        "ringDegree": ring_degree,
        "ringDegreeStatus": ring_degree_status,
        "verifiedRnsLimbCount": limb_verifications.len(),
        "verifiedShamirCoefficientCommitmentCount": limb_verifications.len() * FIRST_PROFILE_DECRYPTION_THRESHOLD,
        "verifiedPrivateVssShareProofCount": limb_verifications.len(),
        "limbVerificationRoots": limb_verifications
            .iter()
            .map(|verification| verification.limb_verification_root.clone())
            .collect::<Vec<_>>(),
    }))
}

fn limb_verification_value(verification: LimbVerification) -> Value {
    json!({
        "rnsLimbIndex": verification.rns_limb_index,
        "rnsPrime": verification.rns_prime,
        "ringDegree": verification.ring_degree,
        "coefficientCommitmentRoots": verification.coefficient_commitment_roots,
        "shareValuesHash": verification.share_values_hash,
        "privateVssShareProofHash": verification.private_vss_share_proof_hash,
        "proofStatementRoot": verification.proof_statement_root,
        "limbVerificationRoot": verification.limb_verification_root,
    })
}

fn verification_response(
    ok: bool,
    verifier_status: &str,
    private_envelope_hash: Option<String>,
    local_verification_root: Option<String>,
    limb_verifications: Vec<Value>,
    refused_objects: Vec<PrivateVssRefusal>,
) -> Value {
    json!({
        "ok": ok,
        "operation": "verifyPrivateVssShareEnvelope",
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "verifierStatus": verifier_status,
        "privateEnvelopeHash": private_envelope_hash,
        "localVerificationRoot": local_verification_root,
        "limbVerifications": limb_verifications,
        "refusedObjects": refused_objects
            .into_iter()
            .map(|refusal| refusal.to_value())
            .collect::<Vec<_>>(),
    })
}

fn compare_context_fields(
    value: &Value,
    setup_context: &Value,
    object_path: &str,
) -> Result<(), PrivateVssRefusal> {
    for field_name in setup_context_field_names() {
        if value.get(field_name) != setup_context.get(field_name) {
            return Err(PrivateVssRefusal::new(
                "privateVssContextMismatch",
                format!("{object_path}.{field_name} must match setupContext"),
                format!("{object_path}.{field_name}"),
            ));
        }
    }

    Ok(())
}

fn find_private_vss_coefficient_leakage(
    value: &Value,
    object_path: &str,
) -> Option<(&'static str, String)> {
    const FORBIDDEN_FIELD_NAMES: [&str; 7] = [
        "coefficientOpenings",
        "coefficientMessage",
        "randomnessByColumn",
        "rawShamirCoefficientValues",
        "rawCoefficientValues",
        "F_i,l,0",
        "F_i,l,k",
    ];

    match value {
        Value::Object(fields) => {
            for (field_name, field_value) in fields {
                let field_path = format!("{object_path}.{field_name}");
                if let Some(forbidden_field_name) = FORBIDDEN_FIELD_NAMES
                    .iter()
                    .copied()
                    .find(|forbidden_field_name| field_name == forbidden_field_name)
                {
                    return Some((forbidden_field_name, field_path));
                }
                if let Some(leakage) =
                    find_private_vss_coefficient_leakage(field_value, &field_path)
                {
                    return Some(leakage);
                }
            }
            None
        }
        Value::Array(items) => items.iter().enumerate().find_map(|(item_index, item)| {
            find_private_vss_coefficient_leakage(item, &format!("{object_path}.{item_index}"))
        }),
        _ => None,
    }
}

fn find_private_vss_plaintext_witness_leakage(
    value: &Value,
    object_path: &str,
) -> Option<(&'static str, &'static str, String)> {
    const FORBIDDEN_FIELD_NAMES: [(&str, &str); 4] = [
        (
            "aggregateOpening",
            "privateVssEnvelopeLeaksAggregateOpening",
        ),
        (
            "carryWitnessesDecimal",
            "privateVssEnvelopeLeaksCarryWitness",
        ),
        ("carryWitnesses", "privateVssEnvelopeLeaksCarryWitness"),
        (
            "aggregateOpeningColumns",
            "privateVssEnvelopeLeaksAggregateOpening",
        ),
    ];

    match value {
        Value::Object(fields) => {
            for (field_name, field_value) in fields {
                let field_path = format!("{object_path}.{field_name}");
                if let Some((forbidden_field_name, reason_code)) = FORBIDDEN_FIELD_NAMES
                    .iter()
                    .copied()
                    .find(|(forbidden_field_name, _reason_code)| field_name == forbidden_field_name)
                {
                    return Some((reason_code, forbidden_field_name, field_path));
                }
                if let Some(leakage) =
                    find_private_vss_plaintext_witness_leakage(field_value, &field_path)
                {
                    return Some(leakage);
                }
            }
            None
        }
        Value::Array(items) => items.iter().enumerate().find_map(|(item_index, item)| {
            find_private_vss_plaintext_witness_leakage(item, &format!("{object_path}.{item_index}"))
        }),
        _ => None,
    }
}

fn setup_context_field_names() -> [&'static str; 8] {
    [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupProfileHash",
        "qShareHash",
        "carryAwareVssShareRelationProfileHash",
        "commitmentProfileHash",
        "setupEpoch",
    ]
}

fn object_field<'a>(
    value: &'a Value,
    field_name: &str,
    object_path: &str,
    reason_code: &'static str,
    message: impl Into<String>,
) -> Result<&'a Value, PrivateVssRefusal> {
    let Some(field) = value.get(field_name) else {
        return Err(PrivateVssRefusal::new(reason_code, message, object_path));
    };
    if !field.is_object() {
        return Err(PrivateVssRefusal::new(
            reason_code,
            format!("{object_path} must be a JSON object"),
            object_path,
        ));
    }

    Ok(field)
}

fn array_field<'a>(
    value: &'a Value,
    field_name: &str,
    object_path: &str,
    reason_code: &'static str,
    message: impl Into<String>,
) -> Result<&'a Vec<Value>, PrivateVssRefusal> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| PrivateVssRefusal::new(reason_code, message, object_path))
}

fn string_field<'a>(
    value: &'a Value,
    field_name: &str,
    object_path: &str,
    reason_code: &'static str,
    message: impl Into<String>,
) -> Result<&'a str, PrivateVssRefusal> {
    value
        .get(field_name)
        .and_then(Value::as_str)
        .filter(|field| !field.is_empty())
        .ok_or_else(|| PrivateVssRefusal::new(reason_code, message, object_path))
}

fn hash_string_field<'a>(
    value: &'a Value,
    field_name: &str,
    object_path: &str,
    reason_code: &'static str,
    message: impl Into<String>,
) -> Result<&'a str, PrivateVssRefusal> {
    value
        .get(field_name)
        .and_then(Value::as_str)
        .ok_or_else(|| PrivateVssRefusal::new(reason_code, message, object_path))
}

fn u64_field(
    value: &Value,
    field_name: &str,
    object_path: &str,
    reason_code: &'static str,
    message: impl Into<String>,
) -> Result<u64, PrivateVssRefusal> {
    value
        .get(field_name)
        .and_then(Value::as_u64)
        .ok_or_else(|| PrivateVssRefusal::new(reason_code, message, object_path))
}

fn usize_field(
    value: &Value,
    field_name: &str,
    object_path: &str,
    reason_code: &'static str,
    message: impl Into<String>,
) -> Result<usize, PrivateVssRefusal> {
    let field = u64_field(value, field_name, object_path, reason_code, message)?;
    usize::try_from(field).map_err(|_| {
        PrivateVssRefusal::new(
            reason_code,
            format!("{object_path} does not fit usize"),
            object_path,
        )
    })
}

fn u64_vector_field(
    value: &Value,
    field_name: &str,
    object_path: &str,
    reason_code: &'static str,
    message: impl Into<String>,
) -> Result<Vec<u64>, PrivateVssRefusal> {
    let values = array_field(value, field_name, object_path, reason_code, message)?;
    values
        .iter()
        .map(|value| {
            value.as_u64().ok_or_else(|| {
                PrivateVssRefusal::new(
                    reason_code,
                    format!("{object_path} must contain only non-negative integers"),
                    object_path,
                )
            })
        })
        .collect()
}

fn hash_vector_field(
    value: &Value,
    field_name: &str,
    object_path: &str,
    reason_code: &'static str,
    message: impl Into<String>,
) -> Result<Vec<String>, PrivateVssRefusal> {
    let values = array_field(value, field_name, object_path, reason_code, message)?;
    values
        .iter()
        .map(|value| {
            let hash = value.as_str().ok_or_else(|| {
                PrivateVssRefusal::new(
                    reason_code,
                    format!("{object_path} must contain protocol hashes"),
                    object_path,
                )
            })?;
            validate_hash_string(hash, object_path)
                .map_err(|error| PrivateVssRefusal::new(reason_code, error.message, object_path))?;
            Ok(hash.to_string())
        })
        .collect()
}

fn u64_matrix_field(
    value: &Value,
    field_name: &str,
    object_path: &str,
    reason_code: &'static str,
    message: impl Into<String>,
) -> CanonicalResult<Vec<Vec<u64>>> {
    let rows = array_field(value, field_name, object_path, reason_code, message)
        .map_err(private_vss_refusal_to_error)?;
    rows.iter()
        .enumerate()
        .map(|(row_index, row)| {
            row.as_array()
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        format!("{object_path}.{row_index} must be an array"),
                    )
                })?
                .iter()
                .enumerate()
                .map(|(column_index, item)| {
                    item.as_u64().ok_or_else(|| {
                        CanonicalError::new(
                            CanonicalErrorCode::InvalidFixture,
                            format!(
                                "{object_path}.{row_index}.{column_index} must be an unsigned integer"
                            ),
                        )
                    })
                })
                .collect()
        })
        .collect()
}

fn i128_matrix3_field(
    value: &Value,
    field_name: &str,
    object_path: &str,
    reason_code: &'static str,
    message: impl Into<String>,
) -> CanonicalResult<Vec<Vec<Vec<i128>>>> {
    let outer_rows = array_field(value, field_name, object_path, reason_code, message)
        .map_err(private_vss_refusal_to_error)?;
    outer_rows
        .iter()
        .enumerate()
        .map(|(outer_index, middle_value)| {
            let middle_rows = middle_value.as_array().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!("{object_path}.{outer_index} must be an array"),
                )
            })?;
            middle_rows
                .iter()
                .enumerate()
                .map(|(middle_index, inner_value)| {
                    let inner_values = inner_value.as_array().ok_or_else(|| {
                        CanonicalError::new(
                            CanonicalErrorCode::InvalidFixture,
                            format!("{object_path}.{outer_index}.{middle_index} must be an array"),
                        )
                    })?;
                    inner_values
                        .iter()
                        .enumerate()
                        .map(|(inner_index, item)| {
                            decimal_i128_value(item).ok_or_else(|| {
                                CanonicalError::new(
                                    CanonicalErrorCode::InvalidFixture,
                                    format!(
                                        "{object_path}.{outer_index}.{middle_index}.{inner_index} must be a signed integer or decimal string"
                                    ),
                                )
                            })
                        })
                        .collect()
                })
                .collect()
        })
        .collect()
}

fn decimal_i128_value(value: &Value) -> Option<i128> {
    if let Some(value) = value.as_i64() {
        return Some(i128::from(value));
    }
    if let Some(value) = value.as_u64() {
        return Some(i128::from(value));
    }
    value.as_str()?.parse::<i128>().ok()
}

fn derive_private_vss_carry_witnesses(
    rns_prime: u64,
    recipient_roster_position: u64,
    ring_degree: usize,
    share_values: &[u64],
    coefficient_messages_by_shamir_index: &[Vec<u64>],
) -> CanonicalResult<Vec<i128>> {
    if coefficient_messages_by_shamir_index.len() != FIRST_PROFILE_DECRYPTION_THRESHOLD {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "coefficientMessagesByShamirIndex must contain every first-profile Shamir coefficient",
        ));
    }
    if coefficient_messages_by_shamir_index.iter().any(|messages| {
        messages.len() != ring_degree || messages.iter().any(|value| *value >= rns_prime)
    }) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "coefficientMessagesByShamirIndex entries must be canonical Q_share residues with length ringDegree",
        ));
    }
    let trustee_point = canonical_trustee_point(
        usize::try_from(recipient_roster_position).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "recipientRosterPosition does not fit usize",
            )
        })?,
        rns_prime,
    )?;
    let mut trustee_point_powers = Vec::with_capacity(coefficient_messages_by_shamir_index.len());
    let mut trustee_point_power = 1_u128;
    let trustee_point_wide = u128::from(trustee_point);
    for _ in coefficient_messages_by_shamir_index {
        trustee_point_powers.push(trustee_point_power);
        trustee_point_power = trustee_point_power
            .checked_mul(trustee_point_wide)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "private VSS trustee point power overflowed during proof generation",
                )
            })?;
    }
    let modulus_wide = u128::from(rns_prime);
    let mut carry_witnesses = Vec::with_capacity(ring_degree);
    for coefficient_position in 0..ring_degree {
        let unreduced_value = coefficient_messages_by_shamir_index
            .iter()
            .zip(trustee_point_powers.iter())
            .try_fold(0_u128, |accumulated_value, (messages, trustee_power)| {
                let term = u128::from(messages[coefficient_position])
                    .checked_mul(*trustee_power)
                    .ok_or_else(|| {
                        CanonicalError::new(
                            CanonicalErrorCode::InvalidFixture,
                            "private VSS unreduced Shamir term overflowed during proof generation",
                        )
                    })?;
                accumulated_value.checked_add(term).ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "private VSS unreduced Shamir evaluation overflowed during proof generation",
                    )
                })
            })?;
        let reduced_value = u64::try_from(unreduced_value % modulus_wide).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "private VSS reduced share value does not fit u64",
            )
        })?;
        if share_values.get(coefficient_position) != Some(&reduced_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "shareValues do not match the private coefficient witness at coefficient {coefficient_position}"
                ),
            ));
        }
        let carry = unreduced_value / modulus_wide;
        carry_witnesses.push(i128::try_from(carry).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "private VSS carry witness does not fit i128",
            )
        })?);
    }

    Ok(carry_witnesses)
}

fn private_vss_refusal_to_error(refusal: PrivateVssRefusal) -> CanonicalError {
    CanonicalError::new(
        CanonicalErrorCode::InvalidFixture,
        format!("{}: {}", refusal.reason_code, refusal.message),
    )
}

fn reject_unexpected_fields(
    value: &Value,
    allowed_fields: &[&str],
    object_path: &str,
) -> Result<(), PrivateVssRefusal> {
    let Some(fields) = value.as_object() else {
        return Err(PrivateVssRefusal::new(
            "privateVssObjectMalformed",
            format!("{object_path} must be a JSON object"),
            object_path,
        ));
    };
    if let Some(unexpected_field) = fields
        .keys()
        .find(|field_name| !allowed_fields.contains(&field_name.as_str()))
    {
        return Err(PrivateVssRefusal::new(
            "privateVssEnvelopeUnexpectedField",
            format!("{object_path} contains unexpected field {unexpected_field}"),
            format!("{object_path}.{unexpected_field}"),
        ));
    }

    Ok(())
}

fn validate_hash_string(hash: &str, field_name: &str) -> CanonicalResult<()> {
    if hash.len() == 128
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }

    Err(CanonicalError::new(
        CanonicalErrorCode::InvalidFixture,
        format!("{field_name} must be a lowercase 512-bit hex protocol hash"),
    ))
}

fn refusal_to_error(refusal: PrivateVssRefusal) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, refusal.message)
}
