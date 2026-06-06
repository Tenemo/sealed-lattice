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
        SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND, SetupCommitmentValue,
        parse_setup_commitment_full_value, setup_commitment_profile_hash, setup_commitment_root,
    },
    vss::{
        CarryAwareVssAggregateCommitmentOpeningInput, carry_aware_vss_share_relation_profile_hash,
        verify_carry_aware_vss_aggregate_commitment_opening,
    },
};

const PRIVATE_VSS_ENVELOPE_OBJECT_TYPE: &str = "PrivateVssShareEnvelope";
const PRIVATE_VSS_LIMB_OPENING_OBJECT_TYPE: &str = "PrivateVssShareLimbOpening";
const PRIVATE_VSS_AGGREGATE_OPENING_OBJECT_TYPE: &str = "PrivateVssAggregateOpening";
const VSS_DEALER_COMMITMENT_OBJECT_TYPE: &str = "VssDealerCoefficientCommitments";
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

struct DealerCommitmentBinding {
    dealer_identity: String,
    dealer_roster_position: u64,
    dealer_commitment_root: String,
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
    carry_witnesses_hash: String,
    combined_commitment_root: String,
    homomorphic_randomness_bound: i128,
    max_carry_witness_decimal: String,
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
            "dealerCoefficientCommitmentRecord",
            "dealerCoefficientCommitmentMaterialRecords",
            "privateEnvelope",
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
    let dealer_record = match object_field(
        request,
        "dealerCoefficientCommitmentRecord",
        "dealerCoefficientCommitmentRecord",
        "dealerCommitmentRecordMissing",
        "dealerCoefficientCommitmentRecord must be provided for private VSS verification",
    ) {
        Ok(dealer_record) => dealer_record,
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

    let dealer_binding = match verify_dealer_commitment_record(
        dealer_record,
        setup_context,
        public_matrix_seed_hash,
    )? {
        Ok(dealer_binding) => dealer_binding,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let material_records = match array_field(
        request,
        "dealerCoefficientCommitmentMaterialRecords",
        "dealerCoefficientCommitmentMaterialRecords",
        "dealerCommitmentMaterialMissing",
        "dealerCoefficientCommitmentMaterialRecords must provide full public commitment material for private VSS verification",
    ) {
        Ok(material_records) => material_records,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let coefficient_commitments = match verify_coefficient_commitment_material_records(
        material_records,
        setup_context,
        public_matrix_seed_hash,
        &dealer_binding,
    )? {
        Ok(coefficient_commitments) => coefficient_commitments,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let envelope_binding = match verify_private_envelope_header(
        private_envelope,
        setup_context,
        public_matrix_seed_hash,
        &dealer_binding,
    )? {
        Ok(envelope_binding) => envelope_binding,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let limb_verifications = match verify_private_envelope_limbs(
        private_envelope,
        public_matrix_seed_hash,
        &dealer_binding,
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
        &dealer_binding,
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
    response["verifiedAggregateOpeningCount"] = json!(DATA_PRIMES.len());

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

fn verify_dealer_commitment_record(
    dealer_record: &Value,
    setup_context: &Value,
    public_matrix_seed_hash: &str,
) -> CanonicalResult<Result<DealerCommitmentBinding, PrivateVssRefusal>> {
    if dealer_record.get("objectType").and_then(Value::as_str)
        != Some(VSS_DEALER_COMMITMENT_OBJECT_TYPE)
    {
        return Ok(Err(PrivateVssRefusal::new(
            "dealerCommitmentRecordTypeMismatch",
            "dealerCoefficientCommitmentRecord.objectType must be VssDealerCoefficientCommitments",
            "dealerCoefficientCommitmentRecord.objectType",
        )));
    }
    if dealer_record.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Err(PrivateVssRefusal::new(
            "dealerCommitmentRecordVersionMismatch",
            "dealerCoefficientCommitmentRecord.objectVersion must be 1",
            "dealerCoefficientCommitmentRecord.objectVersion",
        )));
    }
    if let Err(refusal) = compare_context_fields(
        dealer_record,
        setup_context,
        "dealerCoefficientCommitmentRecord",
    ) {
        return Ok(Err(refusal));
    }
    if dealer_record
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(public_matrix_seed_hash)
    {
        return Ok(Err(PrivateVssRefusal::new(
            "dealerCommitmentPublicMatrixSeedMismatch",
            "dealerCoefficientCommitmentRecord.publicMatrixSeedHash must match publicMatrixSeedHash",
            "dealerCoefficientCommitmentRecord.publicMatrixSeedHash",
        )));
    }
    let dealer_identity = match string_field(
        dealer_record,
        "dealerIdentity",
        "dealerCoefficientCommitmentRecord.dealerIdentity",
        "dealerIdentityMissing",
        "dealerCoefficientCommitmentRecord.dealerIdentity is required",
    ) {
        Ok(dealer_identity) => dealer_identity.to_string(),
        Err(refusal) => return Ok(Err(refusal)),
    };
    let dealer_roster_position = match u64_field(
        dealer_record,
        "dealerRosterPosition",
        "dealerCoefficientCommitmentRecord.dealerRosterPosition",
        "dealerRosterPositionMissing",
        "dealerCoefficientCommitmentRecord.dealerRosterPosition is required",
    ) {
        Ok(dealer_roster_position) => dealer_roster_position,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let coefficient_commitments = match array_field(
        dealer_record,
        "coefficientCommitments",
        "dealerCoefficientCommitmentRecord.coefficientCommitments",
        "dealerCoefficientCommitmentsMissing",
        "dealerCoefficientCommitmentRecord.coefficientCommitments is required",
    ) {
        Ok(coefficient_commitments) => coefficient_commitments,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let expected_coefficient_count = DATA_PRIMES.len() * FIRST_PROFILE_DECRYPTION_THRESHOLD;
    if coefficient_commitments.len() != expected_coefficient_count {
        return Ok(Err(PrivateVssRefusal::new(
            "dealerCoefficientCommitmentCountMismatch",
            "dealerCoefficientCommitmentRecord.coefficientCommitments must contain every Q_share limb and Shamir coefficient",
            "dealerCoefficientCommitmentRecord.coefficientCommitments",
        )));
    }

    let mut seen_coordinates = BTreeSet::new();
    let mut coefficient_commitment_roots = BTreeMap::new();
    for coefficient_record in coefficient_commitments {
        let rns_limb_index = match usize_field(
            coefficient_record,
            "rnsLimbIndex",
            "dealerCoefficientCommitmentRecord.coefficientCommitments.rnsLimbIndex",
            "dealerCoefficientRnsLimbMissing",
            "dealer coefficient commitment must bind rnsLimbIndex",
        ) {
            Ok(rns_limb_index) => rns_limb_index,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let rns_prime = match u64_field(
            coefficient_record,
            "rnsPrime",
            "dealerCoefficientCommitmentRecord.coefficientCommitments.rnsPrime",
            "dealerCoefficientRnsPrimeMissing",
            "dealer coefficient commitment must bind rnsPrime",
        ) {
            Ok(rns_prime) => rns_prime,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if DATA_PRIMES.get(rns_limb_index) != Some(&rns_prime) {
            return Ok(Err(PrivateVssRefusal::new(
                "dealerCoefficientRnsPrimeMismatch",
                "dealer coefficient commitment rnsPrime must match Q_share at rnsLimbIndex",
                "dealerCoefficientCommitmentRecord.coefficientCommitments.rnsPrime",
            )));
        }
        let shamir_coefficient_index = match u64_field(
            coefficient_record,
            "shamirCoefficientIndex",
            "dealerCoefficientCommitmentRecord.coefficientCommitments.shamirCoefficientIndex",
            "dealerCoefficientShamirIndexMissing",
            "dealer coefficient commitment must bind shamirCoefficientIndex",
        ) {
            Ok(shamir_coefficient_index) => shamir_coefficient_index,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if shamir_coefficient_index >= FIRST_PROFILE_DECRYPTION_THRESHOLD as u64 {
            return Ok(Err(PrivateVssRefusal::new(
                "dealerCoefficientShamirIndexInvalid",
                "dealer coefficient commitment shamirCoefficientIndex is outside the accepted threshold degree",
                "dealerCoefficientCommitmentRecord.coefficientCommitments.shamirCoefficientIndex",
            )));
        }
        if !seen_coordinates.insert((rns_limb_index, shamir_coefficient_index)) {
            return Ok(Err(PrivateVssRefusal::new(
                "dealerCoefficientCommitmentDuplicate",
                "dealer coefficient commitments must have distinct limb/coefficient coordinates",
                "dealerCoefficientCommitmentRecord.coefficientCommitments",
            )));
        }
        let commitment_root = match hash_string_field(
            coefficient_record,
            "commitmentRoot",
            "dealerCoefficientCommitmentRecord.coefficientCommitments.commitmentRoot",
            "dealerCoefficientCommitmentRootMissing",
            "dealer coefficient commitment must bind commitmentRoot",
        ) {
            Ok(commitment_root) => commitment_root.to_string(),
            Err(refusal) => return Ok(Err(refusal)),
        };
        coefficient_commitment_roots
            .insert((rns_limb_index, shamir_coefficient_index), commitment_root);
    }

    let dealer_commitment_root = match hash_string_field(
        dealer_record,
        "dealerCommitmentRoot",
        "dealerCoefficientCommitmentRecord.dealerCommitmentRoot",
        "dealerCommitmentRootMissing",
        "dealerCoefficientCommitmentRecord.dealerCommitmentRoot is required",
    ) {
        Ok(dealer_commitment_root) => dealer_commitment_root.to_string(),
        Err(refusal) => return Ok(Err(refusal)),
    };
    let mut root_input = dealer_record.clone();
    root_input
        .as_object_mut()
        .expect("dealer commitment record object was checked")
        .remove("dealerCommitmentRoot");
    let expected_dealer_commitment_root =
        derive_protocol_hash("VssCoefficientCommitmentRoot", &root_input)?;
    if dealer_commitment_root != expected_dealer_commitment_root {
        return Ok(Err(PrivateVssRefusal::new(
            "dealerCommitmentRootMismatch",
            "dealerCommitmentRoot does not match the canonical dealer coefficient commitment record",
            "dealerCoefficientCommitmentRecord.dealerCommitmentRoot",
        )));
    }

    Ok(Ok(DealerCommitmentBinding {
        dealer_identity,
        dealer_roster_position,
        dealer_commitment_root,
        coefficient_commitment_roots,
    }))
}

fn verify_coefficient_commitment_material_records(
    material_records: &[Value],
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    dealer_binding: &DealerCommitmentBinding,
) -> CanonicalResult<CoefficientCommitmentMaterialRecordsVerification> {
    let expected_coefficient_count = DATA_PRIMES.len() * FIRST_PROFILE_DECRYPTION_THRESHOLD;
    if material_records.len() != expected_coefficient_count {
        return Ok(Err(PrivateVssRefusal::new(
            "dealerCommitmentMaterialCountMismatch",
            "dealerCoefficientCommitmentMaterialRecords must contain full public commitment material for every Q_share limb and Shamir coefficient",
            "dealerCoefficientCommitmentMaterialRecords",
        )));
    }

    let mut bindings = BTreeMap::new();
    for material_record in material_records {
        let binding = match verify_coefficient_commitment_material_record(
            material_record,
            setup_context,
            public_matrix_seed_hash,
            dealer_binding,
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
                "dealerCommitmentMaterialDuplicate",
                "dealerCoefficientCommitmentMaterialRecords must have distinct limb/coefficient coordinates",
                "dealerCoefficientCommitmentMaterialRecords",
            )));
        }
    }

    for rns_limb_index in 0..DATA_PRIMES.len() {
        for shamir_coefficient_index in 0..FIRST_PROFILE_DECRYPTION_THRESHOLD as u64 {
            if !bindings.contains_key(&(rns_limb_index, shamir_coefficient_index)) {
                return Ok(Err(PrivateVssRefusal::new(
                    "dealerCommitmentMaterialCoverageMismatch",
                    "dealerCoefficientCommitmentMaterialRecords must cover every Q_share limb and Shamir coefficient",
                    "dealerCoefficientCommitmentMaterialRecords",
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
    dealer_binding: &DealerCommitmentBinding,
) -> CanonicalResult<Result<CoefficientCommitmentBinding, PrivateVssRefusal>> {
    if material_record.get("objectType").and_then(Value::as_str)
        != Some(VSS_COEFFICIENT_COMMITMENT_MATERIAL_OBJECT_TYPE)
    {
        return Ok(Err(PrivateVssRefusal::new(
            "dealerCommitmentMaterialTypeMismatch",
            "coefficient commitment material objectType must be VssCoefficientCommitmentMaterial",
            "dealerCoefficientCommitmentMaterialRecords.objectType",
        )));
    }
    if material_record.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Err(PrivateVssRefusal::new(
            "dealerCommitmentMaterialVersionMismatch",
            "coefficient commitment material objectVersion must be 1",
            "dealerCoefficientCommitmentMaterialRecords.objectVersion",
        )));
    }
    if let Err(refusal) = compare_context_fields(
        material_record,
        setup_context,
        "dealerCoefficientCommitmentMaterialRecords",
    ) {
        return Ok(Err(refusal));
    }
    if material_record
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(public_matrix_seed_hash)
    {
        return Ok(Err(PrivateVssRefusal::new(
            "dealerCommitmentMaterialPublicMatrixSeedMismatch",
            "coefficient commitment material publicMatrixSeedHash must match publicMatrixSeedHash",
            "dealerCoefficientCommitmentMaterialRecords.publicMatrixSeedHash",
        )));
    }
    if material_record
        .get("dealerIdentity")
        .and_then(Value::as_str)
        != Some(dealer_binding.dealer_identity.as_str())
        || material_record
            .get("dealerRosterPosition")
            .and_then(Value::as_u64)
            != Some(dealer_binding.dealer_roster_position)
    {
        return Ok(Err(PrivateVssRefusal::new(
            "dealerCommitmentMaterialDealerMismatch",
            "coefficient commitment material dealer binding must match dealerCoefficientCommitmentRecord",
            "dealerCoefficientCommitmentMaterialRecords.dealerIdentity",
        )));
    }

    let rns_limb_index = match usize_field(
        material_record,
        "rnsLimbIndex",
        "dealerCoefficientCommitmentMaterialRecords.rnsLimbIndex",
        "dealerCommitmentMaterialRnsLimbMissing",
        "coefficient commitment material must bind rnsLimbIndex",
    ) {
        Ok(rns_limb_index) => rns_limb_index,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let rns_prime = match u64_field(
        material_record,
        "rnsPrime",
        "dealerCoefficientCommitmentMaterialRecords.rnsPrime",
        "dealerCommitmentMaterialRnsPrimeMissing",
        "coefficient commitment material must bind rnsPrime",
    ) {
        Ok(rns_prime) => rns_prime,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if DATA_PRIMES.get(rns_limb_index) != Some(&rns_prime) {
        return Ok(Err(PrivateVssRefusal::new(
            "dealerCommitmentMaterialRnsPrimeMismatch",
            "coefficient commitment material rnsPrime must match Q_share at rnsLimbIndex",
            "dealerCoefficientCommitmentMaterialRecords.rnsPrime",
        )));
    }
    let shamir_coefficient_index = match u64_field(
        material_record,
        "shamirCoefficientIndex",
        "dealerCoefficientCommitmentMaterialRecords.shamirCoefficientIndex",
        "dealerCommitmentMaterialShamirIndexMissing",
        "coefficient commitment material must bind shamirCoefficientIndex",
    ) {
        Ok(shamir_coefficient_index) => shamir_coefficient_index,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if shamir_coefficient_index >= FIRST_PROFILE_DECRYPTION_THRESHOLD as u64 {
        return Ok(Err(PrivateVssRefusal::new(
            "dealerCommitmentMaterialShamirIndexInvalid",
            "coefficient commitment material shamirCoefficientIndex is outside the accepted threshold degree",
            "dealerCoefficientCommitmentMaterialRecords.shamirCoefficientIndex",
        )));
    }
    let commitment_root = match hash_string_field(
        material_record,
        "commitmentRoot",
        "dealerCoefficientCommitmentMaterialRecords.commitmentRoot",
        "dealerCommitmentMaterialRootMissing",
        "coefficient commitment material must bind commitmentRoot",
    ) {
        Ok(commitment_root) => commitment_root.to_string(),
        Err(refusal) => return Ok(Err(refusal)),
    };
    if dealer_binding
        .coefficient_commitment_roots
        .get(&(rns_limb_index, shamir_coefficient_index))
        .map(String::as_str)
        != Some(commitment_root.as_str())
    {
        return Ok(Err(PrivateVssRefusal::new(
            "dealerCommitmentMaterialRootMismatch",
            "coefficient commitment material root must match the dealer coefficient commitment record",
            "dealerCoefficientCommitmentMaterialRecords.commitmentRoot",
        )));
    }
    let commitment_value = match object_field(
        material_record,
        "commitment",
        "dealerCoefficientCommitmentMaterialRecords.commitment",
        "dealerCommitmentMaterialCommitmentMissing",
        "coefficient commitment material must include the full public commitment",
    ) {
        Ok(commitment_value) => commitment_value,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let commitment = match parse_setup_commitment_full_value(commitment_value) {
        Ok(commitment) => commitment,
        Err(error) => {
            return Ok(Err(PrivateVssRefusal::new(
                "dealerCommitmentMaterialInvalid",
                error.message,
                "dealerCoefficientCommitmentMaterialRecords.commitment",
            )));
        }
    };
    if commitment.source_rns_limb_index != rns_limb_index
        || commitment.source_message_modulus != rns_prime
        || commitment.shamir_coefficient_index != shamir_coefficient_index
    {
        return Ok(Err(PrivateVssRefusal::new(
            "dealerCommitmentMaterialDomainMismatch",
            "full setup commitment domain must match its material wrapper",
            "dealerCoefficientCommitmentMaterialRecords.commitment",
        )));
    }
    let computed_commitment_root = setup_commitment_root(&commitment)?;
    if commitment_root != computed_commitment_root {
        return Ok(Err(PrivateVssRefusal::new(
            "dealerCommitmentMaterialRootMismatch",
            "full setup commitment material does not match commitmentRoot",
            "dealerCoefficientCommitmentMaterialRecords.commitment",
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
    dealer_binding: &DealerCommitmentBinding,
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
            "dealerIdentity",
            "dealerRosterPosition",
            "recipientIdentity",
            "recipientRosterPosition",
            "dealerCommitmentRoot",
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

    let dealer_identity = match string_field(
        private_envelope,
        "dealerIdentity",
        "privateEnvelope.dealerIdentity",
        "privateEnvelopeDealerMissing",
        "privateEnvelope.dealerIdentity is required",
    ) {
        Ok(dealer_identity) => dealer_identity.to_string(),
        Err(refusal) => return Ok(Err(refusal)),
    };
    let dealer_roster_position = match u64_field(
        private_envelope,
        "dealerRosterPosition",
        "privateEnvelope.dealerRosterPosition",
        "privateEnvelopeDealerPositionMissing",
        "privateEnvelope.dealerRosterPosition is required",
    ) {
        Ok(dealer_roster_position) => dealer_roster_position,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if dealer_identity != dealer_binding.dealer_identity
        || dealer_roster_position != dealer_binding.dealer_roster_position
    {
        return Ok(Err(PrivateVssRefusal::new(
            "privateEnvelopeDealerMismatch",
            "privateEnvelope dealer binding must match dealerCoefficientCommitmentRecord",
            "privateEnvelope.dealerIdentity",
        )));
    }
    if private_envelope
        .get("dealerCommitmentRoot")
        .and_then(Value::as_str)
        != Some(dealer_binding.dealer_commitment_root.as_str())
    {
        return Ok(Err(PrivateVssRefusal::new(
            "privateEnvelopeDealerCommitmentRootMismatch",
            "privateEnvelope.dealerCommitmentRoot must match the accepted dealer commitment root",
            "privateEnvelope.dealerCommitmentRoot",
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
    public_matrix_seed_hash: &str,
    dealer_binding: &DealerCommitmentBinding,
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
            public_matrix_seed_hash,
            dealer_binding,
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
    public_matrix_seed_hash: &str,
    dealer_binding: &DealerCommitmentBinding,
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
            "carryWitnessesDecimal",
            "coefficientCommitmentRoots",
            "aggregateOpening",
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
    let carry_witnesses = match u128_vector_field(
        limb_opening,
        "carryWitnessesDecimal",
        "privateEnvelope.rnsShareOpenings.carryWitnessesDecimal",
        "privateVssCarryWitnessesMissing",
        "private VSS limb opening must include carryWitnessesDecimal",
    ) {
        Ok(carry_witnesses) => carry_witnesses,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let ring_degree = share_values.len();
    if ring_degree == 0 || carry_witnesses.len() != ring_degree {
        return Ok(Err(PrivateVssRefusal::new(
            "privateVssShareCarryLengthMismatch",
            "private VSS share and carry vectors must be non-empty and have the same length",
            "privateEnvelope.rnsShareOpenings",
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
        if dealer_binding
            .coefficient_commitment_roots
            .get(&(rns_limb_index, shamir_coefficient_index))
            .map(String::as_str)
            != Some(commitment_root.as_str())
        {
            return Ok(Err(PrivateVssRefusal::new(
                "privateVssCoefficientCommitmentRootMismatch",
                "private VSS limb coefficientCommitmentRoots must match the public dealer commitment record",
                "privateEnvelope.rnsShareOpenings.coefficientCommitmentRoots",
            )));
        }
        let Some(material_binding) =
            coefficient_commitments.get(&(rns_limb_index, shamir_coefficient_index))
        else {
            return Ok(Err(PrivateVssRefusal::new(
                "privateVssCoefficientCommitmentMaterialMissing",
                "private VSS limb references coefficient commitment material that was not provided",
                "dealerCoefficientCommitmentMaterialRecords",
            )));
        };
        if material_binding.commitment_root != *commitment_root {
            return Ok(Err(PrivateVssRefusal::new(
                "privateVssCoefficientCommitmentMaterialRootMismatch",
                "coefficient commitment material root must match private envelope root reference",
                "dealerCoefficientCommitmentMaterialRecords.commitmentRoot",
            )));
        }
        coefficient_commitment_values.push(material_binding.commitment.clone());
    }

    let aggregate_opening = match object_field(
        limb_opening,
        "aggregateOpening",
        "privateEnvelope.rnsShareOpenings.aggregateOpening",
        "privateVssAggregateOpeningMissing",
        "private VSS limb opening must include an aggregateOpening",
    ) {
        Ok(aggregate_opening) => aggregate_opening,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let aggregate_opening_columns = match aggregate_opening_columns(aggregate_opening)? {
        Ok(aggregate_opening_columns) => aggregate_opening_columns,
        Err(refusal) => return Ok(Err(refusal)),
    };

    let recipient_roster_position = usize::try_from(envelope_binding.recipient_roster_position)
        .map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "recipient roster position does not fit usize",
            )
        })?;
    let opening_verification = match verify_carry_aware_vss_aggregate_commitment_opening(
        CarryAwareVssAggregateCommitmentOpeningInput {
            public_matrix_seed_hash,
            coefficient_commitments: &coefficient_commitment_values,
            recipient_roster_position,
            share_values: &share_values,
            carry_witnesses: &carry_witnesses,
            aggregate_opening_columns: &aggregate_opening_columns,
            modulus: rns_prime,
            fresh_randomness_bound: SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND,
        },
    ) {
        Ok(opening_verification) => opening_verification,
        Err(error) => {
            return Ok(Err(PrivateVssRefusal::new(
                "privateVssEnvelopeInvalidOpening",
                error.message,
                "privateEnvelope.rnsShareOpenings",
            )));
        }
    };

    let carry_witnesses_decimal = carry_witnesses
        .iter()
        .map(u128::to_string)
        .collect::<Vec<_>>();
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
    let carry_witnesses_hash = derive_protocol_hash(
        "PrivateVssLocalVerificationRoot",
        &json!({
            "objectType": "PrivateVssCarryWitnessVector",
            "objectVersion": 1,
            "rnsLimbIndex": rns_limb_index,
            "rnsPrime": rns_prime,
            "carryWitnessesDecimal": carry_witnesses_decimal,
        }),
    )?;
    let max_carry_witness_decimal = carry_witnesses
        .iter()
        .copied()
        .max()
        .unwrap_or(0)
        .to_string();
    let limb_record = json!({
        "objectType": "PrivateVssLimbVerification",
        "objectVersion": 1,
        "rnsLimbIndex": rns_limb_index,
        "rnsPrime": rns_prime,
        "ringDegree": ring_degree,
        "coefficientCommitmentRoots": coefficient_commitment_roots,
        "shareValuesHash": share_values_hash,
        "carryWitnessesHash": carry_witnesses_hash,
        "combinedCommitmentRoot": opening_verification.commitment_opening.commitment_root,
        "homomorphicRandomnessBound": opening_verification.homomorphic_randomness_bound,
        "maxCarryWitnessDecimal": max_carry_witness_decimal,
    });
    let limb_verification_root =
        derive_protocol_hash("PrivateVssLocalVerificationRoot", &limb_record)?;

    Ok(Ok(LimbVerification {
        rns_limb_index,
        rns_prime,
        ring_degree,
        coefficient_commitment_roots,
        share_values_hash,
        carry_witnesses_hash,
        combined_commitment_root: opening_verification.commitment_opening.commitment_root,
        homomorphic_randomness_bound: opening_verification.homomorphic_randomness_bound,
        max_carry_witness_decimal,
        limb_verification_root,
    }))
}

fn local_verification_record(
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    dealer_binding: &DealerCommitmentBinding,
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
        "dealerIdentity": dealer_binding.dealer_identity,
        "dealerRosterPosition": dealer_binding.dealer_roster_position,
        "recipientIdentity": envelope_binding.recipient_identity,
        "recipientRosterPosition": envelope_binding.recipient_roster_position,
        "dealerCommitmentRoot": dealer_binding.dealer_commitment_root,
        "ringDegree": ring_degree,
        "ringDegreeStatus": ring_degree_status,
        "verifiedRnsLimbCount": limb_verifications.len(),
        "verifiedShamirCoefficientCommitmentCount": limb_verifications.len() * FIRST_PROFILE_DECRYPTION_THRESHOLD,
        "verifiedAggregateOpeningCount": limb_verifications.len(),
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
        "carryWitnessesHash": verification.carry_witnesses_hash,
        "combinedCommitmentRoot": verification.combined_commitment_root,
        "homomorphicRandomnessBound": verification.homomorphic_randomness_bound,
        "maxCarryWitnessDecimal": verification.max_carry_witness_decimal,
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

fn u128_vector_field(
    value: &Value,
    field_name: &str,
    object_path: &str,
    reason_code: &'static str,
    message: impl Into<String>,
) -> Result<Vec<u128>, PrivateVssRefusal> {
    let values = array_field(value, field_name, object_path, reason_code, message)?;
    values
        .iter()
        .map(|value| match value {
            Value::String(text) => text.parse::<u128>().map_err(|_| {
                PrivateVssRefusal::new(
                    reason_code,
                    format!("{object_path} decimal string is malformed"),
                    object_path,
                )
            }),
            Value::Number(number) => number.as_u64().map(u128::from).ok_or_else(|| {
                PrivateVssRefusal::new(
                    reason_code,
                    format!(
                        "{object_path} must contain safe non-negative integers or decimal strings"
                    ),
                    object_path,
                )
            }),
            _ => Err(PrivateVssRefusal::new(
                reason_code,
                format!("{object_path} must contain safe non-negative integers or decimal strings"),
                object_path,
            )),
        })
        .collect()
}

fn aggregate_opening_columns(
    aggregate_opening: &Value,
) -> CanonicalResult<Result<Vec<Vec<i128>>, PrivateVssRefusal>> {
    if aggregate_opening.get("objectType").and_then(Value::as_str)
        != Some(PRIVATE_VSS_AGGREGATE_OPENING_OBJECT_TYPE)
    {
        return Ok(Err(PrivateVssRefusal::new(
            "privateVssAggregateOpeningTypeMismatch",
            "private VSS aggregate opening objectType must be PrivateVssAggregateOpening",
            "privateEnvelope.rnsShareOpenings.aggregateOpening.objectType",
        )));
    }
    if aggregate_opening
        .get("objectVersion")
        .and_then(Value::as_u64)
        != Some(1)
    {
        return Ok(Err(PrivateVssRefusal::new(
            "privateVssAggregateOpeningVersionMismatch",
            "private VSS aggregate opening objectVersion must be 1",
            "privateEnvelope.rnsShareOpenings.aggregateOpening.objectVersion",
        )));
    }
    if let Err(refusal) = reject_unexpected_fields(
        aggregate_opening,
        &["objectType", "objectVersion", "openingColumns"],
        "privateEnvelope.rnsShareOpenings.aggregateOpening",
    ) {
        return Ok(Err(refusal));
    }
    Ok(
        match i128_matrix_field(
            aggregate_opening,
            "openingColumns",
            "privateEnvelope.rnsShareOpenings.aggregateOpening.openingColumns",
            "privateVssAggregateOpeningColumnsMissing",
            "private VSS aggregate opening must include openingColumns",
        ) {
            Ok(opening_columns) => Ok(opening_columns),
            Err(refusal) => Err(refusal),
        },
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

fn i128_matrix_field(
    value: &Value,
    field_name: &str,
    object_path: &str,
    reason_code: &'static str,
    message: impl Into<String>,
) -> Result<Vec<Vec<i128>>, PrivateVssRefusal> {
    let columns = array_field(value, field_name, object_path, reason_code, message)?;
    columns
        .iter()
        .map(|column| {
            let Some(coefficients) = column.as_array() else {
                return Err(PrivateVssRefusal::new(
                    reason_code,
                    format!("{object_path} must contain arrays of signed integers"),
                    object_path,
                ));
            };
            coefficients
                .iter()
                .map(|coefficient| {
                    coefficient.as_i64().map(i128::from).ok_or_else(|| {
                        PrivateVssRefusal::new(
                            reason_code,
                            format!("{object_path} must contain signed integers"),
                            object_path,
                        )
                    })
                })
                .collect()
        })
        .collect()
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
