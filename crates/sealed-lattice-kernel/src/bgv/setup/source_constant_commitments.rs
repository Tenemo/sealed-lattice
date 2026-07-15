use super::*;
use crate::bgv::parameters::DATA_PRIMES;
use crate::bgv::setup::commitment::{
    SetupCommitmentValue, parse_setup_commitment_full_value, setup_commitment_root,
};

pub(in crate::bgv::setup) struct CanonicalSourceConstantCommitments {
    pub(in crate::bgv::setup) commitment_values: Vec<Value>,
    pub(in crate::bgv::setup) commitments: Vec<SetupCommitmentValue>,
}

#[cfg(test)]
pub(in crate::bgv::setup) fn canonical_source_constant_commitments_from_vss_material(
    vss_coefficient_commitments: &Value,
    vss_coefficient_commitment_material: &Value,
    trustee_identity: &str,
    trustee_roster_position: u64,
    public_matrix_seed_hash: &str,
    ring_degree: usize,
) -> CanonicalResult<CanonicalSourceConstantCommitments> {
    let source_trustee_records = vss_coefficient_commitments
        .get("sourceTrusteeRecords")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS source trustee commitment records were required for the source linkage",
            )
        })?;
    let matching_source_records = source_trustee_records
        .iter()
        .filter(|record| {
            record
                .get("sourceTrusteeRosterPosition")
                .and_then(Value::as_u64)
                == Some(trustee_roster_position)
        })
        .collect::<Vec<_>>();
    if matching_source_records.len() != 1 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "accepted VSS commitments must contain exactly one source trustee record",
        ));
    }
    let source_trustee_record = matching_source_records[0];
    if vss_coefficient_commitments
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(public_matrix_seed_hash)
        || source_trustee_record
            .get("sourceTrusteeIdentity")
            .and_then(Value::as_str)
            != Some(trustee_identity)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "VSS commitment set does not match the accepted source context",
        ));
    }
    let public_commitment_records = source_trustee_record
        .get("coefficientCommitments")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "source trustee coefficient commitments were required for the source linkage",
            )
        })?;
    let material_records = vss_coefficient_commitment_material
        .get("coefficientCommitments")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS coefficient commitment material records were required for the source linkage",
            )
        })?;
    let threshold_degree = vss_coefficient_commitment_material
        .get("thresholdDegree")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS coefficient commitment material threshold degree was required",
            )
        })?;

    let mut commitment_values = Vec::with_capacity(DATA_PRIMES.len());
    let mut commitments = Vec::with_capacity(DATA_PRIMES.len());
    for (source_rns_limb_index, source_message_modulus) in DATA_PRIMES.iter().copied().enumerate() {
        let public_record = public_commitment_records
            .get(source_rns_limb_index * threshold_degree)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "accepted VSS commitments must contain one canonical public constant root per Q_share limb",
                )
            })?;
        let expected_commitment_root = public_record
            .get("commitmentRoot")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "public source constant commitment root was missing",
                )
            })?;
        let material_record_index = (trustee_roster_position as usize * DATA_PRIMES.len()
            + source_rns_limb_index)
            * threshold_degree;
        let material_record = material_records.get(material_record_index).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "accepted VSS material must contain one canonical source constant commitment per Q_share limb",
            )
        })?;
        let commitment_value = material_record.get("commitment").ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "source constant commitment body was missing from accepted VSS material",
            )
        })?;
        let commitment = parse_setup_commitment_full_value(commitment_value)?;
        if commitment.source_rns_limb_index != source_rns_limb_index
            || commitment.source_message_modulus != source_message_modulus
            || commitment.shamir_coefficient_index != 0
            || commitment.ring_degree != ring_degree
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "source constant commitment body does not match its canonical VSS coordinates",
            ));
        }
        let commitment_root = setup_commitment_root(&commitment)?;
        if expected_commitment_root != commitment_root {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "source constant commitment body does not reproduce its accepted root",
            ));
        }

        commitment_values.push(commitment_value.clone());
        commitments.push(commitment);
    }

    Ok(CanonicalSourceConstantCommitments {
        commitment_values,
        commitments,
    })
}

// Reconstruct the public full-source linkage from the commitment bodies in
// canonical Q_share order, matching each recomputed root to the accepted VSS
// record.
pub(in crate::bgv::setup) fn canonical_source_constant_commitments_from_bridge_statement(
    vss_coefficient_commitments: &Value,
    bridge_statement_record: &Value,
    trustee_identity: &str,
    trustee_roster_position: u64,
    public_matrix_seed_hash: &str,
    ring_degree: usize,
) -> CanonicalResult<CanonicalSourceConstantCommitments> {
    let source_trustee_records = vss_coefficient_commitments
        .get("sourceTrusteeRecords")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS source trustee commitment records were required for the source linkage",
            )
        })?;
    let matching_source_records = source_trustee_records
        .iter()
        .filter(|record| {
            record
                .get("sourceTrusteeRosterPosition")
                .and_then(Value::as_u64)
                == Some(trustee_roster_position)
        })
        .collect::<Vec<_>>();
    if matching_source_records.len() != 1 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "accepted VSS commitments must contain exactly one source trustee record",
        ));
    }
    let source_trustee_record = matching_source_records[0];
    if vss_coefficient_commitments
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(public_matrix_seed_hash)
        || source_trustee_record
            .get("sourceTrusteeIdentity")
            .and_then(Value::as_str)
            != Some(trustee_identity)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "VSS commitment set does not match the accepted source context",
        ));
    }
    let public_commitment_records = source_trustee_record
        .get("coefficientCommitments")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "source trustee coefficient commitments were required for the source linkage",
            )
        })?;
    let source_commitment_records = bridge_statement_record
        .get("sourceConstantCoefficientCommitments")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "same-secret bridge statement must retain the full source constant commitment bodies",
            )
        })?;
    if source_commitment_records.len() != DATA_PRIMES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "same-secret bridge statement must retain one source constant commitment per Q_share limb",
        ));
    }
    if public_commitment_records.len() % DATA_PRIMES.len() != 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "accepted VSS commitment roots must use canonical limb/coefficient order",
        ));
    }
    let threshold_degree = public_commitment_records.len() / DATA_PRIMES.len();
    if threshold_degree == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "accepted VSS commitment roots must include every Shamir coefficient",
        ));
    }

    let mut commitment_values = Vec::with_capacity(DATA_PRIMES.len());
    let mut commitments = Vec::with_capacity(DATA_PRIMES.len());
    for (source_rns_limb_index, source_message_modulus) in DATA_PRIMES.iter().copied().enumerate() {
        let public_record = public_commitment_records
            .get(source_rns_limb_index * threshold_degree)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "accepted VSS commitments must contain one canonical public constant root per Q_share limb",
                )
            })?;
        let expected_commitment_root = public_record
            .get("commitmentRoot")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "public source constant commitment root was missing",
                )
            })?;

        let commitment =
            parse_setup_commitment_full_value(&source_commitment_records[source_rns_limb_index])?;
        if commitment.source_rns_limb_index != source_rns_limb_index
            || commitment.source_message_modulus != source_message_modulus
            || commitment.shamir_coefficient_index != 0
            || commitment.ring_degree != ring_degree
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "same-secret bridge source commitment body does not match its canonical coordinates",
            ));
        }
        let commitment_root = setup_commitment_root(&commitment)?;
        if commitment_root != expected_commitment_root {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "same-secret bridge source commitment body does not reproduce its accepted VSS root",
            ));
        }

        commitment_values.push(crate::bgv::setup::commitment::setup_commitment_full_value(
            &commitment,
        ));
        commitments.push(commitment);
    }

    Ok(CanonicalSourceConstantCommitments {
        commitment_values,
        commitments,
    })
}
