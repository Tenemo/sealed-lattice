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
    for (field_name, expected_value) in [
        ("sourceTrusteeIdentity", trustee_identity),
        ("publicMatrixSeedHash", public_matrix_seed_hash),
    ] {
        if source_trustee_record
            .get(field_name)
            .and_then(Value::as_str)
            != Some(expected_value)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                format!(
                    "source trustee commitment {field_name} does not match its accepted context"
                ),
            ));
        }
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

    let mut commitment_values = Vec::with_capacity(DATA_PRIMES.len());
    let mut commitments = Vec::with_capacity(DATA_PRIMES.len());
    for (source_rns_limb_index, source_message_modulus) in DATA_PRIMES.iter().copied().enumerate() {
        let matching_public_records = public_commitment_records
            .iter()
            .filter(|record| {
                record.get("rnsLimbIndex").and_then(Value::as_u64)
                    == Some(source_rns_limb_index as u64)
                    && record.get("shamirCoefficientIndex").and_then(Value::as_u64) == Some(0)
            })
            .collect::<Vec<_>>();
        if matching_public_records.len() != 1 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "accepted VSS commitments must contain exactly one public constant root per Q_share limb",
            ));
        }
        let public_record = matching_public_records[0];
        if public_record.get("rnsPrime").and_then(Value::as_u64) != Some(source_message_modulus) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "public source constant commitment prime does not match its canonical Q_share limb",
            ));
        }
        let expected_commitment_root = public_record
            .get("commitmentRoot")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "public source constant commitment root was missing",
                )
            })?;
        let matching_records = material_records
            .iter()
            .filter(|record| {
                record
                    .get("sourceTrusteeRosterPosition")
                    .and_then(Value::as_u64)
                    == Some(trustee_roster_position)
                    && record.get("rnsLimbIndex").and_then(Value::as_u64)
                        == Some(source_rns_limb_index as u64)
                    && record.get("shamirCoefficientIndex").and_then(Value::as_u64) == Some(0)
            })
            .collect::<Vec<_>>();
        if matching_records.len() != 1 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "accepted VSS material must contain exactly one source constant commitment per Q_share limb",
            ));
        }
        let material_record = matching_records[0];
        for (field_name, expected_value) in [
            ("sourceTrusteeIdentity", trustee_identity),
            ("publicMatrixSeedHash", public_matrix_seed_hash),
        ] {
            if material_record.get(field_name).and_then(Value::as_str) != Some(expected_value) {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ComponentMismatch,
                    format!(
                        "source constant commitment {field_name} does not match its accepted context"
                    ),
                ));
            }
        }
        if material_record.get("rnsPrime").and_then(Value::as_u64) != Some(source_message_modulus) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "source constant commitment prime does not match its canonical Q_share limb",
            ));
        }
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
        if material_record
            .get("commitmentRoot")
            .and_then(Value::as_str)
            != Some(commitment_root.as_str())
            || expected_commitment_root != commitment_root
        {
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

// Reconstruct the public full-source linkage from the minimal commitment
// bodies retained in one bridge statement. Each body is parsed under the
// canonical SetupCommitment encoding, then its recomputed root is matched to
// the accepted VSS root record. The statement copy never supplies authority
// for its own root.
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
    for (field_name, expected_value) in [
        ("sourceTrusteeIdentity", trustee_identity),
        ("publicMatrixSeedHash", public_matrix_seed_hash),
    ] {
        if source_trustee_record
            .get(field_name)
            .and_then(Value::as_str)
            != Some(expected_value)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                format!(
                    "source trustee commitment {field_name} does not match its accepted context"
                ),
            ));
        }
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

    let mut commitment_values = Vec::with_capacity(DATA_PRIMES.len());
    let mut commitments = Vec::with_capacity(DATA_PRIMES.len());
    for (source_rns_limb_index, source_message_modulus) in DATA_PRIMES.iter().copied().enumerate() {
        let public_records = public_commitment_records
            .iter()
            .filter(|record| {
                record.get("rnsLimbIndex").and_then(Value::as_u64)
                    == Some(source_rns_limb_index as u64)
                    && record.get("shamirCoefficientIndex").and_then(Value::as_u64) == Some(0)
            })
            .collect::<Vec<_>>();
        if public_records.len() != 1 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "accepted VSS commitments must contain exactly one public constant root per Q_share limb",
            ));
        }
        let public_record = public_records[0];
        if public_record.get("rnsPrime").and_then(Value::as_u64) != Some(source_message_modulus) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "public source constant commitment prime does not match its canonical Q_share limb",
            ));
        }
        let expected_commitment_root = public_record
            .get("commitmentRoot")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "public source constant commitment root was missing",
                )
            })?;

        let source_record = &source_commitment_records[source_rns_limb_index];
        if source_record.get("rnsLimbIndex").and_then(Value::as_u64)
            != Some(source_rns_limb_index as u64)
            || source_record.get("rnsPrime").and_then(Value::as_u64) != Some(source_message_modulus)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "same-secret bridge source commitments must use canonical limb order and coordinates",
            ));
        }
        let commitment_value = source_record.get("commitment").ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "same-secret bridge source constant commitment body was missing",
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
