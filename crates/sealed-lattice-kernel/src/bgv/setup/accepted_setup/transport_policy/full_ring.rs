use super::*;

pub(in crate::bgv::setup) fn verify_full_ring_material(
    setup_package: &Value,
) -> CanonicalResult<Option<Value>> {
    // The accepted ring is evidenced by the proof-verified coefficient commitment
    // set, whose ringDegree is bound into the recomputed set root the share-linkage
    // proofs verify. The reduced development ring must be refused (never accepted as
    // the production ring) before terminal acceptance.
    let Some(commitment_set) = setup_package.get("vssPublicCoefficientCommitmentSet") else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "vssPublicCoefficientCommitmentSet was required before full-ring verification",
        ));
    };
    if commitment_set.get("ringDegree").and_then(Value::as_u64) != Some(POLYNOMIAL_DEGREE as u64) {
        return Ok(Some(setup_material_outside_full_ring(
            "vssPublicCoefficientCommitmentSet must use the accepted full ring degree",
            "setupPackage.vssPublicCoefficientCommitmentSet.ringDegree",
        )?));
    }
    if let Some(material_set) = setup_package.get("publicKeyShareMaterial")
        && let Some(response) = verify_full_ring_record(
            material_set,
            "public-key share material must use the accepted full ring degree before terminal setup acceptance",
            "setupPackage.publicKeyShareMaterial.ringDegree",
        )?
    {
        return Ok(Some(response));
    }
    if let Some(proof_set) = setup_package.get("publicKeyShareSuccinctProofs")
        && let Some(response) = verify_full_ring_records(
            proof_set,
            "proofRecords",
            "public-key succinct proof records must use the accepted full ring degree before terminal setup acceptance",
            "setupPackage.publicKeyShareSuccinctProofs.proofRecords.ringDegree",
        )?
    {
        return Ok(Some(response));
    }
    if let Some(collective_public_key) = setup_package.get("collectivePublicKey")
        && let Some(response) = verify_full_ring_record(
            collective_public_key,
            "collective public-key material must use the accepted full ring degree before terminal setup acceptance",
            "setupPackage.collectivePublicKey.ringDegree",
        )?
    {
        return Ok(Some(response));
    }
    if let Some(rounds) = setup_package.get("relinearizationKeyShareRounds") {
        for field_name in ["roundOneRecords", "roundTwoRecords"] {
            if let Some(response) = verify_full_ring_records(
                rounds,
                field_name,
                "relinearization key-share proof records must use the accepted full ring degree before terminal setup acceptance",
                format!("setupPackage.relinearizationKeyShareRounds.{field_name}.ringDegree"),
            )? {
                return Ok(Some(response));
            }
        }
    }
    if let Some(galois_batches) = setup_package
        .get("galoisKeyShareBatches")
        .and_then(Value::as_array)
    {
        for batch in galois_batches {
            if let Some(response) = verify_full_ring_records(
                batch,
                "galoisKeyShareMaterialRecords",
                "Galois key-share material records must use the accepted full ring degree before terminal setup acceptance",
                "setupPackage.galoisKeyShareBatches.galoisKeyShareMaterialRecords.ringDegree",
            )? {
                return Ok(Some(response));
            }
        }
    }

    Ok(None)
}

fn verify_full_ring_records(
    record_set: &Value,
    records_field_name: &str,
    message: impl Into<String> + Clone,
    object_path: impl Into<String> + Clone,
) -> CanonicalResult<Option<Value>> {
    for record in array_value(record_set, records_field_name)? {
        if let Some(response) =
            verify_full_ring_record(record, message.clone(), object_path.clone())?
        {
            return Ok(Some(response));
        }
    }

    Ok(None)
}

fn verify_full_ring_record(
    record: &Value,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Option<Value>> {
    if record.get("ringDegree").and_then(Value::as_u64) != Some(POLYNOMIAL_DEGREE as u64) {
        return Ok(Some(setup_material_outside_full_ring(
            message,
            object_path,
        )?));
    }

    Ok(None)
}

fn setup_material_outside_full_ring(
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        Some("setupMaterial"),
        Vec::new(),
        vec![Refusal::new(
            "setupMaterialOutsideAcceptedRing",
            message,
            object_path,
        )],
        Vec::new(),
    )
}
