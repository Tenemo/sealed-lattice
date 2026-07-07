use super::material_transport::*;
use super::*;

pub(in crate::bgv::setup) fn accepted_setup_public_relinearization_keys_from_transport(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<BTreeMap<usize, KeySwitchKey>> {
    let roster = super::super::accepted_roster_from_package(setup_package);
    let binding = evaluation_key_proof_common_binding(setup_package)?;
    let transported_key_switch_component_material =
        transported_evaluation_key_share_component_material_from_request(request)?;
    let transported_key_switch_component_material = request
        .get("transportedEvaluationKeyShareComponentMaterial")
        .or(transported_key_switch_component_material.as_ref());
    let rounds = setup_package
        .get("relinearizationKeyShareRounds")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "relinearizationKeyShareRounds was required before public relinearization key material loading",
            )
        })?;
    let round_two_records = array_value(rounds, "roundTwoRecords")?;
    let mut records_by_level_and_trustee = BTreeMap::new();
    for record in round_two_records {
        if value_string(record, "objectType")? != RELINEARIZATION_KEY_SHARE_ROUND_TWO_OBJECT_TYPE {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "accepted public relinearization key material must use round-two records",
            ));
        }
        let level = value_u64(record, "level")?;
        let trustee_roster_position = value_u64(record, "trusteeRosterPosition")?;
        if records_by_level_and_trustee
            .insert((level, trustee_roster_position), record)
            .is_some()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "accepted public relinearization key material must not repeat a trustee record for a level",
            ));
        }
    }

    let expected_levels = scheduled_relinearization_levels()?;
    let expected_record_count = expected_levels
        .len()
        .checked_mul(roster.participant_count as usize)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "accepted public relinearization key material record count overflowed",
            )
        })?;
    if records_by_level_and_trustee.len() != expected_record_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "accepted public relinearization key material requires one round-two record per scheduled level and trustee",
        ));
    }

    let mut relinearization_keys = BTreeMap::new();
    for level in expected_levels {
        let level_usize = usize::try_from(level).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "relinearization key level does not fit usize",
            )
        })?;
        let key_switch_seed_hex =
            expected_relinearization_key_switch_seed(&binding, "round-two", level)?;
        let mut aggregate_component_b = None;
        for trustee_roster_position in 0..roster.participant_count {
            let proof_record = records_by_level_and_trustee
                .get(&(level, trustee_roster_position))
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "accepted public relinearization key material is missing a trustee record for a scheduled level",
                    )
                })?;
            verify_relinearization_key_switch_sample_binding(
                proof_record,
                &binding,
                "round-two",
                level,
            )?;
            if value_u64(proof_record, "ringDegree")? != POLYNOMIAL_DEGREE as u64 {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "accepted public relinearization key runtime material requires full-ring component vectors",
                ));
            }
            let component_b = component_b_vectors_from_record(
                EvaluationKeyShareProofFamily::Relinearization,
                proof_record,
                transported_key_switch_component_material,
            )?;
            add_accepted_key_switch_component_b(
                &mut aggregate_component_b,
                component_b,
                level_usize,
            )?;
        }
        let aggregate_component_b = aggregate_component_b.ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "public relinearization key aggregation requires at least one component share",
            )
        })?;
        let key_switch_key = key_switch_key_from_public_component_b(
            level_usize,
            "relinearization",
            &key_switch_seed_hex,
            aggregate_component_b,
        )?;
        relinearization_keys.insert(level_usize, key_switch_key);
    }

    Ok(relinearization_keys)
}

pub(in crate::bgv::setup) fn accepted_setup_public_galois_keys_from_transport(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<BTreeMap<(usize, usize), KeySwitchKey>> {
    let roster = super::super::accepted_roster_from_package(setup_package);
    let binding = evaluation_key_proof_common_binding(setup_package)?;
    let transported_key_switch_component_material =
        transported_evaluation_key_share_component_material_from_request(request)?;
    let transported_key_switch_component_material = request
        .get("transportedEvaluationKeyShareComponentMaterial")
        .or(transported_key_switch_component_material.as_ref());
    let batches = setup_package
        .get("galoisKeyShareBatches")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "galoisKeyShareBatches was required before public Galois key material loading",
            )
        })?;
    let mut sorted_batches = batches
        .iter()
        .map(|batch| Ok((value_u64(batch, "trusteeRosterPosition")?, batch)))
        .collect::<CanonicalResult<Vec<_>>>()?;
    sorted_batches.sort_by_key(|(trustee_roster_position, _)| *trustee_roster_position);
    if sorted_batches.len() != roster.participant_count as usize {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "accepted public Galois key material requires one proof batch per trustee",
        ));
    }
    let mut seen_trustee_roster_positions = BTreeSet::new();
    for (trustee_roster_position, _) in &sorted_batches {
        if !seen_trustee_roster_positions.insert(*trustee_roster_position) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "accepted public Galois key material must not repeat a trustee batch",
            ));
        }
    }
    let expected_schedule = expected_required_galois_key_schedule()?;
    let expected_schedule = expected_schedule.as_array().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "required Galois key schedule must be an array",
        )
    })?;
    let mut rotation_keys = BTreeMap::new();
    for schedule_entry in expected_schedule {
        let rotation = value_u64(schedule_entry, "rotation")?;
        let level = value_u64(schedule_entry, "level")?;
        let level_usize = usize::try_from(level).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "Galois key level does not fit usize",
            )
        })?;
        let rotation_usize = usize::try_from(rotation).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "Galois key rotation does not fit usize",
            )
        })?;
        let key_switch_domain = format!("galois-{rotation}");
        let key_switch_seed_hex = expected_galois_key_switch_seed(&binding, rotation, level)?;
        let mut aggregate_component_b = None;
        for (_, batch) in &sorted_batches {
            let proof_record = galois_key_share_material_for_schedule(batch, rotation, level)?;
            verify_galois_key_switch_sample_binding(proof_record, &binding, rotation, level)?;
            if value_u64(proof_record, "ringDegree")? != POLYNOMIAL_DEGREE as u64 {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "accepted public Galois key runtime material requires full-ring component vectors",
                ));
            }
            let component_b = component_b_vectors_from_record(
                EvaluationKeyShareProofFamily::Galois,
                proof_record,
                transported_key_switch_component_material,
            )?;
            add_accepted_key_switch_component_b(
                &mut aggregate_component_b,
                component_b,
                level_usize,
            )?;
        }
        let aggregate_component_b = aggregate_component_b.ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "public Galois key aggregation requires at least one component share",
            )
        })?;
        let key_switch_key = key_switch_key_from_public_component_b(
            level_usize,
            &key_switch_domain,
            &key_switch_seed_hex,
            aggregate_component_b,
        )?;
        rotation_keys.insert((rotation_usize, level_usize), key_switch_key);
    }

    Ok(rotation_keys)
}

fn add_accepted_key_switch_component_b(
    aggregate_component_b: &mut Option<Vec<Vec<Vec<u64>>>>,
    component_b: Vec<Vec<Vec<u64>>>,
    level: usize,
) -> CanonicalResult<()> {
    let primes = DATA_PRIMES.get(..=level).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "key-switch component aggregation level is outside Q_share",
        )
    })?;
    if component_b.len() != primes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "key-switch component aggregation digit count does not match its level",
        ));
    }
    match aggregate_component_b {
        None => {
            validate_key_switch_component_shape(&component_b, primes)?;
            *aggregate_component_b = Some(component_b);
        }
        Some(aggregate) => {
            validate_key_switch_component_shape(aggregate, primes)?;
            validate_key_switch_component_shape(&component_b, primes)?;
            for (digit_index, (aggregate_by_limb, component_by_limb)) in
                aggregate.iter_mut().zip(component_b.iter()).enumerate()
            {
                if aggregate_by_limb.len() != primes.len()
                    || component_by_limb.len() != primes.len()
                {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "key-switch component aggregation limb count does not match its level",
                    ));
                }
                for (rns_limb_index, (aggregate_coefficients, component_coefficients)) in
                    aggregate_by_limb
                        .iter_mut()
                        .zip(component_by_limb.iter())
                        .enumerate()
                {
                    if aggregate_coefficients.len() != POLYNOMIAL_DEGREE
                        || component_coefficients.len() != POLYNOMIAL_DEGREE
                    {
                        return Err(CanonicalError::new(
                            CanonicalErrorCode::MalformedLength,
                            "key-switch component aggregation requires full-ring coefficient vectors",
                        ));
                    }
                    let modulus = primes[rns_limb_index];
                    for (coefficient, addend) in aggregate_coefficients
                        .iter_mut()
                        .zip(component_coefficients.iter())
                    {
                        *coefficient = add_mod(*coefficient, *addend, modulus)?;
                    }
                }
                if digit_index >= primes.len() {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "key-switch component aggregation digit index is outside its level",
                    ));
                }
            }
        }
    }

    Ok(())
}

// The published runtime-key residues for one key as `[digit][limb][coeff]`: the
// per-limb sum of every trustee's `component_b`, mod each level prime. This is
// exactly the aggregate the two reconstruction functions above build before
// wrapping it into a `KeySwitchKey`, factored out so the S1 aggregate binding
// can bind against the identical residues the runtime key derives from without
// re-summing differently. `rotation` selects the key: `None` reads the
// relinearization round-two records for `level`; `Some(rotation)` reads the
// Galois material records for `(rotation, level)`. Fail-closed on a missing or
// repeated trustee record, exactly like the reconstruction path.
pub(super) fn accepted_key_switch_runtime_residues_by_digit(
    setup_package: &Value,
    request: &Value,
    rotation: Option<u64>,
    level: u64,
) -> CanonicalResult<Vec<Vec<Vec<u64>>>> {
    let roster = super::super::accepted_roster_from_package(setup_package);
    let binding = evaluation_key_proof_common_binding(setup_package)?;
    let transported_key_switch_component_material =
        transported_evaluation_key_share_component_material_from_request(request)?;
    let transported_key_switch_component_material = request
        .get("transportedEvaluationKeyShareComponentMaterial")
        .or(transported_key_switch_component_material.as_ref());
    let level_usize = usize::try_from(level).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "key-switch runtime residue level does not fit usize",
        )
    })?;

    let mut aggregate_component_b = None;
    match rotation {
        None => {
            let rounds = setup_package
                .get("relinearizationKeyShareRounds")
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "relinearizationKeyShareRounds was required before aggregate-binding residue recomputation",
                    )
                })?;
            let round_two_records = array_value(rounds, "roundTwoRecords")?;
            for trustee_roster_position in 0..roster.participant_count {
                let proof_record = relinearization_round_two_record_for_trustee_and_level(
                    round_two_records,
                    trustee_roster_position,
                    level,
                )?;
                verify_relinearization_key_switch_sample_binding(
                    proof_record,
                    &binding,
                    "round-two",
                    level,
                )?;
                if value_u64(proof_record, "ringDegree")? != POLYNOMIAL_DEGREE as u64 {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "aggregate-binding relinearization residue requires full-ring component vectors",
                    ));
                }
                let component_b = component_b_vectors_from_record(
                    EvaluationKeyShareProofFamily::Relinearization,
                    proof_record,
                    transported_key_switch_component_material,
                )?;
                add_accepted_key_switch_component_b(
                    &mut aggregate_component_b,
                    component_b,
                    level_usize,
                )?;
            }
        }
        Some(rotation) => {
            let batches = setup_package
                .get("galoisKeyShareBatches")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "galoisKeyShareBatches was required before aggregate-binding residue recomputation",
                    )
                })?;
            let mut sorted_batches = batches
                .iter()
                .map(|batch| Ok((value_u64(batch, "trusteeRosterPosition")?, batch)))
                .collect::<CanonicalResult<Vec<_>>>()?;
            sorted_batches.sort_by_key(|(trustee_roster_position, _)| *trustee_roster_position);
            if sorted_batches.len() != roster.participant_count as usize {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "aggregate-binding Galois residue requires one proof batch per trustee",
                ));
            }
            for (_, batch) in &sorted_batches {
                let proof_record = galois_key_share_material_for_schedule(batch, rotation, level)?;
                verify_galois_key_switch_sample_binding(proof_record, &binding, rotation, level)?;
                if value_u64(proof_record, "ringDegree")? != POLYNOMIAL_DEGREE as u64 {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "aggregate-binding Galois residue requires full-ring component vectors",
                    ));
                }
                let component_b = component_b_vectors_from_record(
                    EvaluationKeyShareProofFamily::Galois,
                    proof_record,
                    transported_key_switch_component_material,
                )?;
                add_accepted_key_switch_component_b(
                    &mut aggregate_component_b,
                    component_b,
                    level_usize,
                )?;
            }
        }
    }

    aggregate_component_b.ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "aggregate-binding residue recomputation requires at least one component share",
        )
    })
}

// A single trustee's relinearization round-two record for a level: the same
// canonical lookup the reconstruction path uses, refusing a missing or
// duplicated record.
fn relinearization_round_two_record_for_trustee_and_level(
    round_two_records: &[Value],
    trustee_roster_position: u64,
    level: u64,
) -> CanonicalResult<&Value> {
    let mut matching = None;
    for record in round_two_records {
        if value_string(record, "objectType")? != RELINEARIZATION_KEY_SHARE_ROUND_TWO_OBJECT_TYPE {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "aggregate-binding relinearization residue must use round-two records",
            ));
        }
        if value_u64(record, "level")? != level
            || value_u64(record, "trusteeRosterPosition")? != trustee_roster_position
        {
            continue;
        }
        if matching.is_some() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "aggregate-binding relinearization residue must not repeat a trustee record for a level",
            ));
        }
        matching = Some(record);
    }
    matching.ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "aggregate-binding relinearization residue is missing a trustee record for a level",
        )
    })
}

fn validate_key_switch_component_shape(
    component_b: &[Vec<Vec<u64>>],
    primes: &[u64],
) -> CanonicalResult<()> {
    if component_b.len() != primes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "key-switch component digit count does not match its level",
        ));
    }
    for component_by_limb in component_b {
        if component_by_limb.len() != primes.len() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "key-switch component limb count does not match its level",
            ));
        }
        for (rns_limb_index, coefficients) in component_by_limb.iter().enumerate() {
            if coefficients.len() != POLYNOMIAL_DEGREE {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "key-switch component coefficient count must match the full ring degree",
                ));
            }
            if coefficients
                .iter()
                .any(|coefficient| *coefficient >= primes[rns_limb_index])
            {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "key-switch component contains non-canonical Q_share residues",
                ));
            }
        }
    }

    Ok(())
}
