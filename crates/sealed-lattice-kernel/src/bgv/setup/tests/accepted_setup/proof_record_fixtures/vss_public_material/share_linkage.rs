use super::same_secret_bridge::*;
use super::*;

pub(in super::super::super) fn vss_share_linkage_statement_object(
    package: &serde_json::Value,
) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let target_basis_hash =
        crate::bgv::evaluator::top_k::canonical_target_basis_hash().expect("target basis hash");
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let participant_count = participant_count_from_package(package);
    let threshold_degree = package["vssPublicCoefficientCommitmentSet"]["thresholdDegree"]
        .as_u64()
        .expect("threshold degree");
    let ring_degree = package["vssPublicCoefficientCommitmentSet"]["ringDegree"]
        .as_u64()
        .expect("ring degree");
    let source_statement_records = (0..participant_count)
        .map(|source_trustee_roster_position| {
            vss_share_linkage_source_statement_record(
                package,
                &target_basis_hash,
                public_matrix_seed_hash,
                source_trustee_roster_position,
            )
        })
        .collect::<Vec<_>>();
    let mut statement = serde_json::json!({
        "objectType": "VssShareLinkageStatement",
        "objectVersion": 1,
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupParametersHash": setup_context["setupParametersHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "targetBasisHash": target_basis_hash,
        "ringDegree": ring_degree,
        "participantCount": participant_count,
        "targetRnsLimbCount": DATA_PRIMES.len(),
        "thresholdDegree": threshold_degree,
        "coefficientCommitmentRoot": package["vssPublicCoefficientCommitmentSet"]["coefficientCommitmentRoot"],
        "recipientShareCommitmentRoot": package["vssPublicRecipientShareCommitmentSet"]["recipientShareCommitmentRoot"],
        "aggregateThresholdCommitmentRoot": package["vssPublicAggregateThresholdCommitmentSet"]["aggregateThresholdCommitmentRoot"],
        "sourceStatementRecords": source_statement_records,
    });
    statement["statementRoot"] = serde_json::json!(
        derive_canonical_object_hash(&statement).expect("VSS share-linkage statement root")
    );

    statement
}

pub(super) fn vss_share_linkage_source_statement_record(
    package: &serde_json::Value,
    target_basis_hash: &str,
    public_matrix_seed_hash: &str,
    source_trustee_roster_position: u64,
) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let source_trustee_identity = format!("trustee-{source_trustee_roster_position}");
    let coefficient_source_record =
        vss_public_coefficient_source_record_from_package(package, source_trustee_roster_position);
    let recipient_source_record =
        vss_public_recipient_source_record_from_package(package, source_trustee_roster_position);
    let coefficient_opening_roots = coefficient_source_record["coefficientCommitments"]
        .as_array()
        .expect("coefficient commitments")
        .iter()
        .take(
            DATA_PRIMES.len()
                * package["vssPublicCoefficientCommitmentSet"]["thresholdDegree"]
                    .as_u64()
                    .expect("threshold degree") as usize,
        )
        .map(|record| record["coefficientOpeningRoot"].clone())
        .collect::<Vec<_>>();
    let recipient_share_opening_roots = recipient_source_record["recipientShareCommitments"]
        .as_array()
        .expect("recipient-share commitments")
        .iter()
        .map(|record| record["shareOpeningRoot"].clone())
        .collect::<Vec<_>>();
    let mut source_statement = serde_json::json!({
        "objectType": "VssShareLinkageSourceStatement",
        "objectVersion": 1,
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupParametersHash": setup_context["setupParametersHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "targetBasisHash": target_basis_hash,
        "sourceTrusteeIdentity": source_trustee_identity,
        "sourceTrusteeRosterPosition": source_trustee_roster_position,
        "ringDegree": package["vssPublicCoefficientCommitmentSet"]["ringDegree"],
        "participantCount": package["vssPublicCoefficientCommitmentSet"]["participantCount"],
        "targetRnsLimbCount": DATA_PRIMES.len(),
        "thresholdDegree": package["vssPublicCoefficientCommitmentSet"]["thresholdDegree"],
        "coefficientCommitmentRoot": package["vssPublicCoefficientCommitmentSet"]["coefficientCommitmentRoot"],
        "sourceCoefficientCommitmentRoot": coefficient_source_record["sourceCoefficientCommitmentRoot"],
        "sourceRecipientShareCommitmentRoot": recipient_source_record["sourceRecipientShareCommitmentRoot"],
        "coefficientOpeningRoots": coefficient_opening_roots,
        "recipientShareOpeningRoots": recipient_share_opening_roots,
        "aggregateThresholdCommitmentRoot": package["vssPublicAggregateThresholdCommitmentSet"]["aggregateThresholdCommitmentRoot"],
    });
    source_statement["sourceStatementRoot"] = serde_json::json!(
        derive_canonical_object_hash(&source_statement)
            .expect("VSS share-linkage source statement root")
    );

    source_statement
}

pub(in super::super::super) fn vss_share_linkage_proof_material_set_object(
    package: &serde_json::Value,
) -> serde_json::Value {
    let statement = &package["vssShareLinkageStatement"];
    let participant_count = participant_count_from_package(package);
    let proof_records = (0..participant_count)
        .flat_map(|source_trustee_roster_position| {
            vss_share_linkage_proof_records(package, source_trustee_roster_position)
        })
        .collect::<Vec<_>>();
    let mut proof_material_set = serde_json::json!({
        "objectType": "VssShareLinkageProofMaterialSet",
        "objectVersion": 1,
        "proofFamily": VSS_SHARE_LINKAGE_PROOF_FAMILY,
        "ceremonyId": statement["ceremonyId"],
        "manifestHash": statement["manifestHash"],
        "rosterHash": statement["rosterHash"],
        "setupParametersHash": statement["setupParametersHash"],
        "setupEpoch": statement["setupEpoch"],
        "publicMatrixSeedHash": statement["publicMatrixSeedHash"],
        "targetBasisHash": statement["targetBasisHash"],
        "ringDegree": statement["ringDegree"],
        "participantCount": statement["participantCount"],
        "targetRnsLimbCount": statement["targetRnsLimbCount"],
        "thresholdDegree": statement["thresholdDegree"],
        "coefficientCommitmentRoot": statement["coefficientCommitmentRoot"],
        "recipientShareCommitmentRoot": statement["recipientShareCommitmentRoot"],
        "aggregateThresholdCommitmentRoot": statement["aggregateThresholdCommitmentRoot"],
        "statementRoot": statement["statementRoot"],
        "proofRecords": proof_records,
    });
    proof_material_set["proofMaterialSetRoot"] = serde_json::json!(
        derive_canonical_object_hash(&proof_material_set)
            .expect("VSS share-linkage proof material set root")
    );

    proof_material_set
}

pub(super) fn vss_share_linkage_proof_records(
    package: &serde_json::Value,
    source_trustee_roster_position: u64,
) -> Vec<serde_json::Value> {
    let item_records = vss_share_linkage_item_records(package, source_trustee_roster_position);
    let proof_items_per_record = participant_count_from_package(package)
        .try_into()
        .expect("participant count fits usize");
    item_records
        .chunks(proof_items_per_record)
        .enumerate()
        .map(|(proof_record_index, item_records)| {
            vss_share_linkage_proof_record(
                package,
                source_trustee_roster_position,
                proof_record_index,
                item_records,
            )
        })
        .collect()
}

pub(super) fn vss_share_linkage_proof_record(
    package: &serde_json::Value,
    source_trustee_roster_position: u64,
    proof_record_index: usize,
    item_records: &[serde_json::Value],
) -> serde_json::Value {
    let vss_share_linkage = vss_share_linkage_proof_statement(package, item_records);
    let linkage_items = vss_share_linkage_coverage_items_from_records(item_records);
    let proof_bytes_hex = vss_share_linkage_proof_bytes_hex(
        package,
        &vss_share_linkage,
        source_trustee_roster_position,
        proof_record_index,
    );
    let proof_bytes = crate::transcript_core::decode_hex(&proof_bytes_hex)
        .expect("VSS share-linkage proof bytes");
    let mut proof_record = serde_json::json!({
        "objectType": "VssShareLinkageProofRecord",
        "objectVersion": 1,
        "proofFamily": VSS_SHARE_LINKAGE_PROOF_FAMILY,
        "linkageItems": linkage_items,
        "vssShareLinkage": vss_share_linkage,
        "proofBytesHash": hash512_hex(
            VSS_SHARE_LINKAGE_PROOF_BYTES_HASH_DOMAIN,
            &[&proof_bytes],
        ),
        "proofBytesBase64": crate::transcript_core::encode_standard_base64(&proof_bytes),
    });
    proof_record["proofRecordRoot"] = serde_json::json!(
        derive_canonical_object_hash(&proof_record).expect("VSS share-linkage proof record root")
    );

    proof_record
}

pub(super) fn vss_share_linkage_proof_statement(
    package: &serde_json::Value,
    item_records: &[serde_json::Value],
) -> serde_json::Value {
    let mut primary_item = item_records
        .first()
        .expect("VSS primary share-linkage item")
        .clone();
    primary_item["publicMatrixSeedHash"] =
        package["vssShareLinkageStatement"]["publicMatrixSeedHash"].clone();
    primary_item["shareLinkageStatementRoot"] =
        package["vssShareLinkageStatement"]["statementRoot"].clone();
    primary_item["additionalLinkageItems"] =
        serde_json::json!(item_records.iter().skip(1).cloned().collect::<Vec<_>>());

    primary_item
}

pub(super) fn vss_share_linkage_item_records(
    package: &serde_json::Value,
    source_trustee_roster_position: u64,
) -> Vec<serde_json::Value> {
    let participant_count = participant_count_from_package(package);
    (0..DATA_PRIMES.len())
        .flat_map(|rns_limb_index| {
            (0..participant_count).map(move |recipient_roster_position| {
                vss_share_linkage_item_record(
                    package,
                    source_trustee_roster_position,
                    recipient_roster_position,
                    rns_limb_index,
                )
            })
        })
        .collect()
}

pub(super) fn vss_share_linkage_item_record(
    package: &serde_json::Value,
    source_trustee_roster_position: u64,
    recipient_roster_position: u64,
    rns_limb_index: usize,
) -> serde_json::Value {
    let threshold_degree = package["vssPublicCoefficientCommitmentSet"]["thresholdDegree"]
        .as_u64()
        .expect("threshold degree") as usize;
    let coefficient_source_record =
        vss_public_coefficient_source_record_from_package(package, source_trustee_roster_position);
    let recipient_source_record =
        vss_public_recipient_source_record_from_package(package, source_trustee_roster_position);
    let coefficient_records = coefficient_source_record["coefficientCommitments"]
        .as_array()
        .expect("coefficient commitment records");
    let coefficient_record_offset = rns_limb_index
        .checked_mul(threshold_degree)
        .expect("coefficient record offset");
    let selected_coefficient_records = &coefficient_records
        [coefficient_record_offset..coefficient_record_offset + threshold_degree];
    let recipient_record = vss_public_recipient_share_commitment_record_from_package(
        package,
        source_trustee_roster_position,
        recipient_roster_position,
        rns_limb_index,
    );

    serde_json::json!({
        "sourceTrusteeIdentity": coefficient_source_record["sourceTrusteeIdentity"],
        "sourceTrusteeRosterPosition": source_trustee_roster_position,
        "sourceCoefficientCommitmentRoot": coefficient_source_record["sourceCoefficientCommitmentRoot"],
        "sourceRecipientShareCommitmentRoot": recipient_source_record["sourceRecipientShareCommitmentRoot"],
        "recipientIdentity": recipient_record["recipientIdentity"],
        "recipientRosterPosition": recipient_roster_position,
        "sourceRnsLimbIndex": rns_limb_index,
        "sourceMessageModulus": DATA_PRIMES[rns_limb_index],
        "coefficientCommitmentRoots": selected_coefficient_records
            .iter()
            .map(|record| record["coefficientCommitmentRoot"].clone())
            .collect::<Vec<_>>(),
        "coefficientOpeningRoots": selected_coefficient_records
            .iter()
            .map(|record| record["coefficientOpeningRoot"].clone())
            .collect::<Vec<_>>(),
        "coefficientCommitments": selected_coefficient_records
            .iter()
            .map(|record| record["commitment"].clone())
            .collect::<Vec<_>>(),
        "recipientShareCommitmentRoot": recipient_record["shareCommitmentRoot"],
        "recipientShareOpeningRoot": recipient_record["shareOpeningRoot"],
        "recipientShareCommitment": recipient_record["commitment"],
    })
}

pub(super) fn vss_share_linkage_coverage_items_from_records(
    item_records: &[serde_json::Value],
) -> Vec<serde_json::Value> {
    item_records
        .iter()
        .enumerate()
        .map(|(item_index, item_record)| {
            serde_json::json!({
                "sourceTrusteeRosterPosition": item_record["sourceTrusteeRosterPosition"],
                "recipientRosterPosition": item_record["recipientRosterPosition"],
                "sourceRnsLimbIndex": item_record["sourceRnsLimbIndex"],
                "itemIndex": item_index,
            })
        })
        .collect()
}

pub(super) fn vss_share_linkage_proof_bytes_hex(
    package: &serde_json::Value,
    vss_share_linkage: &serde_json::Value,
    source_trustee_roster_position: u64,
    proof_record_index: usize,
) -> String {
    let request = vss_share_linkage_proof_generation_request(
        package,
        vss_share_linkage,
        source_trustee_roster_position,
        proof_record_index,
    );
    let checkpoint_key = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "VssShareLinkageProofCheckpointKey",
        "statementRoot": package["vssShareLinkageStatement"]["statementRoot"],
        "sourceTrusteeRosterPosition": source_trustee_roster_position,
        "proofRecordIndex": proof_record_index,
        "vssShareLinkage": vss_share_linkage,
    }))
    .expect("VSS share-linkage proof checkpoint key");
    let proof_bytes = checkpointed_anchor_proof_bytes(
        VSS_SHARE_LINKAGE_PROOF_CHECKPOINT_DIRECTORY,
        &checkpoint_key,
        || {
            let generated = generate_vss_share_linkage_proof_from_request(&request)
                .expect("VSS share-linkage proof");
            crate::transcript_core::decode_hex(
                generated["proofBytesHex"]
                    .as_str()
                    .expect("VSS share-linkage proof bytes hex"),
            )
            .expect("VSS share-linkage proof bytes")
        },
    );

    to_hex(&proof_bytes)
}

pub(super) fn vss_share_linkage_statement_items(
    vss_share_linkage: &serde_json::Value,
) -> Vec<&serde_json::Value> {
    let mut items = vec![vss_share_linkage];
    items.extend(
        vss_share_linkage["additionalLinkageItems"]
            .as_array()
            .expect("VSS additional linkage items")
            .iter(),
    );

    items
}

pub(super) fn vss_share_linkage_coefficient_slots(
    linkage_items: &[&serde_json::Value],
    threshold_degree: u64,
) -> Vec<(usize, u64)> {
    let mut coefficient_slots = Vec::new();
    for item in linkage_items {
        let rns_limb_index = item["sourceRnsLimbIndex"]
            .as_u64()
            .expect("linkage item limb") as usize;
        for shamir_coefficient_index in 0..threshold_degree {
            let coefficient_slot = (rns_limb_index, shamir_coefficient_index);
            if !coefficient_slots.contains(&coefficient_slot) {
                coefficient_slots.push(coefficient_slot);
            }
        }
    }

    coefficient_slots
}

pub(super) fn vss_share_linkage_proof_generation_request(
    package: &serde_json::Value,
    vss_share_linkage: &serde_json::Value,
    source_trustee_roster_position: u64,
    proof_record_index: usize,
) -> serde_json::Value {
    let statement = &package["vssShareLinkageStatement"];
    let ring_degree = statement["ringDegree"]
        .as_u64()
        .expect("share-linkage ring degree") as usize;
    let threshold_degree = statement["thresholdDegree"]
        .as_u64()
        .expect("share-linkage threshold degree");
    let linkage_items = vss_share_linkage_statement_items(vss_share_linkage);
    let coefficient_slots = vss_share_linkage_coefficient_slots(&linkage_items, threshold_degree);
    let coefficient_messages_by_shamir_index = coefficient_slots
        .iter()
        .map(|(rns_limb_index, shamir_coefficient_index)| {
            accepted_vss_coefficient_message_fixture(
                source_trustee_roster_position,
                *rns_limb_index,
                *shamir_coefficient_index,
                DATA_PRIMES[*rns_limb_index],
                ring_degree,
            )
            .into_iter()
            .map(|value| i64::try_from(value).expect("coefficient message fits i64"))
            .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let coefficient_opening_randomness_by_shamir_index = coefficient_slots
        .iter()
        .map(|(rns_limb_index, shamir_coefficient_index)| {
            vss_public_coefficient_randomness_i64_fixture(
                source_trustee_roster_position,
                *rns_limb_index,
                *shamir_coefficient_index,
                ring_degree,
            )
        })
        .collect::<Vec<_>>();
    let mut recipient_share_messages_by_item = Vec::new();
    let mut recipient_share_opening_randomness_by_item = Vec::new();
    let mut carry_witnesses_by_item = Vec::new();
    for item in &linkage_items {
        let item_source_trustee_roster_position = item["sourceTrusteeRosterPosition"]
            .as_u64()
            .expect("linkage item source trustee");
        assert_eq!(
            item_source_trustee_roster_position, source_trustee_roster_position,
            "linkage proof batch must contain one source trustee"
        );
        let recipient_roster_position = item["recipientRosterPosition"]
            .as_u64()
            .expect("linkage item recipient");
        let rns_limb_index = item["sourceRnsLimbIndex"]
            .as_u64()
            .expect("linkage item limb") as usize;
        let (share_coefficients, carry_witnesses) = vss_public_recipient_share_values_and_carries(
            source_trustee_roster_position,
            recipient_roster_position,
            rns_limb_index,
            threshold_degree,
            DATA_PRIMES[rns_limb_index],
            ring_degree,
        );
        recipient_share_messages_by_item.push(
            share_coefficients
                .into_iter()
                .map(|value| i64::try_from(value).expect("recipient share fits i64"))
                .collect::<Vec<_>>(),
        );
        recipient_share_opening_randomness_by_item.push(
            vss_public_recipient_share_randomness_i64_fixture(
                source_trustee_roster_position,
                recipient_roster_position,
                rns_limb_index,
                ring_degree,
            ),
        );
        carry_witnesses_by_item.push(carry_witnesses);
    }
    let proof_randomness_seed_hex = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "VssPublicMaterialFixtureRandomness",
        "fixture": "vss-share-linkage-proof-randomness",
        "sourceTrusteeRosterPosition": source_trustee_roster_position,
        "proofRecordIndex": proof_record_index,
    }))
    .expect("VSS share-linkage proof randomness seed");
    let proof_randomness_nonce_hex = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "VssPublicMaterialFixtureRandomness",
        "fixture": "vss-share-linkage-proof-randomness-nonce",
        "sourceTrusteeRosterPosition": source_trustee_roster_position,
        "proofRecordIndex": proof_record_index,
    }))
    .expect("VSS share-linkage proof randomness nonce");

    serde_json::json!({
        "context": {
            "ceremonyId": statement["ceremonyId"],
            "manifestHash": statement["manifestHash"],
            "rosterHash": statement["rosterHash"],
            "trusteeIdentity": "vss-share-linkage",
            "trusteeRosterPosition": 0,
            "setupEpoch": statement["setupEpoch"],
            "shareLinkageStatementRoot": statement["statementRoot"],
        },
        "ringDegree": ring_degree,
        "vssShareLinkage": vss_share_linkage,
        "coefficientMessagesByShamirIndex": coefficient_messages_by_shamir_index,
        "recipientShareMessages": recipient_share_messages_by_item
            .first()
            .expect("primary recipient share messages"),
        "coefficientOpeningRandomnessByShamirIndex": coefficient_opening_randomness_by_shamir_index,
        "recipientShareOpeningRandomness": recipient_share_opening_randomness_by_item
            .first()
            .expect("primary recipient share opening randomness"),
        "carryWitnesses": carry_witnesses_by_item
            .first()
            .expect("primary carry witnesses"),
        "recipientShareMessagesByItem": recipient_share_messages_by_item,
        "recipientShareOpeningRandomnessByItem": recipient_share_opening_randomness_by_item,
        "carryWitnessesByItem": carry_witnesses_by_item,
        "proofRandomnessSeedHex": proof_randomness_seed_hex,
        "proofRandomnessNonceHex": proof_randomness_nonce_hex,
    })
}

pub(super) fn vss_public_coefficient_source_record_from_package(
    package: &serde_json::Value,
    source_trustee_roster_position: u64,
) -> &serde_json::Value {
    &package["vssPublicCoefficientCommitmentSet"]["sourceTrusteeRecords"]
        [source_trustee_roster_position as usize]
}

pub(super) fn vss_public_recipient_source_record_from_package(
    package: &serde_json::Value,
    source_trustee_roster_position: u64,
) -> &serde_json::Value {
    &package["vssPublicRecipientShareCommitmentSet"]["sourceTrusteeRecords"]
        [source_trustee_roster_position as usize]
}

pub(super) fn vss_public_recipient_share_commitment_record_from_package(
    package: &serde_json::Value,
    source_trustee_roster_position: u64,
    recipient_roster_position: u64,
    rns_limb_index: usize,
) -> serde_json::Value {
    let rns_limb_count = package["vssPublicRecipientShareCommitmentSet"]["rnsLimbCount"]
        .as_u64()
        .expect("recipient-share limb count") as usize;
    let record_index = (recipient_roster_position as usize)
        .checked_mul(rns_limb_count)
        .and_then(|offset| offset.checked_add(rns_limb_index))
        .expect("recipient-share record index");
    package["vssPublicRecipientShareCommitmentSet"]["sourceTrusteeRecords"]
        [source_trustee_roster_position as usize]["recipientShareCommitments"][record_index]
        .clone()
}

pub(super) fn vss_public_recipient_share_values_and_carries(
    source_trustee_roster_position: u64,
    recipient_roster_position: u64,
    rns_limb_index: usize,
    threshold_degree: u64,
    rns_prime: u64,
    ring_degree: usize,
) -> (Vec<u64>, Vec<i64>) {
    let recipient_trustee_point = crate::bgv::setup::sharing::canonical_trustee_point(
        recipient_roster_position as usize,
        rns_prime,
    )
    .expect("recipient trustee point");
    let coefficient_messages = (0..threshold_degree)
        .map(|shamir_coefficient_index| {
            accepted_vss_coefficient_message_fixture(
                source_trustee_roster_position,
                rns_limb_index,
                shamir_coefficient_index,
                rns_prime,
                ring_degree,
            )
        })
        .collect::<Vec<_>>();
    let mut trustee_point_powers = Vec::with_capacity(threshold_degree as usize);
    let mut trustee_point_power = 1_u128;
    for _ in 0..threshold_degree {
        trustee_point_powers.push(trustee_point_power);
        trustee_point_power = trustee_point_power
            .checked_mul(u128::from(recipient_trustee_point))
            .expect("recipient trustee point power");
    }
    let mut share_coefficients = Vec::with_capacity(ring_degree);
    let mut carry_witnesses = Vec::with_capacity(ring_degree);
    for coefficient_position in 0..ring_degree {
        let lifted_share = coefficient_messages
            .iter()
            .zip(trustee_point_powers.iter())
            .fold(0_u128, |sum, (messages, point_power)| {
                sum + u128::from(messages[coefficient_position]) * *point_power
            });
        share_coefficients.push((lifted_share % u128::from(rns_prime)) as u64);
        carry_witnesses.push(
            i64::try_from(lifted_share / u128::from(rns_prime))
                .expect("recipient share carry fits i64"),
        );
    }

    (share_coefficients, carry_witnesses)
}

pub(super) fn vss_public_recipient_share_randomness_i64_fixture(
    source_trustee_roster_position: u64,
    recipient_roster_position: u64,
    rns_limb_index: usize,
    ring_degree: usize,
) -> Vec<Vec<i64>> {
    let seed_offset = 10_000
        + source_trustee_roster_position as i64 * 503
        + recipient_roster_position as i64 * 37
        + rns_limb_index as i64 * 11;
    (0..crate::bgv::setup::vss_commitment::VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT)
        .map(|column_index| {
            (0..ring_degree)
                .map(|coefficient_position| {
                    ((seed_offset + column_index as i64 * 5 + coefficient_position as i64 * 7)
                        .rem_euclid(3))
                        - 1
                })
                .collect()
        })
        .collect()
}
