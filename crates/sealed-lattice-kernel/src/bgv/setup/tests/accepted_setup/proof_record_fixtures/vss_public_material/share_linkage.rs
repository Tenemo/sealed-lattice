use super::*;

struct VssShareLinkageProofMaterialIdentity {
    proof_bytes_hash: String,
    proof_material_root: String,
}

struct VssShareLinkageProofMaterialReference {
    identity: VssShareLinkageProofMaterialIdentity,
    proof_binding_lease: crate::bgv::setup::CanonicalSetupProofBindingLease,
}

fn vss_share_linkage_proof_material_identity_from_bytes(
    proof_bytes: &[u8],
) -> VssShareLinkageProofMaterialIdentity {
    let proof_bytes_hash = hash512_hex(VSS_SHARE_LINKAGE_PROOF_BYTES_HASH_DOMAIN, &[proof_bytes]);
    let proof_material_root = crate::bgv::setup::setup_proof::setup_proof_material_reference_root(
        VSS_SHARE_LINKAGE_PROOF_FAMILY,
        &proof_bytes_hash,
    )
    .expect("VSS share-linkage proof material root");

    VssShareLinkageProofMaterialIdentity {
        proof_bytes_hash,
        proof_material_root,
    }
}

fn verify_and_retain_vss_share_linkage_proof_binding(
    proof_material_root: &str,
    request: &serde_json::Value,
) -> crate::encoding::CanonicalResult<crate::bgv::setup::CanonicalSetupProofBindingLease> {
    let proof_binding_session =
        match crate::bgv::setup::begin_accepted_setup_fixture_proof_binding_session() {
            Ok(proof_binding_session) => proof_binding_session,
            Err(error) => {
                crate::bgv::setup::evict_verified_canonical_setup_proof_materials(&[
                    proof_material_root.to_string(),
                ]);
                return Err(error);
            }
        };
    if let Err(error) = crate::bgv::setup::trustee_evaluation_key_proof::verify_and_retain_vss_share_linkage_proof_binding(
        &proof_binding_session,
        proof_material_root,
        request,
    ) {
        let _ = crate::bgv::setup::cancel_accepted_setup_proof_binding_session(
            proof_binding_session.session_handle,
        );
        crate::bgv::setup::evict_verified_canonical_setup_proof_materials(&[
            proof_material_root.to_string(),
        ]);
        return Err(error);
    }
    match crate::bgv::setup::finish_accepted_setup_fixture_proof_binding_session(
        proof_binding_session,
        proof_material_root,
    ) {
        Ok(proof_binding_lease) => Ok(proof_binding_lease),
        Err(error) => {
            crate::bgv::setup::evict_verified_canonical_setup_proof_materials(&[
                proof_material_root.to_string(),
            ]);
            Err(error)
        }
    }
}

// One share-linkage statement already supports a conjunction of independent
// source-recipient-limb items. Group several RNS limbs for the same source in
// one proof so the prover does not rebuild the fixed transcript, witness-tree,
// and low-degree-test machinery seventeen times per source. The four-limb cap
// reduces the ten-participant profile from 170 proofs to 50 without creating
// one proof over all seventeen limbs; every source-recipient-limb coordinate
// remains explicitly listed and is checked by the verifier's existing coverage
// map.
const VSS_SHARE_LINKAGE_RNS_LIMBS_PER_PROOF_RECORD: usize = 4;

pub(in super::super::super) fn vss_share_linkage_statement_object(
    package: &serde_json::Value,
) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let participant_count = participant_count_from_package(package);
    let threshold_degree = vss_fixture_threshold_degree(package);
    let ring_degree = vss_commitment_ring_degree_from_fixture_package(package);
    let setup_context_hash = crate::bgv::setup::accepted_setup::setup_context_hash(setup_context)
        .expect("setup context hash");
    let mut statement = serde_json::json!({
        "objectType": "VssShareLinkageStatement",
        "setupContextHash": setup_context_hash,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "ringDegree": ring_degree,
        "participantCount": participant_count,
        "qShareRnsLimbCount": DATA_PRIMES.len(),
        "thresholdDegree": threshold_degree,
        "coefficientCommitmentRoot": package["vssPublicCoefficientCommitmentSet"]["coefficientCommitmentRoot"],
        "recipientShareCommitmentRoot": package["vssPublicRecipientShareCommitmentSet"]["recipientShareCommitmentRoot"],
        "aggregateThresholdCommitmentRoot": package["vssPublicAggregateThresholdCommitmentSet"]["aggregateThresholdCommitmentRoot"],
    });
    statement["statementRoot"] = serde_json::json!(
        derive_canonical_object_hash(&statement).expect("VSS share-linkage statement root")
    );

    statement
}

pub(in super::super::super) fn vss_share_linkage_proof_material_set_object(
    package: &serde_json::Value,
) -> VssProofMaterialSetFixture {
    let participant_count = participant_count_from_package(package);
    let proof_record_fixtures = (0..participant_count)
        .flat_map(|source_trustee_roster_position| {
            vss_share_linkage_proof_records(package, source_trustee_roster_position)
        })
        .collect::<Vec<_>>();
    VssProofMaterialSetFixture {
        value: serde_json::json!({
            "objectType": "VssShareLinkageProofMaterialSet",
            "proofRecords": proof_record_fixtures
                .iter()
                .map(|fixture| fixture.record.clone())
                .collect::<Vec<_>>(),
        }),
        proof_binding_leases: proof_record_fixtures
            .into_iter()
            .map(|fixture| fixture.proof_binding_lease)
            .collect(),
    }
}

pub(super) fn vss_share_linkage_proof_records(
    package: &serde_json::Value,
    source_trustee_roster_position: u64,
) -> Vec<VssProofRecordFixture> {
    let item_records = vss_share_linkage_item_records(package, source_trustee_roster_position);
    let participant_count: usize = participant_count_from_package(package)
        .try_into()
        .expect("participant count fits usize");
    let proof_items_per_record = participant_count
        .checked_mul(VSS_SHARE_LINKAGE_RNS_LIMBS_PER_PROOF_RECORD)
        .expect("VSS share-linkage proof item count");
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
) -> VssProofRecordFixture {
    let vss_share_linkage = vss_share_linkage_proof_statement(package, item_records);
    let proof_material = vss_share_linkage_proof_material_reference(
        package,
        &vss_share_linkage,
        source_trustee_roster_position,
        proof_record_index,
    );
    let proof_record = serde_json::json!({
        "objectType": "VssShareLinkageProofRecord",
        "vssShareLinkage": vss_share_linkage,
        "proofBytesHash": proof_material.identity.proof_bytes_hash,
        "proofMaterialRoot": proof_material.identity.proof_material_root,
    });

    VssProofRecordFixture {
        record: proof_record,
        proof_binding_lease: proof_material.proof_binding_lease,
    }
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
    let threshold_degree = vss_fixture_threshold_degree(package) as usize;
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
        "coefficientCommitments": selected_coefficient_records
            .iter()
            .map(|record| record["commitment"].clone())
            .collect::<Vec<_>>(),
        "recipientShareCommitmentRoot": recipient_record["shareCommitmentRoot"],
        "recipientShareCommitment": recipient_record["commitment"],
    })
}

fn vss_share_linkage_proof_material_reference(
    package: &serde_json::Value,
    vss_share_linkage: &serde_json::Value,
    source_trustee_roster_position: u64,
    proof_record_index: usize,
) -> VssShareLinkageProofMaterialReference {
    let request = vss_share_linkage_proof_generation_request(
        package,
        vss_share_linkage,
        source_trustee_roster_position,
        proof_record_index,
    );
    let checkpoint_key = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "VssShareLinkageProofCheckpointKey",
        // The revision invalidates cached proofs when proof bytes can change
        // without changing the statement root. "trit" identifies the current
        // trit-granular message-claim layout.
        "proverRevision": "share-linkage-trit",
        "statementRoot": package["vssShareLinkageStatement"]["statementRoot"],
        "sourceTrusteeRosterPosition": source_trustee_roster_position,
        "proofRecordIndex": proof_record_index,
        "vssShareLinkage": vss_share_linkage,
    }))
    .expect("VSS share-linkage proof checkpoint key");
    if !final_package_checkpoint_resume_enabled() {
        let generated = generate_vss_share_linkage_proof_from_request(&request)
            .expect("VSS share-linkage proof");
        let proof_material_identity = VssShareLinkageProofMaterialIdentity {
            proof_bytes_hash: generated["proofBytesHash"]
                .as_str()
                .expect("VSS share-linkage proof bytes hash")
                .to_string(),
            proof_material_root: generated["proofMaterialRoot"]
                .as_str()
                .expect("VSS share-linkage proof material root")
                .to_string(),
        };
        assert_eq!(
            crate::bgv::setup::setup_proof::setup_proof_material_reference_root(
                VSS_SHARE_LINKAGE_PROOF_FAMILY,
                &proof_material_identity.proof_bytes_hash,
            )
            .expect("VSS share-linkage generated proof material root"),
            proof_material_identity.proof_material_root,
            "generated VSS share-linkage metadata must bind its retained bytes",
        );
        let proof_binding_lease = verify_and_retain_vss_share_linkage_proof_binding(
            &proof_material_identity.proof_material_root,
            &request,
        )
        .expect("verify VSS share-linkage proof before releasing its bytes");

        return VssShareLinkageProofMaterialReference {
            identity: proof_material_identity,
            proof_binding_lease,
        };
    }

    let mut resumed_proof_material_reference = None;
    let proof_bytes = checkpointed_proof_bytes(
        VSS_SHARE_LINKAGE_PROOF_CHECKPOINT_DIRECTORY,
        &checkpoint_key,
        |proof_bytes| {
            let proof_material_identity =
                vss_share_linkage_proof_material_identity_from_bytes(proof_bytes);
            authenticate_setup_proof_material_stream_for_test(
                VSS_SHARE_LINKAGE_PROOF_FAMILY,
                &proof_material_identity.proof_material_root,
                proof_bytes,
            )?;
            let proof_binding_lease = verify_and_retain_vss_share_linkage_proof_binding(
                &proof_material_identity.proof_material_root,
                &request,
            )?;
            resumed_proof_material_reference = Some(VssShareLinkageProofMaterialReference {
                identity: proof_material_identity,
                proof_binding_lease,
            });
            Ok(())
        },
        || {
            let generated = generate_vss_share_linkage_proof_from_request(&request)
                .expect("VSS share-linkage proof");
            let proof_material_root = generated["proofMaterialRoot"]
                .as_str()
                .expect("VSS share-linkage proof material root");
            let proof_bytes_hash = generated["proofBytesHash"]
                .as_str()
                .expect("VSS share-linkage proof bytes hash");
            let proof_material = crate::bgv::setup::take_verified_canonical_proof_material_bytes(
                VSS_SHARE_LINKAGE_PROOF_FAMILY,
                proof_material_root,
            )
            .expect("VSS share-linkage generated proof material lookup")
            .expect("VSS share-linkage generated proof material");
            assert_eq!(
                proof_material
                    .hash512_hex(VSS_SHARE_LINKAGE_PROOF_BYTES_HASH_DOMAIN)
                    .expect("VSS share-linkage streamed proof bytes hash"),
                proof_bytes_hash,
                "generated VSS share-linkage metadata must bind its retained bytes",
            );
            match std::sync::Arc::try_unwrap(proof_material) {
                Ok(proof_material) => proof_material.into_contiguous(),
                Err(_) => panic!(
                    "generated VSS share-linkage proof bytes must have one store owner before checkpoint persistence"
                ),
            }
        },
    );
    if let Some(proof_material_reference) = resumed_proof_material_reference {
        return proof_material_reference;
    }
    let proof_material_identity =
        vss_share_linkage_proof_material_identity_from_bytes(&proof_bytes);
    if crate::bgv::setup::verified_canonical_setup_proof_material_bytes(
        VSS_SHARE_LINKAGE_PROOF_FAMILY,
        &proof_material_identity.proof_material_root,
    )
    .expect("VSS share-linkage generated proof material lookup")
    .is_none()
    {
        authenticate_setup_proof_material_stream_for_test(
            VSS_SHARE_LINKAGE_PROOF_FAMILY,
            &proof_material_identity.proof_material_root,
            &proof_bytes,
        )
        .expect("authenticate VSS share-linkage proof material stream");
    }
    let proof_binding_lease = verify_and_retain_vss_share_linkage_proof_binding(
        &proof_material_identity.proof_material_root,
        &request,
    )
    .expect("verify VSS share-linkage proof before releasing its bytes");

    VssShareLinkageProofMaterialReference {
        identity: proof_material_identity,
        proof_binding_lease,
    }
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
    let mut recipient_share_messages_by_item = Vec::new();
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
        carry_witnesses_by_item.push(carry_witnesses);
    }
    // Committed-material regeneration inputs in bound-commitment order (every
    // unique coefficient slot, then each item's recipient share), read off the
    // published commitments' context hashes. The private seeds derive from those
    // public hashes, so the prover reproduces byte-identical trees without any
    // seed in the package.
    let (bound_material_seeds, bound_material_context_hashes) =
        vss_share_linkage_bound_material_inputs(&linkage_items, &coefficient_slots);
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
        "recipientShareMessagesByItem": recipient_share_messages_by_item,
        "carryWitnessesByItem": carry_witnesses_by_item,
        "vssCommittedMaterialSeedsByBoundMessage": bound_material_seeds,
        "vssCommittedMaterialContextHashesByBoundMessage": bound_material_context_hashes,
        "proofRandomnessSeedHex": proof_randomness_seed_hex,
        "proofRandomnessNonceHex": proof_randomness_nonce_hex,
    })
}

// Committed-material seeds and context hashes in the statement's
// bound-commitment order: every unique coefficient slot (in first-seen order
// across the linkage items) then each item's recipient share. Context hashes are
// read from the published commitments; seeds derive from them.
fn vss_share_linkage_bound_material_inputs(
    linkage_items: &[&serde_json::Value],
    coefficient_slots: &[(usize, u64)],
) -> (Vec<String>, Vec<String>) {
    let mut context_hashes = Vec::with_capacity(coefficient_slots.len() + linkage_items.len());
    for (rns_limb_index, shamir_coefficient_index) in coefficient_slots {
        let item = linkage_items
            .iter()
            .find(|item| {
                item["sourceRnsLimbIndex"]
                    .as_u64()
                    .expect("linkage item limb") as usize
                    == *rns_limb_index
            })
            .expect("linkage item for coefficient slot limb");
        let context_hash = item["coefficientCommitments"][*shamir_coefficient_index as usize]
            ["commitmentContextHash"]
            .as_str()
            .expect("coefficient commitment context hash")
            .to_string();
        context_hashes.push(context_hash);
    }
    for item in linkage_items {
        context_hashes.push(
            item["recipientShareCommitment"]["commitmentContextHash"]
                .as_str()
                .expect("recipient-share commitment context hash")
                .to_string(),
        );
    }
    let seeds = context_hashes
        .iter()
        .map(|context_hash| super::accepted_vss_material_seed(context_hash))
        .collect::<Vec<_>>();

    (seeds, context_hashes)
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
    let rns_limb_count = DATA_PRIMES.len();
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
