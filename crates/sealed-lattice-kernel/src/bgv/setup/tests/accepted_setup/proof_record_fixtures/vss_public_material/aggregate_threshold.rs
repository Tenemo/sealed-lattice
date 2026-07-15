use super::share_linkage::*;
use super::*;

pub(in super::super) const VSS_AGGREGATE_THRESHOLD_PROOF_CHECKPOINT_DIRECTORY: &str =
    "vss-aggregate-threshold-proof-material";

struct VssAggregateThresholdProofMaterialReference {
    proof_bytes_hash: String,
    proof_binding_lease: crate::bgv::setup::CanonicalSetupProofBindingLease,
}

// The proven threshold-share aggregate binding for every recipient and target
// limb: one share-linkage proof with a unit evaluation point per aggregate
// record, showing the committed threshold share T_{j,l} is the modular sum of
// the committed source recipient shares sigma_{i->j,l}. The proofs are a sibling
// of the aggregate set's recipientRecords, excluded from the set root (they are
// bound by their own statements, which reference the committed roots).
pub(in super::super) fn vss_aggregate_threshold_proofs(
    package: &serde_json::Value,
    aggregate_set: &serde_json::Value,
    recipient_coordinates: &[(u64, usize)],
) -> VssProofRecordSetFixture {
    let participant_count = participant_count_from_package(package);
    let ring_degree = vss_commitment_ring_degree_from_fixture_package(package);
    let recipient_records = aggregate_set["recipientRecords"]
        .as_array()
        .expect("aggregate recipient records");
    assert_eq!(
        recipient_records.len(),
        recipient_coordinates.len(),
        "aggregate recipient records and canonical coordinates",
    );
    let proof_material_references = recipient_records
        .iter()
        .zip(recipient_coordinates.iter().copied())
        .map(
            |(aggregate_record, (recipient_roster_position, rns_limb_index))| {
                vss_aggregate_threshold_proof_record(
                    package,
                    aggregate_record,
                    participant_count,
                    ring_degree,
                    recipient_roster_position,
                    rns_limb_index,
                )
            },
        )
        .collect::<Vec<_>>();
    VssProofRecordSetFixture {
        proof_bytes_hashes: proof_material_references
            .iter()
            .map(|reference| reference.proof_bytes_hash.clone())
            .collect(),
        proof_binding_leases: proof_material_references
            .into_iter()
            .map(|reference| reference.proof_binding_lease)
            .collect(),
    }
}

fn vss_aggregate_threshold_proof_record(
    package: &serde_json::Value,
    aggregate_record: &serde_json::Value,
    participant_count: u64,
    ring_degree: usize,
    recipient_roster_position: u64,
    rns_limb_index: usize,
) -> VssAggregateThresholdProofMaterialReference {
    let threshold_degree = vss_fixture_threshold_degree(package);
    let rns_prime = DATA_PRIMES[rns_limb_index];
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");

    // The n source recipient-share commitments for this recipient and limb are
    // the summands; the aggregate record's committed material is the sum.
    let source_share_records = (0..participant_count)
        .map(|source_trustee_roster_position| {
            vss_public_recipient_share_commitment_record_from_package(
                package,
                source_trustee_roster_position,
                recipient_roster_position,
                rns_limb_index,
            )
        })
        .collect::<Vec<_>>();
    let mut summand_messages = Vec::with_capacity(source_share_records.len());
    for source_trustee_roster_position in 0..participant_count {
        let (share_values, _carries) = vss_public_recipient_share_values_and_carries(
            source_trustee_roster_position,
            recipient_roster_position,
            rns_limb_index,
            threshold_degree,
            rns_prime,
            ring_degree,
        );
        summand_messages.push(
            share_values
                .into_iter()
                .map(|value| i64::try_from(value).expect("summand fits i64"))
                .collect::<Vec<i64>>(),
        );
    }
    let mut aggregate_message = vec![0_i64; ring_degree];
    let mut wrap_witnesses = vec![0_i64; ring_degree];
    for coefficient_position in 0..ring_degree {
        let summed = summand_messages.iter().fold(0_u128, |sum, messages| {
            sum + u128::from(u64::try_from(messages[coefficient_position]).expect("summand"))
        });
        aggregate_message[coefficient_position] =
            i64::try_from(summed % u128::from(rns_prime)).expect("aggregate fits i64");
        wrap_witnesses[coefficient_position] =
            i64::try_from(summed / u128::from(rns_prime)).expect("wrap fits i64");
    }

    let coefficient_source_records =
        package["vssPublicCoefficientCommitmentSet"]["sourceTrusteeRecords"]
            .as_array()
            .expect("VSS coefficient source records");
    let recipient_source_records =
        package["vssPublicRecipientShareCommitmentSet"]["sourceTrusteeRecords"]
            .as_array()
            .expect("VSS recipient-share source records");
    let aggregate_record_index = usize::try_from(recipient_roster_position)
        .expect("recipient roster position fits usize")
        .checked_mul(DATA_PRIMES.len())
        .and_then(|offset| offset.checked_add(rns_limb_index))
        .expect("aggregate record index fits usize");
    let trustee_identities = (0..participant_count)
        .map(|roster_position| format!("trustee-{roster_position}"))
        .collect::<Vec<_>>();
    let vss_aggregate =
        crate::bgv::setup::vss_commitment::vss_aggregate_threshold_statement_from_commitment_records(
            crate::bgv::setup::vss_commitment::VssAggregateThresholdStatementInput {
                public_matrix_seed_hash,
                participant_count: usize::try_from(participant_count)
                    .expect("participant count fits usize"),
                rns_limb_count: DATA_PRIMES.len(),
                coefficient_source_records,
                recipient_source_records,
                aggregate_record,
                aggregate_record_index,
                trustee_identities: &trustee_identities,
            },
    )
    .expect("canonical VSS aggregate threshold statement");
    vss_aggregate_threshold_proof_material_reference(
        package,
        &vss_aggregate,
        &summand_messages,
        &aggregate_message,
        &wrap_witnesses,
        recipient_roster_position,
        rns_limb_index,
    )
}

#[allow(clippy::too_many_arguments)]
fn vss_aggregate_threshold_proof_material_reference(
    package: &serde_json::Value,
    vss_aggregate: &serde_json::Value,
    summand_messages: &[Vec<i64>],
    aggregate_message: &[i64],
    wrap_witnesses: &[i64],
    recipient_roster_position: u64,
    rns_limb_index: usize,
) -> VssAggregateThresholdProofMaterialReference {
    let request = vss_aggregate_threshold_proof_generation_request(
        package,
        vss_aggregate,
        summand_messages,
        aggregate_message,
        wrap_witnesses,
        recipient_roster_position,
        rns_limb_index,
    );
    let checkpoint_key = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "VssAggregateThresholdProofCheckpointKey",
        "proverRevision": "aggregate-unit-point-trit-proof-v2",
        "recipientRosterPosition": recipient_roster_position,
        "rnsLimbIndex": rns_limb_index,
        "vssShareLinkage": vss_aggregate,
    }))
    .expect("VSS aggregate threshold proof checkpoint key");
    let proof_bytes = checkpointed_vss_aggregate_threshold_proof_bytes(
        &checkpoint_key,
        |proof_bytes| {
            verify_vss_share_linkage_proof_source_from_request(&request, proof_bytes).map(|_| ())
        },
        || generated_vss_aggregate_threshold_proof_bytes(&request),
    );
    let proof_bytes_hash = hash512_hex(VSS_SHARE_LINKAGE_PROOF_BYTES_HASH_DOMAIN, &[&proof_bytes]);
    if crate::bgv::setup::verified_canonical_setup_proof_material_bytes(
        VSS_SHARE_LINKAGE_PROOF_FAMILY,
        &proof_bytes_hash,
    )
    .expect("VSS aggregate threshold generated proof material lookup")
    .is_none()
    {
        authenticate_setup_proof_material_stream_for_test(
            VSS_SHARE_LINKAGE_PROOF_FAMILY,
            &proof_bytes_hash,
            &proof_bytes,
        )
        .expect("authenticate VSS aggregate threshold proof material stream");
    }
    let proof_binding_session =
        crate::bgv::setup::begin_accepted_setup_fixture_proof_binding_session()
            .expect("begin VSS aggregate threshold proof binding session");
    crate::bgv::setup::trustee_evaluation_key_proof::verify_and_retain_vss_share_linkage_proof_binding(
        &proof_binding_session,
        &proof_bytes_hash,
        &request,
    )
    .expect("verify VSS aggregate threshold proof before releasing its bytes");
    let proof_binding_lease =
        crate::bgv::setup::finish_accepted_setup_fixture_proof_binding_session(
            proof_binding_session,
            &proof_bytes_hash,
        )
        .expect("retain VSS aggregate threshold verifier-owned binding lease");

    VssAggregateThresholdProofMaterialReference {
        proof_bytes_hash,
        proof_binding_lease,
    }
}

fn checkpointed_vss_aggregate_threshold_proof_bytes(
    checkpoint_key: &str,
    verify_resumed_proof_bytes: impl FnOnce(&[u8]) -> crate::encoding::CanonicalResult<()>,
    generate_proof_bytes: impl FnOnce() -> Vec<u8>,
) -> Vec<u8> {
    checkpointed_proof_bytes(
        VSS_AGGREGATE_THRESHOLD_PROOF_CHECKPOINT_DIRECTORY,
        checkpoint_key,
        verify_resumed_proof_bytes,
        generate_proof_bytes,
    )
}

fn generated_vss_aggregate_threshold_proof_bytes(request: &serde_json::Value) -> Vec<u8> {
    let generated = generate_vss_share_linkage_proof_from_request(request)
        .expect("VSS aggregate threshold proof");
    let proof_bytes_hash = generated["proofBytesHash"]
        .as_str()
        .expect("VSS aggregate threshold proof bytes hash");
    let proof_material = crate::bgv::setup::take_verified_canonical_proof_material_bytes(
        VSS_SHARE_LINKAGE_PROOF_FAMILY,
        proof_bytes_hash,
    )
    .expect("VSS aggregate threshold generated proof material lookup")
    .expect("VSS aggregate threshold generated proof material");
    assert_eq!(
        proof_material
            .hash512_hex(VSS_SHARE_LINKAGE_PROOF_BYTES_HASH_DOMAIN)
            .expect("VSS aggregate threshold streamed proof bytes hash"),
        proof_bytes_hash,
        "generated VSS aggregate threshold proof metadata must bind its retained bytes",
    );

    match std::sync::Arc::try_unwrap(proof_material) {
        Ok(proof_material) => proof_material.into_contiguous(),
        Err(_) => panic!(
            "generated VSS aggregate-threshold proof bytes must have one store owner before checkpoint persistence"
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn vss_aggregate_threshold_proof_generation_request(
    package: &serde_json::Value,
    vss_aggregate: &serde_json::Value,
    summand_messages: &[Vec<i64>],
    aggregate_message: &[i64],
    wrap_witnesses: &[i64],
    recipient_roster_position: u64,
    rns_limb_index: usize,
) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let setup_context_hash = crate::bgv::setup::accepted_setup::setup_context_hash(setup_context)
        .expect("setup context hash");
    let ring_degree = vss_commitment_ring_degree_from_fixture_package(package);
    let mut context_hashes = vss_aggregate["coefficientCommitments"]
        .as_array()
        .expect("aggregate coefficient commitments")
        .iter()
        .map(|commitment| {
            commitment["commitmentContextHash"]
                .as_str()
                .expect("summand commitment context hash")
                .to_string()
        })
        .collect::<Vec<_>>();
    context_hashes.push(
        vss_aggregate["recipientShareCommitment"]["commitmentContextHash"]
            .as_str()
            .expect("aggregate commitment context hash")
            .to_string(),
    );
    let material_seeds = context_hashes
        .iter()
        .map(|context_hash| super::accepted_vss_material_seed(context_hash))
        .collect::<Vec<_>>();
    let proof_randomness_seed_hex = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "VssAggregateThresholdProofRandomness",
        "fixture": "vss-aggregate-threshold-proof-randomness",
        "recipientRosterPosition": recipient_roster_position,
        "rnsLimbIndex": rns_limb_index,
    }))
    .expect("VSS aggregate threshold proof randomness seed");
    serde_json::json!({
        "context": {
            "setupContextHash": setup_context_hash,
            "trusteeIdentity": "vss-aggregate-threshold",
            "trusteeRosterPosition": 0,
        },
        "ringDegree": ring_degree,
        "vssShareLinkage": vss_aggregate,
        "coefficientMessagesByShamirIndex": summand_messages,
        "recipientShareMessagesByItem": vec![aggregate_message.to_vec()],
        "carryWitnessesByItem": vec![wrap_witnesses.to_vec()],
        "vssCommittedMaterialSeedsByBoundMessage": material_seeds,
        "proofRandomnessSeedHex": proof_randomness_seed_hex,
    })
}
