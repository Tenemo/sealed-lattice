use super::share_linkage::*;
use super::*;

pub(in super::super) const VSS_AGGREGATE_THRESHOLD_PROOF_CHECKPOINT_DIRECTORY: &str =
    "vss-aggregate-threshold-proof-material";

struct VssAggregateThresholdProofMaterialReference {
    proof_bytes_hash: String,
    proof_material_root: String,
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
) -> Vec<serde_json::Value> {
    let participant_count = participant_count_from_package(package);
    let ring_degree = package["vssPublicCoefficientCommitmentSet"]["ringDegree"]
        .as_u64()
        .expect("ring degree") as usize;
    let recipient_records = aggregate_set["recipientRecords"]
        .as_array()
        .expect("aggregate recipient records");
    recipient_records
        .iter()
        .map(|aggregate_record| {
            let recipient_roster_position = aggregate_record["recipientRosterPosition"]
                .as_u64()
                .expect("aggregate recipient roster position");
            let rns_limb_index = aggregate_record["rnsLimbIndex"]
                .as_u64()
                .expect("aggregate rns limb index") as usize;
            vss_aggregate_threshold_proof_record(
                package,
                aggregate_record,
                participant_count,
                ring_degree,
                recipient_roster_position,
                rns_limb_index,
            )
        })
        .collect()
}

pub(super) fn append_vss_aggregate_threshold_proof_material_transport(
    package: &mut serde_json::Value,
) {
    let aggregate_proofs =
        package["vssPublicAggregateThresholdCommitmentSet"]["aggregateThresholdProofs"]
            .as_array()
            .expect("VSS aggregate threshold proof records");
    let aggregate_materials = aggregate_proofs
        .iter()
        .map(|proof_record| {
            serde_json::json!({
                "objectType": "SetupTransportedVssShareLinkageProofMaterial",
                "proofMaterialRoot": proof_record["proofMaterialRoot"],
            })
        })
        .collect::<Vec<_>>();

    let package_object = package
        .as_object_mut()
        .expect("collective setup package object");
    let transported_material_set = package_object
        .entry("transportedVssShareLinkageProofMaterial")
        .or_insert_with(|| {
            serde_json::json!({
                "objectType": "SetupTransportedVssShareLinkageProofMaterialSet",
                "proofMaterials": [],
            })
        });
    assert_eq!(
        transported_material_set["objectType"], "SetupTransportedVssShareLinkageProofMaterialSet",
        "VSS share-linkage transport set object type",
    );
    let transported_materials = transported_material_set["proofMaterials"]
        .as_array_mut()
        .expect("VSS share-linkage transported proof materials");
    let mut retained_material_roots = transported_materials
        .iter()
        .map(|material| {
            material["proofMaterialRoot"]
                .as_str()
                .expect("VSS share-linkage transported proof material root")
                .to_string()
        })
        .collect::<std::collections::BTreeSet<_>>();
    for aggregate_material in aggregate_materials {
        let proof_material_root = aggregate_material["proofMaterialRoot"]
            .as_str()
            .expect("VSS aggregate threshold proof material root")
            .to_string();
        if retained_material_roots.insert(proof_material_root) {
            transported_materials.push(aggregate_material);
        }
    }
}

fn vss_aggregate_threshold_proof_record(
    package: &serde_json::Value,
    aggregate_record: &serde_json::Value,
    participant_count: u64,
    ring_degree: usize,
    recipient_roster_position: u64,
    rns_limb_index: usize,
) -> serde_json::Value {
    let threshold_degree = package["vssPublicCoefficientCommitmentSet"]["thresholdDegree"]
        .as_u64()
        .expect("threshold degree");
    let rns_prime = DATA_PRIMES[rns_limb_index];
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let recipient_identity = aggregate_record["recipientIdentity"]
        .as_str()
        .expect("aggregate recipient identity");

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

    let source_source_record =
        vss_public_recipient_source_record_from_package(package, recipient_roster_position);
    let source_recipient_share_commitment_root =
        source_source_record["sourceRecipientShareCommitmentRoot"]
            .as_str()
            .expect("source recipient-share commitment root")
            .to_string();
    let source_coefficient_source_record =
        vss_public_coefficient_source_record_from_package(package, recipient_roster_position);
    let source_coefficient_commitment_root =
        source_coefficient_source_record["sourceCoefficientCommitmentRoot"]
            .as_str()
            .expect("source coefficient commitment root")
            .to_string();

    let vss_aggregate = vss_aggregate_threshold_statement_object(
        public_matrix_seed_hash,
        recipient_identity,
        recipient_roster_position,
        rns_limb_index,
        rns_prime,
        &source_coefficient_commitment_root,
        &source_recipient_share_commitment_root,
        &source_share_records,
        aggregate_record,
    );
    let proof_material = vss_aggregate_threshold_proof_material_reference(
        package,
        &vss_aggregate,
        &summand_messages,
        &aggregate_message,
        &wrap_witnesses,
        recipient_roster_position,
        rns_limb_index,
    );

    serde_json::json!({
        "objectType": "VssAggregateThresholdProofRecord",
        "recipientRosterPosition": recipient_roster_position,
        "rnsLimbIndex": rns_limb_index,
        "vssShareLinkage": vss_aggregate,
        "proofBytesHash": proof_material.proof_bytes_hash,
        "proofMaterialRoot": proof_material.proof_material_root,
    })
}

// The unit-evaluation-point share-linkage statement for one aggregate record:
// the source recipient shares stand in for the coefficients, the aggregate
// threshold share for the recipient share.
#[allow(clippy::too_many_arguments)]
fn vss_aggregate_threshold_statement_object(
    public_matrix_seed_hash: &str,
    recipient_identity: &str,
    recipient_roster_position: u64,
    rns_limb_index: usize,
    rns_prime: u64,
    source_coefficient_commitment_root: &str,
    source_recipient_share_commitment_root: &str,
    source_share_records: &[serde_json::Value],
    aggregate_record: &serde_json::Value,
) -> serde_json::Value {
    let coefficient_commitment_roots = source_share_records
        .iter()
        .map(|record| record["shareCommitmentRoot"].clone())
        .collect::<Vec<_>>();
    let coefficient_commitments = source_share_records
        .iter()
        .map(|record| record["commitment"].clone())
        .collect::<Vec<_>>();
    let mut statement = serde_json::json!({
        "objectType": "VssShareLinkageStatement",
        "isThresholdAggregate": true,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "sourceTrusteeIdentity": recipient_identity,
        "sourceTrusteeRosterPosition": recipient_roster_position,
        "sourceCoefficientCommitmentRoot": source_coefficient_commitment_root,
        "sourceRecipientShareCommitmentRoot": source_recipient_share_commitment_root,
        "recipientIdentity": recipient_identity,
        "recipientRosterPosition": recipient_roster_position,
        "sourceRnsLimbIndex": rns_limb_index,
        "sourceMessageModulus": rns_prime,
        "coefficientCommitmentRoots": coefficient_commitment_roots,
        "coefficientCommitments": coefficient_commitments,
        "recipientShareCommitmentRoot": aggregate_record["aggregateCommitmentRoot"],
        "recipientShareCommitment": aggregate_record["commitment"],
        "additionalLinkageItems": [],
    });
    let statement_root =
        derive_canonical_object_hash(&statement).expect("VSS aggregate threshold statement root");
    statement["shareLinkageStatementRoot"] = serde_json::json!(statement_root);

    statement
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
    let proof_material_root = crate::bgv::setup::setup_proof::setup_proof_material_reference_root(
        VSS_SHARE_LINKAGE_PROOF_FAMILY,
        &proof_bytes_hash,
    )
    .expect("VSS aggregate threshold proof material root");
    if crate::bgv::setup::accepted_setup_fixture_proof_binding_lease(&proof_material_root)
        .expect("VSS aggregate threshold proof binding lookup")
        .is_none()
    {
        if crate::bgv::setup::verified_canonical_setup_proof_material_bytes(
            VSS_SHARE_LINKAGE_PROOF_FAMILY,
            &proof_material_root,
        )
        .expect("VSS aggregate threshold generated proof material lookup")
        .is_none()
        {
            authenticate_setup_proof_material_stream_for_test(
                VSS_SHARE_LINKAGE_PROOF_FAMILY,
                &proof_material_root,
                &proof_bytes,
            )
            .expect("authenticate VSS aggregate threshold proof material stream");
        }
        let proof_binding_session =
            crate::bgv::setup::begin_accepted_setup_fixture_proof_binding_session()
                .expect("begin VSS aggregate threshold proof binding session");
        crate::bgv::setup::trustee_evaluation_key_proof::verify_and_retain_vss_share_linkage_proof_binding(
            &proof_binding_session,
            &proof_material_root,
            &request,
        )
        .expect("verify VSS aggregate threshold proof before releasing its bytes");
        crate::bgv::setup::cache_accepted_setup_fixture_proof_binding_lease(
            proof_binding_session,
            &proof_material_root,
        )
        .expect("cache VSS aggregate threshold verifier-owned binding lease");
    }

    VssAggregateThresholdProofMaterialReference {
        proof_bytes_hash,
        proof_material_root,
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
    let proof_material_root = generated["proofMaterialRoot"]
        .as_str()
        .expect("VSS aggregate threshold proof material root");
    let proof_material = crate::bgv::setup::take_verified_canonical_proof_material_bytes(
        VSS_SHARE_LINKAGE_PROOF_FAMILY,
        proof_material_root,
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
    let ring_degree = package["vssPublicCoefficientCommitmentSet"]["ringDegree"]
        .as_u64()
        .expect("ring degree") as usize;
    // Bound-commitment order: the summand slots (coefficient commitments) then
    // the single aggregate recipient share. Context hashes read off the
    // published commitments; seeds derive from them.
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
    let proof_randomness_nonce_hex = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "VssAggregateThresholdProofRandomness",
        "fixture": "vss-aggregate-threshold-proof-randomness-nonce",
        "recipientRosterPosition": recipient_roster_position,
        "rnsLimbIndex": rns_limb_index,
    }))
    .expect("VSS aggregate threshold proof randomness nonce");

    serde_json::json!({
        "context": {
            "ceremonyId": setup_context["ceremonyId"],
            "manifestHash": setup_context["manifestHash"],
            "rosterHash": setup_context["rosterHash"],
            "trusteeIdentity": "vss-aggregate-threshold",
            "trusteeRosterPosition": 0,
            "setupEpoch": setup_context["setupEpoch"],
            "shareLinkageStatementRoot": vss_aggregate["shareLinkageStatementRoot"],
        },
        "ringDegree": ring_degree,
        "vssShareLinkage": vss_aggregate,
        "coefficientMessagesByShamirIndex": summand_messages,
        "recipientShareMessagesByItem": vec![aggregate_message.to_vec()],
        "carryWitnessesByItem": vec![wrap_witnesses.to_vec()],
        "vssCommittedMaterialSeedsByBoundMessage": material_seeds,
        "vssCommittedMaterialContextHashesByBoundMessage": context_hashes,
        "proofRandomnessSeedHex": proof_randomness_seed_hex,
        "proofRandomnessNonceHex": proof_randomness_nonce_hex,
    })
}
