use super::super::*;
use super::*;
use crate::hashing::derive_canonical_object_hash;

pub(in super::super) fn collective_public_key_object(
    package: &serde_json::Value,
) -> serde_json::Value {
    let material_records = package["publicKeyShareMaterial"]["shareMaterialRecords"]
        .as_array()
        .expect("public-key material records");
    let ring_degree = vss_commitment_ring_degree_from_fixture_package(package);
    let mut aggregate_coefficients_by_limb = (0..DATA_PRIMES.len())
        .map(|_| vec![0_u64; ring_degree])
        .collect::<Vec<_>>();
    for material_record in material_records {
        for (rns_limb_index, limb) in material_record["shareCoefficientVectorsByLimb"]
            .as_array()
            .expect("share limbs")
            .iter()
            .enumerate()
        {
            let coefficients = coefficient_vector_from_le_hex(
                limb["coefficientsLeHex"].as_str().expect("coefficient hex"),
                ring_degree,
                "public-key share coefficient width",
            )
            .expect("public-key share coefficients");
            for (coefficient_index, coefficient) in coefficients.iter().enumerate() {
                aggregate_coefficients_by_limb[rns_limb_index][coefficient_index] = add_mod(
                    aggregate_coefficients_by_limb[rns_limb_index][coefficient_index],
                    *coefficient,
                    DATA_PRIMES[rns_limb_index],
                )
                .expect("aggregate public-key coefficient");
            }
        }
    }
    let aggregate_limbs = aggregate_coefficients_by_limb
        .iter()
        .map(|coefficients| {
            serde_json::json!({
                "coefficientsLeHex": coefficient_vector_le_hex(coefficients),
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "objectType": "CollectivePublicKey",
        "aggregateCoefficientVectorsByLimb": aggregate_limbs,
    })
}

pub(in super::super) fn replace_public_key_share_hashes_with_material_hashes(
    package: &mut serde_json::Value,
) {
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash")
        .to_string();
    let ring_degree = vss_commitment_ring_degree_from_fixture_package(package);
    let participant_count = participant_count_from_package(package);
    for trustee_roster_position in 0..participant_count {
        let (coefficients_by_limb, _) = public_key_share_coefficients_and_errors_for_fixture(
            &public_matrix_seed_hash,
            trustee_roster_position,
            ring_degree,
        );
        let share_hashes = coefficients_by_limb
            .iter()
            .map(|coefficients| {
                serde_json::json!({
                    "coefficientVectorHash512": public_key_share_coefficient_vector_hash(coefficients),
                })
            })
            .collect::<Vec<_>>();
        package["publicKeyShares"]["shareRecords"][trustee_roster_position as usize]["shareCoefficientVectorHash512ByLimb"] =
            serde_json::json!(share_hashes);
    }
    package["evaluatorKeySchedule"]["publicKeyShareSetRoot"] = serde_json::json!(
        crate::bgv::setup::accepted_setup::derive_public_key_share_set_root(package)
            .expect("public-key share set root")
    );
}

pub(in super::super) fn public_key_share_material_object(
    package: &serde_json::Value,
) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let setup_context_hash = crate::bgv::setup::accepted_setup::setup_context_hash(setup_context)
        .expect("setup context hash");
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let ring_degree = vss_commitment_ring_degree_from_fixture_package(package);
    let participant_count = participant_count_from_package(package);
    let mut material_records = Vec::new();
    let mut material_root_references = Vec::new();
    for trustee_roster_position in 0..participant_count {
        let trustee_identity = format!("trustee-{trustee_roster_position}");
        let (coefficients_by_limb, _) = public_key_share_coefficients_and_errors_for_fixture(
            public_matrix_seed_hash,
            trustee_roster_position,
            ring_degree,
        );
        let limbs = coefficients_by_limb
            .iter()
            .map(|coefficients| {
                serde_json::json!({
                    "coefficientsLeHex": coefficient_vector_le_hex(coefficients),
                })
            })
            .collect::<Vec<_>>();
        let share_record =
            &package["publicKeyShares"]["shareRecords"][trustee_roster_position as usize];
        let public_key_share_root =
            crate::bgv::setup::accepted_setup::derive_public_key_share_root(
                setup_context,
                public_matrix_seed_hash,
                share_record,
            )
            .expect("public-key share root");
        let material_root_input = serde_json::json!({
            "objectType": "PublicKeyShareMaterial",
            "setupContextHash": setup_context_hash,
            "trusteeIdentity": trustee_identity.as_str(),
            "trusteeRosterPosition": trustee_roster_position,
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "publicKeyShareRoot": public_key_share_root,
            "shareCoefficientVectorsByLimb": limbs,
        });
        let public_key_share_material_root = derive_canonical_object_hash(&material_root_input)
            .expect("public-key share material root");
        let material_record = serde_json::json!({
            "objectType": "PublicKeyShareMaterial",
            "shareCoefficientVectorsByLimb":
                material_root_input["shareCoefficientVectorsByLimb"],
        });
        material_root_references.push(serde_json::json!({
            "trusteeIdentity": trustee_identity,
            "trusteeRosterPosition": trustee_roster_position,
            "publicKeyShareMaterialRoot": public_key_share_material_root,
        }));
        material_records.push(material_record);
    }
    let public_key_share_material_set_root = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "PublicKeyShareMaterialSet",
        "setupContextHash": setup_context_hash,
        "ringDegree": ring_degree,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "publicKeyShareSetRoot":
            crate::bgv::setup::accepted_setup::derive_public_key_share_set_root(package)
                .expect("public-key share set root"),
        "publicKeyShareMaterialRoots": material_root_references,
    }))
    .expect("public-key share material set root");

    serde_json::json!({
        "objectType": "PublicKeyShareMaterialSet",
        "shareMaterialRecords": material_records,
        "publicKeyShareMaterialSetRoot": public_key_share_material_set_root,
    })
}

pub(in super::super) fn authenticate_public_key_share_material_fixture(
    package: &serde_json::Value,
    accepted_setup_session: crate::bgv::setup::AcceptedSetupProofBindingSession,
) {
    let Some(material_set) = package.get("publicKeyShareMaterial") else {
        return;
    };
    let Some(material_records) = material_set
        .get("shareMaterialRecords")
        .and_then(serde_json::Value::as_array)
    else {
        return;
    };
    let ring_degree = vss_commitment_ring_degree_from_fixture_package(package);
    let mut material_bytes = Vec::new();
    material_bytes.extend_from_slice(b"SLPKSMV2");
    for material_record in material_records {
        for rns_limb_index in 0..DATA_PRIMES.len() {
            let coefficients = coefficient_vector_from_le_hex(
                material_record["shareCoefficientVectorsByLimb"][rns_limb_index]
                    ["coefficientsLeHex"]
                    .as_str()
                    .expect("public-key material coefficient bytes"),
                ring_degree,
                "public-key material coefficient width",
            )
            .expect("public-key material coefficients");
            for coefficient in coefficients {
                material_bytes.extend_from_slice(&coefficient.to_le_bytes());
            }
        }
    }

    let chunk_size = crate::foundation::FOUNDATION_PROFILE.stream_chunk_byte_length;
    let mut descriptor_writer = crate::foundation::CanonicalStreamWriter::new(
        crate::foundation::CanonicalStreamDomain::PublicKeyShareMaterial,
        u64::try_from(material_bytes.len()).expect("public-key material byte length fits u64"),
    )
    .expect("public-key material descriptor writer");
    for (chunk_index, chunk) in material_bytes.chunks(chunk_size).enumerate() {
        descriptor_writer
            .absorb_chunk(chunk_index, chunk)
            .expect("public-key material descriptor chunk");
    }
    let descriptor_bytes = descriptor_writer
        .finish()
        .expect("public-key material descriptor")
        .encode()
        .expect("public-key material descriptor bytes");
    let material_root_bytes = crate::transcript_core::decode_hex(
        material_set["publicKeyShareMaterialSetRoot"]
            .as_str()
            .expect("public-key material set root"),
    )
    .expect("public-key material set root bytes");
    let stream = crate::bgv::setup::begin_accepted_setup_canonical_stream(
        crate::bgv::setup::canonical_stream_transport::BGV_CANONICAL_STREAM_FAMILY_PUBLIC_KEY_SHARE_MATERIAL,
        &material_root_bytes,
        &descriptor_bytes,
        accepted_setup_session,
    )
    .expect("begin authenticated public-key material stream");
    for (chunk_index, chunk) in material_bytes.chunks(chunk_size).enumerate() {
        crate::bgv::setup::absorb_bgv_canonical_stream_chunk(
            stream.handle,
            u32::try_from(chunk_index).expect("public-key material chunk index fits u32"),
            chunk,
        )
        .expect("authenticate public-key material chunk");
    }
    crate::bgv::setup::finish_bgv_canonical_stream(stream.handle)
        .expect("finish authenticated public-key material stream");
}

pub(in super::super) fn public_key_share_coefficients_and_errors_for_fixture(
    public_matrix_seed_hash: &str,
    trustee_roster_position: u64,
    ring_degree: usize,
) -> (Vec<Vec<u64>>, Vec<i64>) {
    // One small centered-binomial error polynomial per trustee, shared across
    // every Q_share limb, so the public-key share relation b_l = p*e - a_l*s
    // holds for the single committed error column the succinct argument proves.
    let error_coefficients = (0..ring_degree)
        .map(|coefficient_position| {
            accepted_public_key_error_coefficient_fixture(
                trustee_roster_position,
                coefficient_position,
            )
        })
        .collect::<Vec<_>>();
    let mut coefficients_by_limb = Vec::new();
    for modulus in DATA_PRIMES.iter().copied() {
        let secret_residues = (0..ring_degree)
            .map(|coefficient_position| {
                signed_i64_residue_for_fixture(
                    accepted_vss_secret_coefficient_fixture(
                        trustee_roster_position,
                        coefficient_position,
                    ),
                    modulus,
                )
            })
            .collect::<Vec<_>>();
        let public_a =
            dense_public_residues(public_matrix_seed_hash, "accepted-bgv-public-a", modulus)
                .expect("the fixed public sampler derives within its candidate-draw limit")
                .into_iter()
                .take(ring_degree)
                .collect::<Vec<_>>();
        let product = negacyclic_product_mod(&public_a, &secret_residues, modulus)
            .expect("public-key product");
        let coefficients = error_coefficients
            .iter()
            .zip(product.iter())
            .map(|(error, product_coefficient)| {
                let scaled_error = mul_mod(
                    PLAINTEXT_MODULUS % modulus,
                    signed_i64_residue_for_fixture(*error, modulus),
                    modulus,
                )
                .expect("scaled error");
                sub_mod(scaled_error, *product_coefficient, modulus).expect("public-key share")
            })
            .collect::<Vec<_>>();
        coefficients_by_limb.push(coefficients);
    }

    (coefficients_by_limb, error_coefficients)
}

fn accepted_public_key_error_coefficient_fixture(
    trustee_roster_position: u64,
    coefficient_position: usize,
) -> i64 {
    match (trustee_roster_position as usize * 37 + coefficient_position * 5) % 5 {
        0 => -2,
        1 => -1,
        2 => 0,
        3 => 1,
        _ => 2,
    }
}

pub(in super::super) struct PublicKeyShareSuccinctProofFixture {
    pub(in super::super) proof_set: serde_json::Value,
    pub(in super::super) proof_binding_leases:
        Vec<crate::bgv::setup::CanonicalSetupProofBindingLease>,
}

struct PublicKeyShareSuccinctProofRecordFixture {
    proof_record: serde_json::Value,
    proof_binding_lease: crate::bgv::setup::CanonicalSetupProofBindingLease,
}

pub(in super::super) fn public_key_share_succinct_proofs_fixture(
    package: &serde_json::Value,
    proof_binding_session: &crate::bgv::setup::AcceptedSetupProofBindingSession,
) -> PublicKeyShareSuccinctProofFixture {
    use crate::bgv::setup::trustee_evaluation_key_proof::{
        EvaluationKeyShareDescriptor, KeyBearingWitness, PUBLIC_KEY_SHARE_COMMON_REFERENCE_LABEL,
        PUBLIC_KEY_SHARE_PROOF_FAMILY, SetupProofStatement, SuccinctSetupProofContext,
        TrusteeEvaluationKeyStatement, VssCommittedMaterialWitness,
        public_key_share_succinct_proof_bytes_hash, verify_trustee_evaluation_key_proof_bytes,
    };
    let setup_context = &package["setupContext"];
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let participant_count = participant_count_from_package(package);
    // Terminal public-key-share proofs bind the verified same-secret bridge
    // material that the accepted-setup verifier reconstructs.
    let verified_same_secret_bridge =
        crate::bgv::setup::accepted_setup::verified_same_secret_bridge_material_from_package(
            package,
            Some(proof_binding_session),
        )
        .expect("same-secret bridge material");
    let per_trustee_records = (0..participant_count)
        .map(|trustee_roster_position| {
            let trustee_identity = format!("trustee-{trustee_roster_position}");
            let bridge_binding = verified_same_secret_bridge
                .statement_for_roster_position(trustee_roster_position)
                .expect("same-secret bridge statement binding");
            assert_eq!(bridge_binding.trustee_identity, trustee_identity);
            let ring_degree = package["sameSecretBridgeStatementSet"]["ringDegree"]
                .as_u64()
                .expect("same-secret bridge ring degree") as usize;
            let (coefficients_by_limb, error_coefficients) =
                public_key_share_coefficients_and_errors_for_fixture(
                    public_matrix_seed_hash,
                    trustee_roster_position,
                    ring_degree,
                );
            let secret_coefficients = (0..ring_degree)
                .map(|coefficient_position| {
                    accepted_vss_secret_coefficient_fixture(
                        trustee_roster_position,
                        coefficient_position,
                    )
                })
                .collect::<Vec<_>>();
            let negative_indicator_coefficients = secret_coefficients
                .iter()
                .map(|coefficient| i64::from(*coefficient < 0))
                .collect();
            let committed_material_seeds =
            vss_public_material::same_secret_bridge_committed_material_seeds_from_fixture_package(
                package,
                trustee_roster_position,
            );
            let statement = TrusteeEvaluationKeyStatement {
                context: SuccinctSetupProofContext {
                    setup_context_hash: crate::bgv::setup::accepted_setup::setup_context_hash(
                        setup_context,
                    )
                    .expect("setup context hash"),
                    trustee_identity: trustee_identity.clone(),
                    trustee_roster_position,
                    binding_roots: Vec::new(),
                },
                ring_degree,
                proof: SetupProofStatement::PublicKeyShare {
                    key: EvaluationKeyShareDescriptor {
                        kind: EvaluationKeyShareKind::PublicKeyShare,
                        level: DATA_PRIMES.len() - 1,
                        key_switch_domain: PUBLIC_KEY_SHARE_COMMON_REFERENCE_LABEL.to_string(),
                        key_switch_seed_hex: public_matrix_seed_hash.to_string(),
                        component_b_by_digit: vec![coefficients_by_limb],
                        round_one_aggregate_diagonal: Vec::new(),
                    },
                    same_secret_bridge: bridge_binding.statement.clone(),
                },
            };
            let witness = TrusteeEvaluationKeyWitness::PublicKeyShare {
                key: KeyBearingWitness {
                    secret_coefficients,
                    error_coefficients_by_key: vec![vec![error_coefficients]],
                },
                negative_indicator_coefficients,
                committed_material: VssCommittedMaterialWitness {
                    vss_committed_material_seeds_by_bound_message: committed_material_seeds,
                },
            };
            let proof_randomness_seed_hex = derive_canonical_object_hash(&serde_json::json!({
                "objectType": "PublicKeyShareProofRoot",
                "fixture": "public-key-share-succinct-proof-randomness",
                "trusteeRosterPosition": trustee_roster_position,
            }))
            .expect("public-key share succinct proof randomness seed");
            let statement_hash_hex = to_hex(&statement.statement_hash());
            let checkpointed_proof = checkpointed_proof_bytes_with_verification_state(
                PUBLIC_KEY_SHARE_PROOF_CHECKPOINT_DIRECTORY,
                &statement_hash_hex,
                |proof_bytes| verify_trustee_evaluation_key_proof_bytes(&statement, proof_bytes),
                || {
                    let proof = prove_evaluation_key_share(
                        &statement,
                        &witness,
                        &proof_randomness_seed_hex,
                    )
                    .expect("public-key share succinct proof");
                    encode_trustee_evaluation_key_proof(&proof)
                },
            );
            let CheckpointedProofBytes {
                proof_bytes,
                was_semantically_verified,
            } = checkpointed_proof;
            let proof_bytes_hash = public_key_share_succinct_proof_bytes_hash(&proof_bytes);
            let proof_record = serde_json::json!({
                "objectType": "PublicKeyShareSuccinctProof",
                "proofBytesHash": &proof_bytes_hash,
            });
            authenticate_setup_proof_material_stream_for_test(
                PUBLIC_KEY_SHARE_PROOF_FAMILY,
                &proof_bytes_hash,
                &proof_bytes,
            )
            .expect("authenticate public-key share proof material stream");
            final_package_phase(&format!(
                "generated public-key share succinct proof trustee {trustee_roster_position}"
            ));

            if !was_semantically_verified {
                verify_trustee_evaluation_key_proof_bytes(&statement, &proof_bytes)
                    .expect("verify generated public-key share proof bytes");
            }
            let verification_binding_hash = crate::bgv::setup::accepted_setup::
            public_key_share_succinct_proof_verification_binding_hash(
                &proof_record,
                &statement,
            )
            .expect("public-key share proof verification binding");
            crate::bgv::setup::retain_accepted_setup_proof_binding(
                proof_binding_session.session_handle,
                PUBLIC_KEY_SHARE_PROOF_FAMILY,
                &proof_bytes_hash,
                verification_binding_hash,
            )
            .expect("retain public-key share proof binding");
            let proof_binding_lease = crate::bgv::setup::accepted_setup_proof_binding_lease(
                proof_binding_session.session_handle,
                &proof_bytes_hash,
            )
            .expect("public-key share proof binding lease lookup")
            .expect("public-key share proof binding must be retained");

            PublicKeyShareSuccinctProofRecordFixture {
                proof_record,
                proof_binding_lease,
            }
        })
        .collect::<Vec<_>>();
    let mut proof_records = Vec::new();
    let mut proof_binding_leases = Vec::new();
    for fixture in per_trustee_records {
        proof_records.push(fixture.proof_record);
        proof_binding_leases.push(fixture.proof_binding_lease);
    }
    let proof_set = serde_json::json!({
        "objectType": "PublicKeyShareSuccinctProofSet",
        "proofRecords": proof_records,
    });

    PublicKeyShareSuccinctProofFixture {
        proof_set,
        proof_binding_leases,
    }
}

pub(in super::super) fn signed_i64_residue_for_fixture(value: i64, modulus: u64) -> u64 {
    if value >= 0 {
        u64::try_from(value).expect("non-negative value") % modulus
    } else {
        let magnitude = value.unsigned_abs() % modulus;
        if magnitude == 0 {
            0
        } else {
            modulus - magnitude
        }
    }
}
