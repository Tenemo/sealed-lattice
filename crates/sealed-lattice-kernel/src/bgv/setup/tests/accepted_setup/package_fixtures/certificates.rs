use super::*;

pub(super) fn setup_commitment_security_certificate_fixture(
    profile: &serde_json::Value,
    participant_count: u64,
) -> serde_json::Value {
    // Mirror the production roster-derived bounds (accepted_certificates.rs):
    // the decryption threshold and full-roster aggregation count are pure
    // functions of participantCount, and the verifier recomputes this exact
    // certificate per roster, so the fixture must match it for every n.
    let decryption_threshold = participant_count / 3 + 1;
    let max_source_message_modulus = DATA_PRIMES.iter().copied().max().expect("Q_share primes");
    let recipient_scalar_sum = scalar_power_sum_fixture(decryption_threshold, participant_count);
    let threshold_scalar_sum = recipient_scalar_sum * u128::from(participant_count);
    let recipient_scalar_sum_u64 = u64::try_from(recipient_scalar_sum).expect("recipient bound");
    let threshold_scalar_sum_u64 = u64::try_from(threshold_scalar_sum).expect("threshold bound");
    let commitment_modulus_product =
        profile["commitmentProfile"]["messageEncoding"]["commitmentModulusLimbs"]
            .as_array()
            .expect("commitment modulus limbs")
            .iter()
            .map(|limb| BigUint::from(limb["modulus"].as_u64().expect("commitment modulus limb")))
            .product::<BigUint>();
    let max_recipient_lifted_coefficient =
        u128::from(max_source_message_modulus - 1) * recipient_scalar_sum;
    let max_threshold_lifted_coefficient =
        u128::from(max_source_message_modulus - 1) * threshold_scalar_sum;
    let commitment_modulus_product_bits = ceil_log2_fixture(&commitment_modulus_product);
    let fresh_message_no_wrap =
        BigUint::from(max_source_message_modulus - 1) < commitment_modulus_product.clone();
    let certificate = serde_json::json!({
        "objectType": "SetupCommitmentSecurityCertificate",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "setupProfileHash": profile["setupProfileHash"],
        "commitmentProfileId": "SealedLattice-BDLOP-Commitment-v1",
        "commitmentProfileHash": profile["commitmentProfileHash"],
        "qShareHash": profile["qShareHash"],
        "carryAwareVssShareRelationProfileHash": profile["carryAwareVssShareRelationProfileHash"],
        "ringAndMatrixParameters": {
            "coefficientRing": "Z_q[X]/(X^N+1)",
            "ringDegree": POLYNOMIAL_DEGREE,
            "sourceRnsLimbCount": DATA_PRIMES.len(),
            "sourceRnsPrimes": DATA_PRIMES,
            "commitmentModulusLimbs": profile["commitmentProfile"]["messageEncoding"]["commitmentModulusLimbs"],
            "commitmentModulusProductDecimal": commitment_modulus_product.to_string(),
            "commitmentModulusProductCeilBits": commitment_modulus_product_bits,
            "moduleRank": 2,
            "randomnessWidth": 5,
            "commitmentRowCount": 3,
            "publicMatrixSource": "full-roster-common-randomness-XOF-unbiased-residue-stream",
            "matrixHashBound": true,
        },
        "freshOpeningDistribution": {
            "distribution": "coefficientwise-centered-ternary",
            "coefficientSet": [-1, 0, 1],
            "infinityNormBound": 1,
            "randomnessWidth": 5,
            "rawOpeningExported": false,
            "perCoefficientOpeningExported": false,
        },
        "fullWidthMessageBound": {
            "messageSource": "per-RNS-prime-Shamir-coefficient-ring-element",
            "maxSourceMessageModulus": max_source_message_modulus,
            "maxFreshMessageCoefficientDecimal": (max_source_message_modulus - 1).to_string(),
            "commitmentModulusProductDecimal": commitment_modulus_product.to_string(),
            "freshMessageNoWrap": fresh_message_no_wrap,
        },
        "aggregateOpeningBounds": {
            "shamirCoefficientCount": decryption_threshold,
            "maximumTrusteePoint": participant_count,
            "recipientScalarPowerSumDecimal": recipient_scalar_sum.to_string(),
            "recipientAggregateOpeningInfinityBound": recipient_scalar_sum_u64,
            "maxRecipientLiftedCoefficientDecimal": max_recipient_lifted_coefficient.to_string(),
            "sourceTrusteeCountForThresholdAggregation": participant_count,
            "thresholdScalarPowerSumDecimal": threshold_scalar_sum.to_string(),
            "thresholdShareOpeningInfinityBound": threshold_scalar_sum_u64,
            "maxThresholdLiftedCoefficientDecimal": max_threshold_lifted_coefficient.to_string(),
            "commitmentModulusProductDecimal": commitment_modulus_product.to_string(),
            "recipientAndThresholdNoWrap": true,
        },
        "multiOpeningLeakage": {
            "recipientAggregateOpeningsArePublic": false,
            "recipientAggregateOpeningsAreMailboxPlaintext": false,
            "maxCorruptRecipientsBeforeThreshold": decryption_threshold - 1,
            "shamirPolynomialDegree": decryption_threshold - 1,
            "rawCoefficientOpeningsExported": false,
            "perCoefficientRandomnessExported": false,
            "thresholdBoundary": "recipient-aggregate-openings-and-carry-witnesses-are-private-proof-witnesses",
        },
        "bindingAssumption": {
            "assumption": "Module-SIS",
            "boundTarget": "two-valid-openings-to-one-commitment-yield-short-module-SIS-solution",
            "moduleRank": 2,
            "randomnessWidth": 5,
            "commitmentModulusProductCeilBits": commitment_modulus_product_bits,
            "extractedOpeningInfinityBound": threshold_scalar_sum_u64,
        },
        "hidingAssumption": {
            "assumption": "Module-LWE with recipient-hidden proof-witness opening leakage boundary",
            "openingDistribution": "coefficientwise-centered-ternary",
            "publicMatrixDistribution": "hash-derived-uniform-residue-stream",
            "lowEntropySecretHiding": true,
        },
        "estimatorRows": [
            {
                "rowId": "first-profile-module-sis-binding-row",
                "problem": "Module-SIS",
                "targetSecurityBits": 128,
                "ringDegree": POLYNOMIAL_DEGREE,
                "moduleRank": 2,
                "modulusCeilBits": commitment_modulus_product_bits,
                "shortVectorInfinityBoundDecimal": threshold_scalar_sum.to_string(),
                "accountingBasis": "accepted Module-SIS binding row under FPS25 commitment references and no-wrap threshold-opening bounds"
            },
            {
                "rowId": "first-profile-module-lwe-hiding-row",
                "problem": "Module-LWE",
                "targetSecurityBits": 128,
                "ringDegree": POLYNOMIAL_DEGREE,
                "moduleRank": 2,
                "secretDistribution": "centered-ternary-opening",
                "modulusCeilBits": commitment_modulus_product_bits,
                "accountingBasis": "accepted Module-LWE hiding row under FPS25/ACC18 references and recipient-hidden opening leakage boundary"
            }
        ],
    });

    let certificate_hash =
        derive_protocol_hash("SetupCommitmentSecurityCertificateHash", &certificate)
            .expect("commitment security certificate hash");
    let mut certificate_with_hash = certificate;
    certificate_with_hash["setupCommitmentSecurityCertificateHash"] =
        serde_json::json!(certificate_hash);

    certificate_with_hash
}

pub(super) fn scalar_power_sum_fixture(coefficient_count: u64, trustee_point: u64) -> u128 {
    let mut scalar_sum = 0_u128;
    let mut trustee_power = 1_u128;
    for coefficient_index in 0..coefficient_count {
        scalar_sum += trustee_power;
        if coefficient_index + 1 < coefficient_count {
            trustee_power *= u128::from(trustee_point);
        }
    }

    scalar_sum
}

pub(super) fn ceil_log2_fixture(value: &BigUint) -> u32 {
    if value <= &BigUint::from(1_u8) {
        0
    } else {
        let previous = value - BigUint::from(1_u8);
        u32::try_from(previous.bits()).expect("fixture bit length")
    }
}

pub(in super::super) fn setup_transport_chunk_manifest_root_fixture(
    chunk_count: u64,
    total_byte_length: u64,
    chunk_hashes: &[String],
    full_object_hash: &str,
) -> String {
    derive_protocol_hash(
        "SetupTransportChunkManifestRoot",
        &serde_json::json!({
            "objectType": "SetupTransportChunkManifest",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "transportProfileId": "sealed-lattice-setup-binary-chunked-transport-v1",
            "chunkSizeBytes": 1_048_576_u64,
            "chunkCount": chunk_count,
            "totalByteLength": total_byte_length,
            "chunkHashes": chunk_hashes,
            "fullObjectHash": full_object_hash,
        }),
    )
    .expect("setup transport chunk manifest root")
}

pub(in super::super) fn setup_transport_certificate_fixture(
    profile: &serde_json::Value,
    vss_coefficient_commitment_material: &serde_json::Value,
) -> serde_json::Value {
    let chunk_size_bytes = 1_048_576_u64;
    // The transported VSS object byte length is a function of the material's
    // roster and ring degree, matching the verifier's roster-and-ring-derived
    // expectation (transport_policy::setup_transport_vss_material_byte_length_for_roster).
    // It is read from the material set so a reduced-ring or non-first-closure
    // material declares a consistent transport object. The streamed path then
    // overrides byteLength from the actually transported material.
    let material_participant_count = vss_coefficient_commitment_material["participantCount"]
        .as_u64()
        .expect("VSS material participant count");
    let material_decryption_threshold = vss_coefficient_commitment_material["thresholdDegree"]
        .as_u64()
        .expect("VSS material threshold degree");
    let material_ring_degree = vss_coefficient_commitment_material["ringDegree"]
        .as_u64()
        .expect("VSS material ring degree") as usize;
    let total_byte_length = vss_material_binary_total_byte_length(
        material_ring_degree,
        material_participant_count,
        material_decryption_threshold,
    );
    let chunk_count = total_byte_length.div_ceil(chunk_size_bytes);
    let vss_full_object_hash = derive_protocol_hash(
        "SetupTransportChunkManifestRoot",
        &serde_json::json!({
            "fixture": "setup-transport-full-object-hash",
            "totalByteLength": total_byte_length,
        }),
    )
    .expect("transport full object hash");
    let chunk_hashes = (0..chunk_count)
        .map(|chunk_index| {
            derive_protocol_hash(
                "SetupTransportChunkManifestRoot",
                &serde_json::json!({
                    "fixture": "setup-transport-chunk-hash",
                    "chunkIndex": chunk_index,
                }),
            )
            .expect("transport chunk hash")
        })
        .collect::<Vec<_>>();
    let vss_chunk_root = derive_protocol_hash(
        "SetupTransportChunkManifestRoot",
        &serde_json::json!({
            "objectType": "SetupTransportChunkManifest",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "transportProfileId": "sealed-lattice-setup-binary-chunked-transport-v1",
            "chunkSizeBytes": chunk_size_bytes,
            "chunkCount": chunk_count,
            "totalByteLength": total_byte_length,
            "chunkHashes": chunk_hashes,
            "fullObjectHash": vss_full_object_hash,
        }),
    )
    .expect("setup transport chunk root");
    let transported_objects = serde_json::json!([
        {
            "objectType": "SetupTransportedObject",
            "objectVersion": 1,
            "objectName": "vssCoefficientCommitmentMaterial",
            "objectRole": "public-vss-coefficient-commitment-material",
            "objectRoot": vss_coefficient_commitment_material["vssCoefficientCommitmentMaterialRoot"],
            "byteLength": total_byte_length,
            "chunkStartIndex": 0_u64,
            "chunkCount": chunk_count,
            "chunkRoot": vss_chunk_root,
            "chunkHashes": chunk_hashes,
            "fullObjectHash": vss_full_object_hash,
            "encoding": "binary",
            "loadingPolicy": "stream-verified-before-object-use",
        }
    ]);
    let aggregate_full_object_hash = derive_protocol_hash(
        "SetupTransportFullObjectSetHash",
        &serde_json::json!({
            "objectType": "SetupTransportFullObjectSet",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "transportProfileId": "sealed-lattice-setup-binary-chunked-transport-v1",
            "transportedObjects": [{
                "objectName": "vssCoefficientCommitmentMaterial",
                "objectRole": "public-vss-coefficient-commitment-material",
                "objectRoot": vss_coefficient_commitment_material["vssCoefficientCommitmentMaterialRoot"],
                "byteLength": total_byte_length,
                "chunkStartIndex": 0_u64,
                "chunkCount": chunk_count,
                "chunkRoot": vss_chunk_root,
                "fullObjectHash": vss_full_object_hash,
            }],
            "totalByteLength": total_byte_length,
            "chunkCount": chunk_count,
            "chunkHashes": chunk_hashes,
        }),
    )
    .expect("setup transport full object set hash");
    let chunk_root = derive_protocol_hash(
        "SetupTransportChunkManifestRoot",
        &serde_json::json!({
            "objectType": "SetupTransportChunkManifest",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "transportProfileId": "sealed-lattice-setup-binary-chunked-transport-v1",
            "chunkSizeBytes": chunk_size_bytes,
            "chunkCount": chunk_count,
            "totalByteLength": total_byte_length,
            "chunkHashes": chunk_hashes,
            "fullObjectHash": aggregate_full_object_hash,
        }),
    )
    .expect("setup transport aggregate chunk root");
    let mut certificate = serde_json::json!({
        "objectType": "SetupTransportCertificate",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "transportProfileId": "sealed-lattice-setup-binary-chunked-transport-v1",
        "setupTransportProfileHash": profile["setupTransportProfileHash"],
        "largeObjectEncoding": "binary",
        "chunking": "required",
        "chunkSizeBytes": chunk_size_bytes,
        "chunkCount": chunk_count,
        "totalByteLength": total_byte_length,
        "storageQuotaBytes": 2_147_483_648_u64,
        "largestSingleBufferBytes": 1_572_864_u64,
        "copyCountLimit": 2_u64,
        "streamVerificationOrder": "ascending-chunk-index",
        "resumePolicy": "chunk-index-checkpointed-by-hash",
        "lazyLoadingPolicy": "root-addressed-large-object-loading",
        "transportedObjects": transported_objects,
        "chunkHashes": chunk_hashes,
        "chunkRoot": chunk_root,
        "fullObjectHash": aggregate_full_object_hash,
    });
    let certificate_hash = derive_protocol_hash("SetupTransportCertificateHash", &certificate)
        .expect("setup transport certificate hash");
    certificate["setupTransportCertificateHash"] = serde_json::json!(certificate_hash);

    certificate
}

pub(in super::super) fn setup_transport_certificate_for_transported_vss_material(
    profile: &serde_json::Value,
    vss_coefficient_commitment_material: &serde_json::Value,
    transported_vss_material: &serde_json::Value,
) -> serde_json::Value {
    let mut certificate =
        setup_transport_certificate_fixture(profile, vss_coefficient_commitment_material);
    let vss_transport_object = certificate["transportedObjects"][0]
        .as_object_mut()
        .expect("VSS transport certificate object");
    vss_transport_object.insert(
        "objectRoot".to_string(),
        vss_coefficient_commitment_material["vssCoefficientCommitmentMaterialRoot"].clone(),
    );
    vss_transport_object.insert(
        "byteLength".to_string(),
        transported_vss_material["totalByteLength"].clone(),
    );
    vss_transport_object.insert(
        "chunkCount".to_string(),
        transported_vss_material["chunkCount"].clone(),
    );
    vss_transport_object.insert(
        "chunkRoot".to_string(),
        transported_vss_material["chunkRoot"].clone(),
    );
    vss_transport_object.insert(
        "chunkHashes".to_string(),
        transported_vss_material["chunkHashes"].clone(),
    );
    vss_transport_object.insert(
        "fullObjectHash".to_string(),
        transported_vss_material["fullObjectHash"].clone(),
    );
    rebind_setup_transport_certificate(&mut certificate);

    certificate
}
