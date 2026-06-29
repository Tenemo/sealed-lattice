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
    let compact_vss_parameter_certificate_input_binding =
        compact_vss_parameter_certificate_input_binding_fixture(
            profile,
            participant_count,
            decryption_threshold,
        );
    let compact_vss_parameter_certificate_input_binding_hash =
        compact_vss_parameter_certificate_input_binding
            ["compactVssParameterCertificateInputBindingHash"]
            .clone();
    let certificate = serde_json::json!({
        "objectType": "SetupCommitmentSecurityCertificate",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "setupProfileHash": profile["setupProfileHash"],
        "commitmentProfileId": "SealedLattice-BDLOP-Commitment-v1",
        "commitmentProfileHash": profile["commitmentProfileHash"],
        "qShareHash": profile["qShareHash"],
        "carryAwareVssShareRelationProfileHash": profile["carryAwareVssShareRelationProfileHash"],
        "compactVssParameterCertificateInputBindingHash": compact_vss_parameter_certificate_input_binding_hash,
        "compactVssParameterCertificateInputBinding": compact_vss_parameter_certificate_input_binding,
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
        },
        "freshOpeningDistribution": {
            "distribution": "coefficientwise-centered-ternary",
            "coefficientSet": [-1, 0, 1],
            "infinityNormBound": 1,
            "randomnessWidth": 5,
        },
        "fullWidthMessageBound": {
            "messageSource": "per-RNS-prime-Shamir-coefficient-ring-element",
            "maxSourceMessageModulus": max_source_message_modulus,
            "maxFreshMessageCoefficientDecimal": (max_source_message_modulus - 1).to_string(),
            "commitmentModulusProductDecimal": commitment_modulus_product.to_string(),
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
            },
            {
                "rowId": "first-profile-module-lwe-hiding-row",
                "problem": "Module-LWE",
                "targetSecurityBits": 128,
                "ringDegree": POLYNOMIAL_DEGREE,
                "moduleRank": 2,
                "secretDistribution": "centered-ternary-opening",
                "modulusCeilBits": commitment_modulus_product_bits,
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

fn compact_vss_parameter_certificate_input_binding_fixture(
    profile: &serde_json::Value,
    participant_count: u64,
    decryption_threshold: u64,
) -> serde_json::Value {
    let commitment_modulus_limb_count = SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() as u64;
    let output_coordinate_count = crate::bgv::setup::COMPACT_VSS_OUTPUT_COORDINATE_COUNT as u64;
    let randomness_column_count = crate::bgv::setup::COMPACT_VSS_RANDOMNESS_COLUMN_COUNT as u64;
    let message_column_count =
        crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_MESSAGE_DIGIT_COUNT as u64;
    let projection_weight =
        crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_PROJECTION_WEIGHT as u64;
    let input_column_count = message_column_count + randomness_column_count;
    let coordinate_count_per_commitment = commitment_modulus_limb_count * output_coordinate_count;
    let sampled_matrix_residues_per_coordinate = input_column_count * projection_weight;
    let sampled_projection_indices_per_coordinate = sampled_matrix_residues_per_coordinate;
    let sampled_matrix_residues_per_commitment =
        coordinate_count_per_commitment * sampled_matrix_residues_per_coordinate;
    let sampled_projection_indices_per_commitment =
        coordinate_count_per_commitment * sampled_projection_indices_per_coordinate;
    let maximum_one_source_shamir_scalar_l1 =
        scalar_power_sum_fixture(decryption_threshold, participant_count);
    let one_recipient_aggregate_shamir_scalar_l1 =
        maximum_one_source_shamir_scalar_l1 * u128::from(participant_count);
    let fresh_opening_witness_coefficient_count = input_column_count * POLYNOMIAL_DEGREE as u64;
    let aggregate_randomness_difference_infinity_bound = participant_count * 2;
    let recipient_shamir_relation_l1 = maximum_one_source_shamir_scalar_l1 + 1;
    let aggregate_sum_relation_l1 = participant_count + 1;
    let commitment_modulus_limbs = SETUP_COMMITMENT_MODULUS_LIMB_INDICES
        .iter()
        .map(|commitment_modulus_index| {
            serde_json::json!({
                "commitmentModulusIndex": commitment_modulus_index,
                "modulus": DATA_PRIMES[*commitment_modulus_index],
            })
        })
        .collect::<Vec<_>>();
    let target_rns_primes = profile["canonicalTargetBasis"]["targetPrimes"]
        .as_array()
        .expect("canonical target basis target primes")
        .clone();
    let input_column_labels = (0..message_column_count)
        .map(|digit_index| serde_json::json!(format!("message:{digit_index}")))
        .chain(
            (0..randomness_column_count)
                .map(|column_index| serde_json::json!(format!("randomness:{column_index}"))),
        )
        .collect::<Vec<_>>();

    let binding_body = serde_json::json!({
        "objectType": "CompactVssParameterCertificateInputBinding",
        "objectVersion": 2,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "profileId": "sealed-lattice-compact-vss-sparse-linear-v1",
        "participantCount": participant_count,
        "sourceRnsLimbCount": DATA_PRIMES.len(),
        "targetRnsLimbCount": target_rns_primes.len(),
        "thresholdDegree": decryption_threshold,
        "ringDegree": POLYNOMIAL_DEGREE,
        "commitmentRelation": {
            "relation": "C = A_message * m + A_randomness * r mod q_c",
            "coefficientRing": "Z_q[X]/(X^N+1)",
            "commitmentModulusLimbIndices": SETUP_COMMITMENT_MODULUS_LIMB_INDICES,
            "commitmentModulusLimbs": commitment_modulus_limbs,
            "outputCoordinateCount": output_coordinate_count,
            "messageWidth": message_column_count,
            "randomnessWidth": randomness_column_count,
            "projectionWeight": projection_weight,
            "coordinateCountPerCommitment": coordinate_count_per_commitment,
            "inputColumnLabels": input_column_labels,
            "homomorphicAdditionRule": "commitments combine linearly only when profile, public matrix seed, source limb, and commitment modulus order match",
            "homomorphicScalarRule": "public Shamir and aggregation scalars multiply both message and randomness columns over the same commitment key",
        },
        "commonCommitmentKey": {
            "matrixResidueHashDomain": "sealed-lattice-compact-vss-commitment/matrix-residue-v1",
            "projectionIndexHashDomain": "sealed-lattice-compact-vss-commitment/projection-index-v1",
            "rejectionSamplingRule": "sample little-endian 64-bit chunks and reject values at or above 2^64 - (2^64 mod modulus or ringDegree)",
            "matrixResiduePreimageFields": [
                "publicMatrixSeedHash",
                "profileId",
                "rnsLimbIndex",
                "commitmentModulusIndex",
                "outputCoordinateIndex",
                "inputColumn",
                "projectionTermIndex",
                "modulus",
                "blockIndex"
            ],
            "projectionIndexPreimageFields": [
                "publicMatrixSeedHash",
                "profileId",
                "rnsLimbIndex",
                "commitmentModulusIndex",
                "outputCoordinateIndex",
                "inputColumn",
                "projectionTermIndex",
                "ringDegree",
                "blockIndex"
            ],
            "sparseProjectionShape": {
                "inputColumnCount": input_column_count,
                "projectionWeight": projection_weight,
                "coordinateCountPerCommitment": coordinate_count_per_commitment,
                "sampledMatrixResiduesPerCoordinate": sampled_matrix_residues_per_coordinate,
                "sampledProjectionIndicesPerCoordinate": sampled_projection_indices_per_coordinate,
                "sampledMatrixResiduesPerCommitment": sampled_matrix_residues_per_commitment,
                "sampledProjectionIndicesPerCommitment": sampled_projection_indices_per_commitment,
            },
        },
        "messageEncoding": {
            "sourceCoefficientRepresentation": "canonical residue modulo the selected source RNS prime",
            "targetCoefficientRepresentation": "canonical residue modulo the selected target RNS prime",
            "signedRepresentativeConvention": "same-secret bridge witnesses use the setup proof signed representative convention before reduction into each RNS prime",
            "paddingAndBlockOrder": "two base-3^17 little-endian digit coefficients per message ring position",
            "freshEncodingRule": "exact canonical residue encoding into two message digit columns",
            "proofRangeEncodingRule": "proof traces decompose the low digit with 17 trits and the high digit with the statement-bound trit count for the opened message class",
            "derivedEncodingRule": "Shamir recipient-share and aggregate threshold openings bind carried public-sum messages through decoded message digit columns and private carry witnesses",
        },
        "normInputClasses": [
            {
                "className": "shamirScalarL1Amplification",
                "maximumRecipientTrusteePoint": participant_count,
                "shamirCoefficientCount": decryption_threshold,
                "maximumOneSourceShamirScalarL1": maximum_one_source_shamir_scalar_l1,
                "oneRecipientAggregateShamirScalarL1": one_recipient_aggregate_shamir_scalar_l1,
            },
            {
                "className": "messageEncodingNorm",
                "sourceCoefficientUpperBoundMultiplier": 1_u64,
                "recipientShareCoefficientUpperBoundMultiplier": maximum_one_source_shamir_scalar_l1,
                "aggregateCoefficientUpperBoundMultiplier": one_recipient_aggregate_shamir_scalar_l1,
            },
            {
                "className": "openingRandomnessNorm",
                "randomnessColumnCount": randomness_column_count,
            },
            {
                "className": "aggregateDealerCount",
                "sourceTrusteeCount": participant_count,
            },
        ],
        "parameterReviewInputs": {
            "inputVersion": 1,
            "coefficientRing": {
                "ringPolynomial": "X^N+1",
                "ringDegree": POLYNOMIAL_DEGREE,
                "commitmentModulusLimbIndices": SETUP_COMMITMENT_MODULUS_LIMB_INDICES,
                "commitmentModulusLimbs": commitment_modulus_limbs,
            },
            "openingWitnessRows": [
                {
                    "rowId": "compact-vss-fresh-opening-witness",
                    "commitmentRoles": [
                        "coefficient",
                        "recipient-share"
                    ],
                    "messageCoefficientBound": "selectedRnsPrime times the recipient Shamir scalar L1 for recipient-share openings",
                    "messageCoefficientUpperBoundMultiplier": maximum_one_source_shamir_scalar_l1,
                    "messageDifferenceUpperBoundMultiplier": maximum_one_source_shamir_scalar_l1,
                    "randomnessDistribution": "balanced-ternary-per-column-coefficient",
                    "randomnessCoefficientInfinityBound": 1_u64,
                    "randomnessDifferenceInfinityBound": 2_u64,
                    "messageColumnCount": message_column_count,
                    "randomnessColumnCount": randomness_column_count,
                    "witnessColumnCount": input_column_count,
                    "witnessCoefficientCount": fresh_opening_witness_coefficient_count,
                },
                {
                    "rowId": "compact-vss-aggregate-opening-witness",
                    "commitmentRoles": [
                        "aggregate-threshold-share"
                    ],
                    "messageCoefficientBound": "selectedRnsPrime times the all-source recipient Shamir scalar L1",
                    "messageCoefficientUpperBoundMultiplier": one_recipient_aggregate_shamir_scalar_l1,
                    "messageDifferenceUpperBoundMultiplier": one_recipient_aggregate_shamir_scalar_l1,
                    "randomnessDistribution": "sum-of-source-balanced-ternary-openings",
                    "randomnessCoefficientInfinityBound": participant_count,
                    "randomnessDifferenceInfinityBound": aggregate_randomness_difference_infinity_bound,
                    "messageColumnCount": message_column_count,
                    "randomnessColumnCount": randomness_column_count,
                    "witnessColumnCount": input_column_count,
                    "witnessCoefficientCount": fresh_opening_witness_coefficient_count,
                },
            ],
            "linearRelationRows": [
                {
                    "rowId": "compact-vss-recipient-share-shamir-evaluation",
                    "relation": "recipient share opening equals Shamir evaluation of source coefficient openings",
                    "sourceOpeningCount": decryption_threshold,
                    "recipientOpeningTermCount": 1_u64,
                    "maximumRecipientTrusteePoint": participant_count,
                    "sourceShamirScalarL1": maximum_one_source_shamir_scalar_l1,
                    "combinedRelationTermL1": recipient_shamir_relation_l1,
                    "appliesToColumns": input_column_labels,
                },
                {
                    "rowId": "compact-vss-aggregate-threshold-public-sum",
                    "relation": "aggregate threshold opening equals public sum of source-recipient openings",
                    "sourceTrusteeCount": participant_count,
                    "aggregateOpeningTermCount": 1_u64,
                    "sourceOpeningScalarL1": participant_count,
                    "combinedRelationTermL1": aggregate_sum_relation_l1,
                    "appliesToColumns": input_column_labels,
                },
                {
                    "rowId": "compact-vss-one-recipient-aggregate-from-source-coefficients",
                    "relation": "one recipient aggregate opening as a sum of all source Shamir evaluations",
                    "sourceTrusteeCount": participant_count,
                    "sourceCoefficientCountPerTrustee": decryption_threshold,
                    "oneRecipientAggregateShamirScalarL1": one_recipient_aggregate_shamir_scalar_l1,
                    "appliesToColumns": input_column_labels,
                },
            ],
            "targetBasisReductionRows": [
                {
                    "rowId": "compact-vss-same-secret-bridge-target-reduction",
                    "sourceSecretDistribution": "standard-ternary",
                    "sourceSignedRepresentativeInfinityBound": 1_u64,
                    "targetRnsLimbCount": target_rns_primes.len(),
                    "targetRnsPrimes": target_rns_primes,
                    "targetBasisHash": profile["canonicalTargetBasisHash"],
                    "targetBasisLimbOrder": "profile-order-prefix",
                    "sameSecretProofFamilyBindingRoot": same_secret_proof_family_binding_root_fixture(),
                },
            ],
            "reviewReductionRows": [
                {
                    "rowId": "compact-vss-module-sis-binding-review-input",
                    "problem": "Module-SIS",
                    "openingWitnessRows": [
                        "compact-vss-fresh-opening-witness",
                        "compact-vss-aggregate-opening-witness"
                    ],
                    "linearRelationRows": [
                        "compact-vss-recipient-share-shamir-evaluation",
                        "compact-vss-aggregate-threshold-public-sum",
                        "compact-vss-one-recipient-aggregate-from-source-coefficients"
                    ],
                    "collisionDifferenceRule": "subtract two accepted openings over the integers before reducing to the commitment modulus",
                },
                {
                    "rowId": "compact-vss-module-lwe-hiding-review-input",
                    "problem": "Module-LWE",
                    "openingWitnessRows": [
                        "compact-vss-fresh-opening-witness",
                        "compact-vss-aggregate-opening-witness"
                    ],
                    "randomnessSource": "balanced-ternary opening columns before public linear aggregation",
                    "sampledProjectionIndicesPerCommitment": sampled_projection_indices_per_commitment,
                },
            ],
        },
        "estimatorInputRows": [
            {
                "rowId": "compact-vss-module-sis-binding-input",
                "problem": "Module-SIS",
                "targetSecurityBits": 128_u64,
                "ringDegree": POLYNOMIAL_DEGREE,
                "commitmentModulusLimbIndices": SETUP_COMMITMENT_MODULUS_LIMB_INDICES,
                "commitmentModulusLimbs": commitment_modulus_limbs,
                "outputCoordinateCount": output_coordinate_count,
                "messageWidth": message_column_count,
                "randomnessWidth": randomness_column_count,
                "projectionWeight": projection_weight,
                "sampledMatrixResiduesPerCommitment": sampled_matrix_residues_per_commitment,
                "sampledProjectionIndicesPerCommitment": sampled_projection_indices_per_commitment,
            },
            {
                "rowId": "compact-vss-module-lwe-hiding-input",
                "problem": "Module-LWE",
                "targetSecurityBits": 128_u64,
                "ringDegree": POLYNOMIAL_DEGREE,
                "commitmentModulusLimbIndices": SETUP_COMMITMENT_MODULUS_LIMB_INDICES,
                "commitmentModulusLimbs": commitment_modulus_limbs,
                "outputCoordinateCount": output_coordinate_count,
                "messageWidth": message_column_count,
                "randomnessWidth": randomness_column_count,
                "projectionWeight": projection_weight,
                "sampledMatrixResiduesPerCommitment": sampled_matrix_residues_per_commitment,
                "sampledProjectionIndicesPerCommitment": sampled_projection_indices_per_commitment,
            },
        ],
        "sameSecretBridgeInput": {
            "targetBasisHash": profile["canonicalTargetBasisHash"],
            "targetRnsPrimes": target_rns_primes,
            "sameSecretProofFamilyBindingRoot": same_secret_proof_family_binding_root_fixture(),
            "targetBasisLimbOrder": "profile-order-prefix",
        },
    });
    let binding_hash = derive_protocol_hash(
        "CompactVssParameterCertificateInputBindingHash",
        &binding_body,
    )
    .expect("compact VSS parameter certificate input binding hash");
    let mut binding = binding_body;
    binding["compactVssParameterCertificateInputBindingHash"] = serde_json::json!(binding_hash);

    binding
}

fn same_secret_proof_family_binding_root_fixture() -> String {
    derive_protocol_hash(
        "SameSecretProofFamilyBindingRoot",
        &serde_json::json!({
            "objectType": "SameSecretProofFamilyBinding",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "setupProofProfileId": "SealedLattice-SetupProof-v1",
            "proofFamily": "same-secret-linkage-anchor",
            "sameSecretRelation": "vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs",
            "anchorArgument": "one keyless succinct linkage proof per trustee; secret-dependent families bind the anchor root and open the same commitment values",
            "boundSecretDependentProofFamilies": [
                "vss-constant-relation",
                "public-key-share",
                "relinearization-key-share",
                "galois-key-share",
            ],
        }),
    )
    .expect("same-secret proof family binding root")
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
