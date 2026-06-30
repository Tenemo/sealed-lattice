use super::*;
use crate::bgv::setup::trustee_evaluation_key_proof::{
    CLAIM_MASK_DIGIT_COUNT, CLAIM_MASK_RADIX, COMPACT_VSS_CARRY_CLAIM_MASK_DIGIT_COUNT,
    COMPACT_VSS_CONSISTENCY_COEFFICIENT_BITS, COMPACT_VSS_CONSISTENCY_REPETITIONS,
    COMPACT_VSS_DIGIT_CLAIM_MASK_DIGIT_COUNT, CONSISTENCY_COEFFICIENT_BITS,
    CONSISTENCY_REPETITIONS, TARGET_DECRYPTION_AGGREGATE_MESSAGE_CLAIM_MASK_DIGIT_COUNT,
    TARGET_DECRYPTION_RANDOMNESS_CLAIM_MASK_DIGIT_COUNT,
    TARGET_DECRYPTION_SMUDGING_MESSAGE_CLAIM_MASK_DIGIT_COUNT,
};
use crate::bgv::target_decryption::TARGET_DECRYPTION_SMUDGING_COEFFICIENT_BOUND;

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
    let randomness_projection_weight =
        crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_RANDOMNESS_PROJECTION_WEIGHT as u64;
    let ring_degree = POLYNOMIAL_DEGREE as u64;
    let input_column_count = message_column_count + randomness_column_count;
    let coordinate_count_per_commitment = commitment_modulus_limb_count * output_coordinate_count;
    let message_coverage_terms_per_coordinate =
        ring_degree.div_ceil(coordinate_count_per_commitment);
    let message_matrix_residues_per_commitment = message_column_count * ring_degree;
    let randomness_matrix_residues_per_coordinate =
        randomness_column_count * randomness_projection_weight;
    let sampled_randomness_projection_indices_per_coordinate =
        randomness_matrix_residues_per_coordinate;
    let randomness_matrix_residues_per_commitment =
        coordinate_count_per_commitment * randomness_matrix_residues_per_coordinate;
    let sampled_matrix_residues_per_commitment =
        message_matrix_residues_per_commitment + randomness_matrix_residues_per_commitment;
    let sampled_randomness_projection_indices_per_commitment =
        coordinate_count_per_commitment * sampled_randomness_projection_indices_per_coordinate;
    let scheduled_message_terms_per_message_column =
        coordinate_count_per_commitment * message_coverage_terms_per_coordinate;
    let unused_scheduled_terms_per_message_column =
        scheduled_message_terms_per_message_column.saturating_sub(ring_degree);
    let sampled_message_terms_per_commitment = message_column_count * ring_degree;
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
    let target_rns_limb_count = target_rns_primes.len() as u64;
    let input_column_labels = (0..message_column_count)
        .map(|digit_index| serde_json::json!(format!("message:{digit_index}")))
        .chain(
            (0..randomness_column_count)
                .map(|column_index| serde_json::json!(format!("randomness:{column_index}"))),
        )
        .collect::<Vec<_>>();
    let compact_vss_message_digit_maximum =
        crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_MESSAGE_DIGIT_BASE - 1;
    let setup_consistency_coefficient_maximum =
        consistency_coefficient_maximum_fixture(CONSISTENCY_COEFFICIENT_BITS);
    let compact_vss_consistency_coefficient_maximum =
        consistency_coefficient_maximum_fixture(COMPACT_VSS_CONSISTENCY_COEFFICIENT_BITS);
    let largest_target_rns_prime = target_rns_primes
        .iter()
        .map(|prime| prime.as_u64().expect("target RNS prime"))
        .max()
        .expect("target RNS primes");
    let aggregate_target_message_coefficient_bound =
        u128::from(largest_target_rns_prime) * u128::from(participant_count);
    let aggregate_target_message_bound_u64 =
        u64::try_from(aggregate_target_message_coefficient_bound)
            .expect("aggregate target message bound fits u64");
    let aggregate_target_message_digit_maximum = (0..message_column_count as usize)
        .map(|digit_index| {
            crate::bgv::setup::compact_vss_commitment::compact_vss_message_digit_bound(
                aggregate_target_message_bound_u64,
                digit_index,
            )
            .expect("aggregate target message digit bound")
            .saturating_sub(1)
        })
        .max()
        .unwrap_or(0);
    let target_decryption_smudging_message_coefficient_bound =
        u64::try_from(TARGET_DECRYPTION_SMUDGING_COEFFICIENT_BOUND)
            .expect("target smudging coefficient bound")
            * 2
            + 1;
    let smudging_target_message_digit_maximum = (0..message_column_count as usize)
        .map(|digit_index| {
            crate::bgv::setup::compact_vss_commitment::compact_vss_message_digit_bound(
                target_decryption_smudging_message_coefficient_bound,
                digit_index,
            )
            .expect("smudging target message digit bound")
            .saturating_sub(1)
        })
        .max()
        .unwrap_or(0);
    let bridge_direct_digit_vector_count = target_rns_limb_count * message_column_count;
    let source_coefficient_commitments =
        participant_count * DATA_PRIMES.len() as u64 * decryption_threshold;
    let recipient_share_commitments = participant_count * participant_count * target_rns_limb_count;
    let aggregate_threshold_commitments = participant_count * target_rns_limb_count;
    let total_compact_commitments = source_coefficient_commitments
        + recipient_share_commitments
        + aggregate_threshold_commitments;
    let total_public_commitment_coordinates =
        total_compact_commitments * coordinate_count_per_commitment;
    let total_sampled_message_matrix_residues =
        total_compact_commitments * message_matrix_residues_per_commitment;
    let total_sampled_randomness_projection_indices =
        total_compact_commitments * sampled_randomness_projection_indices_per_commitment;
    let total_sampled_matrix_residues =
        total_compact_commitments * sampled_matrix_residues_per_commitment;
    let maximum_non_reconstructing_recipient_count = decryption_threshold.saturating_sub(1);
    let corrupted_recipient_opening_credential_count =
        maximum_non_reconstructing_recipient_count * participant_count * target_rns_limb_count;
    let smallest_commitment_modulus = SETUP_COMMITMENT_MODULUS_LIMB_INDICES
        .iter()
        .map(|commitment_modulus_index| DATA_PRIMES[*commitment_modulus_index])
        .min()
        .expect("compact commitment modulus limbs");
    let estimator_digit_difference_strict_upper_bound = (smallest_commitment_modulus - 1) / 2;
    let estimator_digit_precondition_margin =
        i128::from(estimator_digit_difference_strict_upper_bound)
            - i128::from(compact_vss_message_digit_maximum);

    let binding_body = serde_json::json!({
        "objectType": "CompactVssParameterCertificateInputBinding",
        "objectVersion": 8,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "profileId": crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "participantCount": participant_count,
        "sourceRnsLimbCount": DATA_PRIMES.len(),
        "targetRnsLimbCount": target_rns_limb_count,
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
            "messageCoverageTermsPerCoordinate": message_coverage_terms_per_coordinate,
            "randomnessProjectionWeight": randomness_projection_weight,
            "coordinateCountPerCommitment": coordinate_count_per_commitment,
            "inputColumnLabels": input_column_labels,
            "homomorphicAdditionRule": "commitments combine linearly only when profile, public matrix seed, source limb, and commitment modulus order match",
            "homomorphicScalarRule": "public Shamir and aggregation scalars multiply both message and randomness columns over the same commitment key",
        },
        "commonCommitmentKey": {
            "matrixResidueHashDomain": "sealed-lattice-compact-vss-commitment/matrix-residue-v1",
            "randomnessProjectionIndexHashDomain": "sealed-lattice-compact-vss-commitment/projection-index-v1",
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
            "randomnessProjectionIndexPreimageFields": [
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
            "messageCoverageShape": {
                "inputColumnCount": input_column_count,
                "coordinateCountPerCommitment": coordinate_count_per_commitment,
                "messageCoverageTermsPerCoordinate": message_coverage_terms_per_coordinate,
                "sampledMessageMatrixResiduesPerCommitment": message_matrix_residues_per_commitment,
                "coveredMessageCoefficientsPerMessageColumn": ring_degree,
                "uncoveredMessageCoefficientsPerMessageColumn": 0_u64,
            },
            "randomnessProjectionShape": {
                "randomnessProjectionWeight": randomness_projection_weight,
                "sampledMatrixResiduesPerCoordinate": randomness_matrix_residues_per_coordinate,
                "sampledRandomnessProjectionIndicesPerCoordinate": sampled_randomness_projection_indices_per_coordinate,
                "sampledMatrixResiduesPerCommitment": randomness_matrix_residues_per_commitment,
                "sampledRandomnessProjectionIndicesPerCommitment": sampled_randomness_projection_indices_per_commitment,
            },
        },
        "compactMaterialArtifactBoundary": {
            "artifactRole": "compact-vss-setup-public-material",
            "publicMaterialFields": [
                "compactVssCoefficientCommitmentSet",
                "compactVssRecipientShareCommitmentSet",
                "compactVssAggregateThresholdCommitmentSet",
                "compactVssShareLinkageStatement",
                "compactVssShareLinkageProofMaterialSet"
            ],
            "bridgeMaterialFields": [
                "compactSameSecretBridgeStatementSet",
                "compactSameSecretBridgeProofMaterialSet",
                "sameSecretConsistency",
                "sameSecretProofs"
            ],
            "commitmentOpeningRootObligations": [
                {
                    "commitmentSet": "compactVssCoefficientCommitmentSet",
                    "coordinateScope": "source trustee, source RNS limb, and Shamir coefficient",
                    "commitmentRootField": "coefficientCommitmentRoot",
                    "openingRootField": "coefficientOpeningRoot"
                },
                {
                    "commitmentSet": "compactVssRecipientShareCommitmentSet",
                    "coordinateScope": "source trustee, recipient trustee, and source RNS limb",
                    "commitmentRootField": "shareCommitmentRoot",
                    "openingRootField": "shareOpeningRoot"
                },
                {
                    "commitmentSet": "compactVssAggregateThresholdCommitmentSet",
                    "coordinateScope": "recipient trustee and target RNS limb",
                    "commitmentRootField": "aggregateCommitmentRoot",
                    "openingRootField": "aggregateOpeningRoot",
                    "sourceCommitmentRootField": "sourceShareCommitmentRoots",
                    "sourceOpeningRootField": "sourceShareOpeningRoots"
                }
            ],
            "proofObligations": [
                {
                    "proofFamily": "compact-vss-share-linkage",
                    "statementField": "compactVssShareLinkageStatement",
                    "proofMaterialField": "compactVssShareLinkageProofMaterialSet",
                    "boundRelations": [
                        "source coefficient opening to recipient-share opening",
                        "recipient-share opening to aggregate threshold opening"
                    ]
                },
                {
                    "proofFamily": "compact-same-secret-bridge",
                    "statementField": "compactSameSecretBridgeStatementSet",
                    "proofMaterialField": "compactSameSecretBridgeProofMaterialSet",
                    "boundRelations": [
                        "VSS constant coefficient opening to same-secret anchor",
                        "same-secret anchor to target basis opening"
                    ]
                },
                {
                    "proofFamily": "target-decryption-share",
                    "boundRelations": [
                        "target aggregate opening to released target share",
                        "target smudging opening to target-bound smudging share"
                    ]
                }
            ],
            "certificateRows": [
                "compact-vss-module-sis-binding-review-input",
                "compact-vss-module-lwe-hiding-review-input",
                "compact-vss-covered-message-module-sis-binding-input",
                "compact-vss-covered-message-module-lwe-hiding-input",
                "compact-vss-structured-ring-review-input",
                "compact-vss-multi-opening-review-input",
                "compact-vss-covered-message-module-sis-binding-conclusion",
                "compact-vss-covered-message-module-lwe-hiding-conclusion",
                "compact-vss-structured-ring-review-conclusion",
                "compact-vss-multi-opening-review-conclusion"
            ],
            "targetResultReleaseBoundary": "target-result release consumes compact material only through proof-bound aggregate and smudging openings tied to these commitment and opening roots",
            "acceptancePrecondition": "source-derived binding and hiding conclusion rows must cover this exact artifact boundary before target-result release consumes compact material"
        },
        "messageEncoding": {
            "sourceCoefficientRepresentation": "canonical residue modulo the selected source RNS prime",
            "targetCoefficientRepresentation": "canonical residue modulo the selected target RNS prime",
            "signedRepresentativeConvention": "same-secret bridge witnesses use the setup proof signed representative convention before reduction into each RNS prime",
            "paddingAndBlockOrder": "two base-3^17 little-endian digit coefficients per message ring position",
            "freshEncodingRule": "exact canonical residue encoding into two message digit columns",
            "proofRangeEncodingRule": "share-linkage, same-secret bridge, and target-decryption rows bind message digit columns with masked consistency claims and verifier-side trit decoder columns",
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
            "messageCoordinateCoverageReview": {
                "rowId": "compact-vss-message-coordinate-coverage",
                "finding": "The active covered relation assigns every message coefficient in each committed digit column to one compact commitment coordinate before sampling its matrix residue.",
                "interpretation": "This closes the previous absent-coordinate blocker for message columns. The binding and hiding conclusion rows consume this coverage row.",
                "ringDegree": POLYNOMIAL_DEGREE,
                "messageWidth": message_column_count,
                "coordinateCountPerCommitment": coordinate_count_per_commitment,
                "messageCoverageTermsPerCoordinate": message_coverage_terms_per_coordinate,
                "scheduledMessageTermsPerMessageColumn": scheduled_message_terms_per_message_column,
                "unusedScheduledTermsPerMessageColumn": unused_scheduled_terms_per_message_column,
                "sampledMessageTermsPerCommitment": sampled_message_terms_per_commitment,
                "coveredMessageCoefficientsPerMessageColumn": ring_degree,
                "uncoveredMessageCoefficientsPerMessageColumn": 0_u64,
                "coverageRule": "globalCoordinateIndex + coverageTermIndex * coordinateCountPerCommitment covers coefficient positions below ringDegree exactly once per message digit column",
                "remainingReplacementRequirement": "Target-result release still needs accepted compact setup, same-secret bridge acceptance, production smudging evidence, and final runtime evidence.",
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
            "commitmentExposureRows": [
                {
                    "rowId": "compact-vss-final-public-commitment-exposure",
                    "sourceCoefficientCommitments": source_coefficient_commitments,
                    "recipientShareCommitments": recipient_share_commitments,
                    "aggregateThresholdCommitments": aggregate_threshold_commitments,
                    "totalCompactCommitments": total_compact_commitments,
                    "coordinateCountPerCommitment": coordinate_count_per_commitment,
                    "totalPublicCommitmentCoordinates": total_public_commitment_coordinates,
                    "sampledMessageMatrixResiduesPerCommitment": message_matrix_residues_per_commitment,
                    "sampledRandomnessProjectionIndicesPerCommitment": sampled_randomness_projection_indices_per_commitment,
                    "sampledMatrixResiduesPerCommitment": sampled_matrix_residues_per_commitment,
                    "totalSampledMessageMatrixResidues": total_sampled_message_matrix_residues,
                    "totalSampledRandomnessProjectionIndices": total_sampled_randomness_projection_indices,
                    "totalSampledMatrixResidues": total_sampled_matrix_residues,
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
            "proofExtractionRows": [
                {
                    "rowId": "compact-vss-share-linkage-proof-extraction-input",
                    "proofFamily": "compact-vss-share-linkage",
                    "extractedOpeningWitnessRows": [
                        "compact-vss-fresh-opening-witness",
                        "compact-vss-aggregate-opening-witness"
                    ],
                    "extractedRelationRows": [
                        "compact-vss-recipient-share-shamir-evaluation",
                        "compact-vss-aggregate-threshold-public-sum",
                        "compact-vss-one-recipient-aggregate-from-source-coefficients"
                    ],
                    "extractedMaskedClaimRows": [
                        "compact-vss-share-linkage-carry-claim",
                        "compact-vss-share-linkage-message-digit-claim"
                    ],
                    "rangeEvidenceRule": "message digit columns are verifier-decoded from 17 trits per digit and carry claims use masked consistency bounds",
                },
                {
                    "rowId": "compact-vss-same-secret-bridge-proof-extraction-input",
                    "proofFamily": "compact-same-secret-bridge",
                    "extractedRelationRows": [
                        "compact-vss-same-secret-bridge-target-reduction"
                    ],
                    "extractedMaskedClaimRows": [
                        "compact-vss-same-secret-bridge-non-digit-claim",
                        "compact-vss-same-secret-bridge-message-digit-claim"
                    ],
                    "rangeEvidenceRule": "target-basis bridge rows expose signed-short and target-message digit bounds through the setup proof consistency relation",
                },
                {
                    "rowId": "compact-vss-target-decryption-proof-extraction-input",
                    "proofFamily": "target-decryption-share",
                    "extractedMaskedClaimRows": [
                        "compact-vss-target-decryption-aggregate-message-claim",
                        "compact-vss-target-decryption-smudging-message-claim",
                        "compact-vss-target-decryption-randomness-claim"
                    ],
                    "rangeEvidenceRule": "target proof rows bind aggregate opening digits, smudging opening digits, and ternary opening randomness before release",
                },
            ],
            "maskedClaimNormRows": [
                {
                    "rowId": "compact-vss-share-linkage-carry-claim",
                    "proofFamily": "compact-vss-share-linkage",
                    "claimVectorClass": "packed-opening-carry",
                    "appliesToRelations": [
                        "compact-vss-recipient-share-shamir-evaluation",
                        "compact-vss-aggregate-threshold-public-sum",
                        "compact-vss-one-recipient-aggregate-from-source-coefficients"
                    ],
                    "witnessInfinityBound": maximum_one_source_shamir_scalar_l1,
                    "clearClaimBoundDecimal": masked_claim_clear_bound_decimal_fixture(
                        maximum_one_source_shamir_scalar_l1,
                        POLYNOMIAL_DEGREE as u64,
                        COMPACT_VSS_CONSISTENCY_COEFFICIENT_BITS,
                    ),
                    "consistencyRepetitions": COMPACT_VSS_CONSISTENCY_REPETITIONS,
                    "consistencyCoefficientBits": COMPACT_VSS_CONSISTENCY_COEFFICIENT_BITS,
                    "consistencyCoefficientMaximumDecimal": compact_vss_consistency_coefficient_maximum.to_string(),
                    "claimMaskRadix": CLAIM_MASK_RADIX,
                    "maskDigitCount": COMPACT_VSS_CARRY_CLAIM_MASK_DIGIT_COUNT,
                    "rangeEvidenceRule": "carry claims use the lifted Shamir carry bound for each packed item",
                },
                {
                    "rowId": "compact-vss-share-linkage-message-digit-claim",
                    "proofFamily": "compact-vss-share-linkage",
                    "claimVectorClass": "message-digit",
                    "appliesToRelations": [
                        "compact-vss-recipient-share-shamir-evaluation",
                        "compact-vss-aggregate-threshold-public-sum",
                        "compact-vss-one-recipient-aggregate-from-source-coefficients"
                    ],
                    "messageDigitBaseDecimal": crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_MESSAGE_DIGIT_BASE.to_string(),
                    "messageDigitCount": message_column_count,
                    "witnessInfinityBoundDecimal": compact_vss_message_digit_maximum.to_string(),
                    "clearClaimBoundDecimal": masked_claim_clear_bound_decimal_fixture(
                        compact_vss_message_digit_maximum as u128,
                        POLYNOMIAL_DEGREE as u64,
                        COMPACT_VSS_CONSISTENCY_COEFFICIENT_BITS,
                    ),
                    "consistencyRepetitions": COMPACT_VSS_CONSISTENCY_REPETITIONS,
                    "consistencyCoefficientBits": COMPACT_VSS_CONSISTENCY_COEFFICIENT_BITS,
                    "consistencyCoefficientMaximumDecimal": compact_vss_consistency_coefficient_maximum.to_string(),
                    "claimMaskRadix": CLAIM_MASK_RADIX,
                    "maskDigitCount": COMPACT_VSS_DIGIT_CLAIM_MASK_DIGIT_COUNT,
                    "rangeEvidenceRule": "direct masked claims bind committed base-3^17 digit columns and verifier-side trit decoder columns",
                },
                {
                    "rowId": "compact-vss-same-secret-bridge-non-digit-claim",
                    "proofFamily": "compact-same-secret-bridge",
                    "claimVectorClass": "secret-indicator-or-randomness",
                    "appliesToRelations": [
                        "compact-vss-same-secret-bridge-target-reduction"
                    ],
                    "witnessInfinityBound": 2_u64,
                    "clearClaimBoundDecimal": masked_claim_clear_bound_decimal_fixture(
                        2,
                        POLYNOMIAL_DEGREE as u64,
                        CONSISTENCY_COEFFICIENT_BITS,
                    ),
                    "consistencyRepetitions": CONSISTENCY_REPETITIONS,
                    "consistencyCoefficientBits": CONSISTENCY_COEFFICIENT_BITS,
                    "consistencyCoefficientMaximumDecimal": setup_consistency_coefficient_maximum.to_string(),
                    "claimMaskRadix": CLAIM_MASK_RADIX,
                    "maskDigitCount": CLAIM_MASK_DIGIT_COUNT,
                    "rangeEvidenceRule": "non-digit bridge claims keep the setup-family consistency mask",
                },
                {
                    "rowId": "compact-vss-same-secret-bridge-message-digit-claim",
                    "proofFamily": "compact-same-secret-bridge",
                    "claimVectorClass": "target-message-digit",
                    "appliesToRelations": [
                        "compact-vss-same-secret-bridge-target-reduction"
                    ],
                    "targetRnsLimbCount": target_rns_primes.len(),
                    "messageDigitBaseDecimal": crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_MESSAGE_DIGIT_BASE.to_string(),
                    "messageDigitCount": message_column_count,
                    "directDigitVectorCount": bridge_direct_digit_vector_count,
                    "witnessInfinityBoundDecimal": compact_vss_message_digit_maximum.to_string(),
                    "clearClaimBoundDecimal": masked_claim_clear_bound_decimal_fixture(
                        compact_vss_message_digit_maximum as u128,
                        POLYNOMIAL_DEGREE as u64,
                        CONSISTENCY_COEFFICIENT_BITS,
                    ),
                    "consistencyRepetitions": CONSISTENCY_REPETITIONS,
                    "consistencyCoefficientBits": CONSISTENCY_COEFFICIENT_BITS,
                    "consistencyCoefficientMaximumDecimal": setup_consistency_coefficient_maximum.to_string(),
                    "claimMaskRadix": CLAIM_MASK_RADIX,
                    "maskDigitCount": COMPACT_VSS_DIGIT_CLAIM_MASK_DIGIT_COUNT,
                    "rangeEvidenceRule": "bridge target messages use direct digit claims and verifier-side trit decoder columns",
                },
                {
                    "rowId": "compact-vss-target-decryption-aggregate-message-claim",
                    "proofFamily": "target-decryption-share",
                    "claimVectorClass": "aggregate-opening-message-digit",
                    "appliesToRelations": [
                        "target-decryption-share-proof"
                    ],
                    "targetRnsLimbCount": target_rns_primes.len(),
                    "largestTargetRnsPrime": largest_target_rns_prime,
                    "aggregateMessageCoefficientBoundDecimal": aggregate_target_message_coefficient_bound.to_string(),
                    "messageDigitBaseDecimal": crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_MESSAGE_DIGIT_BASE.to_string(),
                    "messageDigitCount": message_column_count,
                    "witnessInfinityBoundDecimal": aggregate_target_message_digit_maximum.to_string(),
                    "clearClaimBoundDecimal": masked_claim_clear_bound_decimal_fixture(
                        aggregate_target_message_digit_maximum as u128,
                        POLYNOMIAL_DEGREE as u64,
                        CONSISTENCY_COEFFICIENT_BITS,
                    ),
                    "consistencyRepetitions": CONSISTENCY_REPETITIONS,
                    "consistencyCoefficientBits": CONSISTENCY_COEFFICIENT_BITS,
                    "consistencyCoefficientMaximumDecimal": setup_consistency_coefficient_maximum.to_string(),
                    "claimMaskRadix": CLAIM_MASK_RADIX,
                    "maskDigitCount": TARGET_DECRYPTION_AGGREGATE_MESSAGE_CLAIM_MASK_DIGIT_COUNT,
                    "rangeEvidenceRule": "target aggregate messages use direct masked claims for each committed base-3^17 digit and verifier-side trit decoder columns",
                },
                {
                    "rowId": "compact-vss-target-decryption-smudging-message-claim",
                    "proofFamily": "target-decryption-share",
                    "claimVectorClass": "smudging-opening-message-digit",
                    "appliesToRelations": [
                        "target-decryption-share-proof"
                    ],
                    "smudgingMessageCoefficientBound": target_decryption_smudging_message_coefficient_bound,
                    "messageDigitBaseDecimal": crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_MESSAGE_DIGIT_BASE.to_string(),
                    "messageDigitCount": message_column_count,
                    "witnessInfinityBoundDecimal": smudging_target_message_digit_maximum.to_string(),
                    "clearClaimBoundDecimal": masked_claim_clear_bound_decimal_fixture(
                        smudging_target_message_digit_maximum as u128,
                        POLYNOMIAL_DEGREE as u64,
                        CONSISTENCY_COEFFICIENT_BITS,
                    ),
                    "consistencyRepetitions": CONSISTENCY_REPETITIONS,
                    "consistencyCoefficientBits": CONSISTENCY_COEFFICIENT_BITS,
                    "consistencyCoefficientMaximumDecimal": setup_consistency_coefficient_maximum.to_string(),
                    "claimMaskRadix": CLAIM_MASK_RADIX,
                    "maskDigitCount": TARGET_DECRYPTION_SMUDGING_MESSAGE_CLAIM_MASK_DIGIT_COUNT,
                    "rangeEvidenceRule": "target smudging messages use direct masked claims for each committed base-3^17 digit and verifier-side trit decoder columns",
                },
                {
                    "rowId": "compact-vss-target-decryption-randomness-claim",
                    "proofFamily": "target-decryption-share",
                    "claimVectorClass": "target-opening-randomness",
                    "appliesToRelations": [
                        "target-decryption-share-proof"
                    ],
                    "witnessInfinityBound": 1_u64,
                    "clearClaimBoundDecimal": masked_claim_clear_bound_decimal_fixture(
                        1,
                        POLYNOMIAL_DEGREE as u64,
                        CONSISTENCY_COEFFICIENT_BITS,
                    ),
                    "consistencyRepetitions": CONSISTENCY_REPETITIONS,
                    "consistencyCoefficientBits": CONSISTENCY_COEFFICIENT_BITS,
                    "consistencyCoefficientMaximumDecimal": setup_consistency_coefficient_maximum.to_string(),
                    "claimMaskRadix": CLAIM_MASK_RADIX,
                    "maskDigitCount": TARGET_DECRYPTION_RANDOMNESS_CLAIM_MASK_DIGIT_COUNT,
                    "rangeEvidenceRule": "target opening randomness claims use ternary witness columns and the target randomness mask",
                },
            ],
            "targetBasisReductionRows": [
                {
                    "rowId": "compact-vss-same-secret-bridge-target-reduction",
                    "sourceSecretDistribution": "standard-ternary",
                    "sourceSignedRepresentativeInfinityBound": 1_u64,
                    "targetRnsLimbCount": target_rns_limb_count,
                    "targetRnsPrimes": target_rns_primes,
                    "targetBasisHash": profile["canonicalTargetBasisHash"],
                    "targetBasisLimbOrder": "profile-order-prefix",
                    "sameSecretProofFamilyBindingRoot": same_secret_proof_family_binding_root_fixture(),
                },
            ],
            "structuredRingRows": [
                {
                    "rowId": "compact-vss-structured-ring-review-input",
                    "coefficientRing": "Z_q[X]/(X^N+1)",
                    "ringPolynomial": "X^N+1",
                    "ringDegree": POLYNOMIAL_DEGREE,
                    "cyclotomicFamily": "power-of-two negacyclic",
                    "commitmentModulusLimbs": commitment_modulus_limbs,
                    "matrixResidueHashDomain": "sealed-lattice-compact-vss-commitment/matrix-residue-v1",
                    "randomnessProjectionIndexHashDomain": "sealed-lattice-compact-vss-commitment/projection-index-v1",
                    "sampledMatrixResiduesPerCommitment": sampled_matrix_residues_per_commitment,
                    "reviewScope": "binding and hiding estimates must account for the module/cyclotomic ring structure, not only scalar LWE rows",
                },
            ],
            "multiOpeningRows": [
                {
                    "rowId": "compact-vss-multi-opening-review-input",
                    "publicCommitmentExposureRow": "compact-vss-final-public-commitment-exposure",
                    "sourceCoefficientCommitments": source_coefficient_commitments,
                    "recipientShareCommitments": recipient_share_commitments,
                    "aggregateThresholdCommitments": aggregate_threshold_commitments,
                    "totalCompactCommitments": total_compact_commitments,
                    "maximumNonReconstructingRecipientCount": maximum_non_reconstructing_recipient_count,
                    "corruptedRecipientOpeningCredentialCount": corrupted_recipient_opening_credential_count,
                    "correlatedOpeningModel": "recipient-share and aggregate openings are public linear combinations under the same compact commitment key; the hiding row must account for the joint view",
                    "multiOpeningLossScope": "loss is counted across coefficient, recipient-share, aggregate, same-secret bridge, and target-decryption openings sharing the final compact parameter set",
                },
            ],
            "reviewReductionRows": [
                {
                    "rowId": "compact-vss-module-sis-binding-review-input",
                    "problem": "Module-SIS",
                    "bindingRows": [
                        "compact-vss-covered-message-module-sis-binding-input"
                    ],
                    "openingWitnessRows": [
                        "compact-vss-fresh-opening-witness",
                        "compact-vss-aggregate-opening-witness"
                    ],
                    "linearRelationRows": [
                        "compact-vss-recipient-share-shamir-evaluation",
                        "compact-vss-aggregate-threshold-public-sum",
                        "compact-vss-one-recipient-aggregate-from-source-coefficients"
                    ],
                    "maskedClaimNormRows": [
                        "compact-vss-share-linkage-carry-claim",
                        "compact-vss-share-linkage-message-digit-claim",
                        "compact-vss-same-secret-bridge-non-digit-claim",
                        "compact-vss-same-secret-bridge-message-digit-claim",
                        "compact-vss-target-decryption-aggregate-message-claim",
                        "compact-vss-target-decryption-smudging-message-claim",
                        "compact-vss-target-decryption-randomness-claim"
                    ],
                    "proofExtractionRows": [
                        "compact-vss-share-linkage-proof-extraction-input",
                        "compact-vss-same-secret-bridge-proof-extraction-input",
                        "compact-vss-target-decryption-proof-extraction-input"
                    ],
                    "multiOpeningRows": [
                        "compact-vss-multi-opening-review-input"
                    ],
                    "collisionDifferenceRule": "subtract two accepted openings over the integers before reducing to the commitment modulus",
                },
                {
                    "rowId": "compact-vss-module-lwe-hiding-review-input",
                    "problem": "Module-LWE",
                    "hidingRows": [
                        "compact-vss-covered-message-module-lwe-hiding-input"
                    ],
                    "openingWitnessRows": [
                        "compact-vss-fresh-opening-witness",
                        "compact-vss-aggregate-opening-witness"
                    ],
                    "maskedClaimNormRows": [
                        "compact-vss-share-linkage-carry-claim",
                        "compact-vss-share-linkage-message-digit-claim",
                        "compact-vss-same-secret-bridge-non-digit-claim",
                        "compact-vss-same-secret-bridge-message-digit-claim",
                        "compact-vss-target-decryption-aggregate-message-claim",
                        "compact-vss-target-decryption-smudging-message-claim",
                        "compact-vss-target-decryption-randomness-claim"
                    ],
                    "randomnessSource": "balanced-ternary opening columns before public linear aggregation",
                    "sampledRandomnessProjectionIndicesPerCommitment": sampled_randomness_projection_indices_per_commitment,
                    "multiOpeningRows": [
                        "compact-vss-multi-opening-review-input"
                    ],
                },
            ],
            "moduleSisBindingRows": [
                {
                    "rowId": "compact-vss-covered-message-module-sis-binding-input",
                    "problem": "Module-SIS",
                    "coefficientRing": "Z_q[X]/(X^N+1)",
                    "ringDegree": POLYNOMIAL_DEGREE,
                    "commitmentModulusLimbs": commitment_modulus_limbs,
                    "outputCoordinateCount": output_coordinate_count,
                    "coordinateCountPerCommitment": coordinate_count_per_commitment,
                    "messageDigitBaseDecimal": crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_MESSAGE_DIGIT_BASE.to_string(),
                    "messageDigitCount": message_column_count,
                    "messageDigitTritCount": crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_MESSAGE_BASE_DIGIT_TRIT_COUNT,
                    "messageDigitDifferenceInfinityBoundDecimal": compact_vss_message_digit_maximum.to_string(),
                    "freshnessRandomnessDifferenceInfinityBound": 2_u64,
                    "aggregateRandomnessDifferenceInfinityBound": aggregate_randomness_difference_infinity_bound,
                    "sampledMessageMatrixResiduesPerCommitment": message_matrix_residues_per_commitment,
                    "sampledRandomnessProjectionIndicesPerCommitment": sampled_randomness_projection_indices_per_commitment,
                    "sampledMatrixResiduesPerCommitment": sampled_matrix_residues_per_commitment,
                    "openingWitnessRows": [
                        "compact-vss-fresh-opening-witness",
                        "compact-vss-aggregate-opening-witness"
                    ],
                    "linearRelationRows": [
                        "compact-vss-recipient-share-shamir-evaluation",
                        "compact-vss-aggregate-threshold-public-sum",
                        "compact-vss-one-recipient-aggregate-from-source-coefficients"
                    ],
                    "proofExtractionRows": [
                        "compact-vss-share-linkage-proof-extraction-input",
                        "compact-vss-same-secret-bridge-proof-extraction-input",
                        "compact-vss-target-decryption-proof-extraction-input"
                    ],
                    "multiOpeningRows": [
                        "compact-vss-multi-opening-review-input"
                    ],
                    "estimatorSmallnessPrecondition": {
                        "smallestCommitmentModulus": smallest_commitment_modulus,
                        "strictDifferenceUpperBoundDecimal": estimator_digit_difference_strict_upper_bound.to_string(),
                        "messageDigitDifferenceInfinityBoundDecimal": compact_vss_message_digit_maximum.to_string(),
                        "marginDecimal": estimator_digit_precondition_margin.to_string(),
                    },
                },
            ],
            "moduleLweHidingRows": [
                {
                    "rowId": "compact-vss-covered-message-module-lwe-hiding-input",
                    "problem": "Module-LWE",
                    "coefficientRing": "Z_q[X]/(X^N+1)",
                    "ringDegree": POLYNOMIAL_DEGREE,
                    "commitmentModulusLimbs": commitment_modulus_limbs,
                    "outputCoordinateCount": output_coordinate_count,
                    "coordinateCountPerCommitment": coordinate_count_per_commitment,
                    "randomnessColumnCount": randomness_column_count,
                    "randomnessProjectionWeight": randomness_projection_weight,
                    "randomnessSource": "balanced-ternary opening columns before public linear aggregation",
                    "publicCommitmentExposureRow": "compact-vss-final-public-commitment-exposure",
                    "totalPublicCommitmentCoordinates": total_public_commitment_coordinates,
                    "sampledRandomnessProjectionIndicesPerCommitment": sampled_randomness_projection_indices_per_commitment,
                    "totalSampledRandomnessProjectionIndices": total_sampled_randomness_projection_indices,
                    "maximumNonReconstructingRecipientCount": maximum_non_reconstructing_recipient_count,
                    "corruptedRecipientOpeningCredentialCount": corrupted_recipient_opening_credential_count,
                    "corruptedRecipientLeakageModel": "corrupted recipients learn their delivered shares and opening credentials; hiding must cover all other coefficient openings under the same compact key",
                    "multiOpeningRows": [
                        "compact-vss-multi-opening-review-input"
                    ],
                    "structuredRingRows": [
                        "compact-vss-structured-ring-review-input"
                    ],
                },
            ],
            "certificateConclusionRows": [
                {
                    "rowId": "compact-vss-covered-message-module-sis-binding-conclusion",
                    "problem": "Module-SIS",
                    "construction": "covered-message compact Ajtai-style commitment over Z_q[X]/(X^N+1)",
                    "reduction": "two verifier-valid openings for the same compact commitment subtract to a nonzero Module-SIS relation over the joint message-digit and randomness-difference witness",
                    "sourceInputRows": [
                        "compact-vss-covered-message-module-sis-binding-input",
                        "compact-vss-message-coordinate-coverage",
                        "compact-vss-fresh-opening-witness",
                        "compact-vss-aggregate-opening-witness",
                        "compact-vss-share-linkage-proof-extraction-input",
                        "compact-vss-same-secret-bridge-proof-extraction-input",
                        "compact-vss-target-decryption-proof-extraction-input",
                        "compact-vss-multi-opening-review-input"
                    ],
                    "verifierRangeEvidence": "message digits are bounded by verifier-side trit decoder columns, carry claims, and masked consistency rows before a compact opening is accepted",
                    "witnessDifferenceInfinityBoundDecimal": compact_vss_message_digit_maximum.to_string(),
                    "randomnessDifferenceInfinityBounds": {
                        "freshOpening": 2_u64,
                        "aggregateOpening": aggregate_randomness_difference_infinity_bound,
                    },
                    "estimatorPrecondition": {
                        "source": "malb/lattice-estimator SIS lattice row requires length_bound < (q - 1) / 2",
                        "smallestCommitmentModulus": smallest_commitment_modulus,
                        "strictDifferenceUpperBoundDecimal": estimator_digit_difference_strict_upper_bound.to_string(),
                        "witnessDifferenceInfinityBoundDecimal": compact_vss_message_digit_maximum.to_string(),
                        "marginDecimal": estimator_digit_precondition_margin.to_string(),
                    },
                    "literatureBasis": [
                        "HSS24 modified Ajtai commitment: binding under MSIS for the joint message-and-randomness opening difference",
                        "LNP22/Lyubashevsky-style opening proof extraction: verifier-accepted openings give bounded witness differences"
                    ],
                },
                {
                    "rowId": "compact-vss-covered-message-module-lwe-hiding-conclusion",
                    "problem": "Module-LWE",
                    "construction": "covered-message compact Ajtai-style commitment with two balanced-ternary randomness columns",
                    "reduction": "public compact commitments are interpreted as Module-LWE samples hiding the message shift under the final public sample count and corrupted-recipient opening view",
                    "sourceInputRows": [
                        "compact-vss-covered-message-module-lwe-hiding-input",
                        "compact-vss-final-public-commitment-exposure",
                        "compact-vss-multi-opening-review-input",
                        "compact-vss-structured-ring-review-input"
                    ],
                    "randomnessSource": "balanced-ternary opening columns before public linear aggregation",
                    "publicSampleRows": {
                        "totalCompactCommitments": total_compact_commitments,
                        "totalPublicCommitmentCoordinates": total_public_commitment_coordinates,
                        "sampledRandomnessProjectionIndicesPerCommitment": sampled_randomness_projection_indices_per_commitment,
                        "totalSampledRandomnessProjectionIndices": total_sampled_randomness_projection_indices,
                    },
                    "corruptedRecipientOpeningCredentialCount": corrupted_recipient_opening_credential_count,
                    "leakageScope": "hiding review covers the joint public commitment view plus delivered openings for a non-reconstructing corrupted-recipient set",
                    "literatureBasis": [
                        "HSS24 modified Ajtai commitment: hiding under MLWE for the small randomness part",
                        "ACF25-style functional-hiding caution: delegated derived openings are not used on the selected fresh-recipient-commitment path"
                    ],
                },
                {
                    "rowId": "compact-vss-structured-ring-review-conclusion",
                    "construction": "power-of-two negacyclic module ring with uniformly sampled commitment residues from the bound matrix-expansion domains",
                    "sourceInputRows": [
                        "compact-vss-structured-ring-review-input"
                    ],
                    "ringDegree": POLYNOMIAL_DEGREE,
                    "commitmentModulusLimbs": commitment_modulus_limbs,
                    "matrixResidueHashDomain": "sealed-lattice-compact-vss-commitment/matrix-residue-v1",
                    "randomnessProjectionIndexHashDomain": "sealed-lattice-compact-vss-commitment/projection-index-v1",
                    "reviewScope": "binding and hiding conclusions are scoped to the declared module/cyclotomic ring and do not rely on scalar-only rows",
                },
                {
                    "rowId": "compact-vss-multi-opening-review-conclusion",
                    "sourceInputRows": [
                        "compact-vss-multi-opening-review-input"
                    ],
                    "sourceCoefficientCommitments": source_coefficient_commitments,
                    "recipientShareCommitments": recipient_share_commitments,
                    "aggregateThresholdCommitments": aggregate_threshold_commitments,
                    "totalCompactCommitments": total_compact_commitments,
                    "maximumNonReconstructingRecipientCount": maximum_non_reconstructing_recipient_count,
                    "corruptedRecipientOpeningCredentialCount": corrupted_recipient_opening_credential_count,
                    "exposureScope": "multi-opening loss is counted across coefficient, recipient-share, aggregate, same-secret bridge, and target-decryption openings sharing the final compact parameter set",
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
                "messageCoverageTermsPerCoordinate": message_coverage_terms_per_coordinate,
                "randomnessProjectionWeight": randomness_projection_weight,
                "sampledMatrixResiduesPerCommitment": sampled_matrix_residues_per_commitment,
                "sampledRandomnessProjectionIndicesPerCommitment": sampled_randomness_projection_indices_per_commitment,
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
                "messageCoverageTermsPerCoordinate": message_coverage_terms_per_coordinate,
                "randomnessProjectionWeight": randomness_projection_weight,
                "sampledMatrixResiduesPerCommitment": sampled_matrix_residues_per_commitment,
                "sampledRandomnessProjectionIndicesPerCommitment": sampled_randomness_projection_indices_per_commitment,
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

fn consistency_coefficient_maximum_fixture(coefficient_bits: u32) -> u128 {
    (1_u128 << coefficient_bits) - 1
}

fn masked_claim_clear_bound_decimal_fixture(
    witness_infinity_bound: u128,
    ring_degree: u64,
    consistency_coefficient_bits: u32,
) -> String {
    let clear_bound = witness_infinity_bound
        * u128::from(ring_degree)
        * consistency_coefficient_maximum_fixture(consistency_coefficient_bits);

    clear_bound.to_string()
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
