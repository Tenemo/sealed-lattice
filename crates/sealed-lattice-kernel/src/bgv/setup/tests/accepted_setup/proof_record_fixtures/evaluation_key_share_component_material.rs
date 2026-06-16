use super::*;

// Build one key share's public component material so the trustee
// evaluation-key relation holds: for digit j and limb l,
// b = p * e_j - a_{j,l} (*) s + [l == j] * source_j, with the per-digit
// source supplied as exact lifted integers (round one and Galois) or as
// residues of the public-aggregate product (round two).
pub(in super::super) fn evaluation_key_share_fixture_material(
    proof_family: EvaluationKeyShareProofFamily,
    trustee_roster_position: u64,
    level: u64,
    rotation: Option<u64>,
    ring_degree: usize,
    key_switch_seed_hex: &str,
    relinearization_source_by_digit: Option<&[Vec<i128>]>,
) -> EvaluationKeyShareFixtureMaterial {
    let level = usize::try_from(level).expect("level fits usize");
    let secret_coefficients =
        evaluation_key_secret_coefficients_for_fixture(trustee_roster_position, ring_degree);
    let secret_i128 = secret_coefficients
        .iter()
        .map(|coefficient| i128::from(*coefficient))
        .collect::<Vec<_>>();
    let key_switch_domain = match proof_family {
        EvaluationKeyShareProofFamily::Relinearization => "relinearization".to_string(),
        EvaluationKeyShareProofFamily::Galois => {
            format!("galois-{}", rotation.expect("Galois rotation"))
        }
    };
    let source_by_digit: Vec<Vec<i128>> = match proof_family {
        EvaluationKeyShareProofFamily::Relinearization => relinearization_source_by_digit
            .expect("relinearization source coefficients")
            .to_vec(),
        EvaluationKeyShareProofFamily::Galois => {
            let galois_source = automorphism_i128_for_evaluation_key_fixture(
                &secret_i128,
                usize::try_from(rotation.expect("Galois rotation")).expect("rotation fits usize"),
            )
            .expect("Galois source");
            vec![galois_source; level + 1]
        }
    };
    assert_eq!(source_by_digit.len(), level + 1);
    let mut component_b_by_digit = Vec::new();
    for (digit_index, digit_source) in source_by_digit.iter().enumerate() {
        let error_coefficients = evaluation_key_error_coefficients_for_fixture(
            proof_family,
            trustee_roster_position,
            level,
            rotation,
            digit_index,
            ring_degree,
        );
        let component_b_by_limb = (0..=level)
            .map(|rns_limb_index| {
                let source_for_limb = if rns_limb_index == digit_index {
                    digit_source.clone()
                } else {
                    vec![0_i128; ring_degree]
                };
                key_switch_component_b_for_evaluation_key_fixture(KeySwitchComponentBFixtureInput {
                    key_switch_domain: &key_switch_domain,
                    key_switch_seed_hex,
                    digit_index,
                    source_coefficients: &source_for_limb,
                    secret_coefficients: &secret_coefficients,
                    error_coefficients: &error_coefficients,
                    modulus: DATA_PRIMES[rns_limb_index],
                    ring_degree,
                })
                .expect("evaluation-key component b")
            })
            .collect::<Vec<_>>();
        component_b_by_digit.push(component_b_by_limb);
    }
    let (component_vector_entries, component_vector_root) = evaluation_key_component_vector_entries(
        proof_family,
        &key_switch_domain,
        key_switch_seed_hex,
        level,
        ring_degree,
        &component_b_by_digit,
    );

    EvaluationKeyShareFixtureMaterial {
        component_b_by_digit,
        component_vector_entries,
        component_vector_root,
    }
}

pub(in super::super) fn evaluation_key_secret_coefficients_for_fixture(
    trustee_roster_position: u64,
    ring_degree: usize,
) -> Vec<i64> {
    (0..ring_degree)
        .map(|coefficient_position| {
            accepted_vss_secret_coefficient_fixture(trustee_roster_position, coefficient_position)
        })
        .collect()
}

// Round-one sources: the trustee secret on every digit diagonal.
pub(in super::super) fn relinearization_round_one_source_by_digit_for_fixture(
    trustee_roster_position: u64,
    ring_degree: usize,
    digit_count: usize,
) -> Vec<Vec<i128>> {
    let secret_i128 =
        evaluation_key_secret_coefficients_for_fixture(trustee_roster_position, ring_degree)
            .into_iter()
            .map(i128::from)
            .collect::<Vec<_>>();

    vec![secret_i128; digit_count]
}

// Round-two sources: the trustee secret times the PUBLIC round-one aggregate
// diagonal, computed per digit field exactly as the package verifier
// recomputes it, so each trustee forms its round-two share from public
// material only.
pub(in super::super) fn relinearization_round_two_source_by_digit_for_fixture(
    trustee_roster_position: u64,
    ring_degree: usize,
    round_one_aggregate_diagonals: &[Vec<u64>],
) -> Vec<Vec<i128>> {
    let secret =
        evaluation_key_secret_coefficients_for_fixture(trustee_roster_position, ring_degree);
    round_one_aggregate_diagonals
        .iter()
        .enumerate()
        .map(|(digit_index, aggregate_diagonal)| {
            let modulus = DATA_PRIMES[digit_index];
            let secret_residues = secret
                .iter()
                .map(|coefficient| signed_i64_residue_for_fixture(*coefficient, modulus))
                .collect::<Vec<_>>();
            negacyclic_product_mod(&secret_residues, aggregate_diagonal, modulus)
                .expect("round-two aggregate source product")
                .into_iter()
                .map(i128::from)
                .collect()
        })
        .collect()
}

// The public round-one aggregate diagonals recomputed from the package
// records through the same path the verifier uses.
pub(in super::super) fn round_one_aggregate_diagonals_from_fixture_package(
    package: &serde_json::Value,
    transported_component_material: Option<&serde_json::Value>,
) -> BTreeMap<u64, Vec<Vec<u64>>> {
    round_one_public_aggregate_diagonals_from_package(package, transported_component_material)
        .expect("round-one public aggregate diagonals")
}

pub(in super::super) fn evaluation_key_error_coefficients_for_fixture(
    proof_family: EvaluationKeyShareProofFamily,
    trustee_roster_position: u64,
    level: usize,
    rotation: Option<u64>,
    digit_index: usize,
    ring_degree: usize,
) -> Vec<i64> {
    let family_offset = match proof_family {
        EvaluationKeyShareProofFamily::Relinearization => 13_usize,
        EvaluationKeyShareProofFamily::Galois => {
            usize::try_from(rotation.expect("Galois rotation")).expect("rotation fits usize") % 17
        }
    };
    (0..ring_degree)
        .map(|coefficient_position| {
            match (trustee_roster_position as usize * 41
                + level * 19
                + digit_index * 7
                + coefficient_position * 5
                + family_offset)
                % 5
            {
                0 => -2,
                1 => -1,
                2 => 0,
                3 => 1,
                _ => 2,
            }
        })
        .collect()
}

fn evaluation_key_component_vector_entries(
    proof_family: EvaluationKeyShareProofFamily,
    key_switch_domain: &str,
    key_switch_seed_hex: &str,
    level: usize,
    ring_degree: usize,
    component_b_by_digit: &[Vec<Vec<u64>>],
) -> (Vec<serde_json::Value>, String) {
    let entries = component_b_by_digit
        .iter()
        .enumerate()
        .flat_map(|(digit_index, component_b_by_limb)| {
            component_b_by_limb
                .iter()
                .enumerate()
                .map(move |(rns_limb_index, coefficients)| {
                    serde_json::json!({
                        "digitIndex": digit_index,
                        "rnsLimbIndex": rns_limb_index,
                        "rnsPrime": DATA_PRIMES[rns_limb_index],
                        "component": "b",
                        "coefficientByteLength": ring_degree * 8,
                        "coefficientVectorHash512": evaluation_key_share_component_vector_hash(coefficients),
                        "coefficientsLeHex": coefficient_vector_le_hex(coefficients),
                    })
                })
        })
        .collect::<Vec<_>>();
    let root = evaluation_key_share_component_vector_root(
        proof_family,
        key_switch_domain,
        key_switch_seed_hex,
        level,
        ring_degree,
        &entries,
    )
    .expect("evaluation-key component vector root");

    (entries, root)
}

pub(in super::super) fn relinearization_key_switch_seed_for_test(
    schedule: &serde_json::Value,
    round: &str,
    level: u64,
) -> String {
    derive_protocol_hash(
        "RelinearizationKeyShareSeed",
        &serde_json::json!({
            "objectType": "RelinearizationKeySwitchPublicSampleSeed",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "setupProofProfileId": "SealedLattice-SetupProof-v1",
            "proofFamily": "relinearization-key-share",
            "keySwitchSampleScope": "shared-by-scheduled-level-and-round",
            "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
            "relinearizationCrpRoot": schedule["relinearizationCrpRoot"],
            "round": round,
            "level": level,
        }),
    )
    .expect("relinearization key-switch seed")
}

pub(in super::super) fn galois_key_switch_seed_for_test(
    schedule: &serde_json::Value,
    rotation: u64,
    level: u64,
) -> String {
    derive_protocol_hash(
        "GaloisKeyShareSeed",
        &serde_json::json!({
            "objectType": "GaloisKeySwitchPublicSampleSeed",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "setupProofProfileId": "SealedLattice-SetupProof-v1",
            "proofFamily": "galois-key-share",
            "keySwitchSampleScope": "shared-by-scheduled-rotation-and-level",
            "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
            "galoisKeyCrpRoot": schedule["galoisKeyCrpRoot"],
            "requiredGaloisSetHash": schedule["requiredGaloisSetHash"],
            "rotation": rotation,
            "level": level,
        }),
    )
    .expect("Galois key-switch seed")
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
