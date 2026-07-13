use super::*;

use crate::bgv::setup::evaluation_key_share_material::{
    EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING, EvaluationKeyShareProofFamily,
    evaluation_key_share_component_material_reference_root,
    evaluation_key_share_component_vector_hash, evaluation_key_share_component_vector_root,
};
use crate::bgv::setup::trustee_evaluation_key_proof::public_key_switch_sample;
use crate::foundation::{CanonicalStreamDomain, CanonicalStreamWriter};
use crate::hashing::derive_canonical_object_hash;

// Deterministic public key-switch component material for one evaluation-key
// share, built so the trustee evaluation-key relation holds: for digit j and
// limb l,
//   b = p * e_j - a_{j,l} (*) s + [l == j] * source_j,
// with the per-digit source supplied as exact lifted integers (relinearization
// round one and Galois) or as residues of the public-aggregate product
// (relinearization round two). The public sample a_{j,l} is the same
// deterministic key-switch sample the accepted-setup verifier's relation
// recomputes.
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
            );
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
            })
            .collect::<Vec<_>>();
        component_b_by_digit.push(component_b_by_limb);
    }
    let component_vector_root = evaluation_key_component_vector_root(
        proof_family,
        &key_switch_domain,
        key_switch_seed_hex,
        level,
        ring_degree,
        &component_b_by_digit,
    );

    EvaluationKeyShareFixtureMaterial {
        component_b_by_digit,
        component_vector_root,
    }
}

pub(in super::super) struct AuthenticatedEvaluationKeyShareComponentMaterialFixture {
    pub(in super::super) material_root: String,
    pub(in super::super) transported_material: serde_json::Value,
}

// Moves one deterministic share's component vectors through the same canonical
// stream verifier used by the browser bridge. The package retains only the
// canonical material reference; statement construction and terminal
// verification resolve the authenticated bytes from the verifier-owned store.
pub(in super::super) fn authenticate_evaluation_key_share_component_material_fixture(
    proof_family: EvaluationKeyShareProofFamily,
    record: &serde_json::Value,
    fixture_material: &EvaluationKeyShareFixtureMaterial,
    accepted_setup_session: crate::bgv::setup::AcceptedSetupProofBindingSession,
) -> AuthenticatedEvaluationKeyShareComponentMaterialFixture {
    let material_root =
        evaluation_key_share_component_material_reference_root(proof_family, record)
            .expect("evaluation-key component material reference root");
    let material_bytes = encode_evaluation_key_share_component_material(
        record,
        &fixture_material.component_b_by_digit,
    );
    let total_byte_length =
        u64::try_from(material_bytes.len()).expect("component material byte length fits u64");
    let chunk_size = usize::try_from(SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES)
        .expect("component material chunk size fits usize");
    let mut descriptor_writer =
        CanonicalStreamWriter::new(CanonicalStreamDomain::EvaluatorKeyStore, total_byte_length)
            .expect("component material canonical descriptor writer");
    for (chunk_index, chunk) in material_bytes.chunks(chunk_size).enumerate() {
        descriptor_writer
            .absorb_chunk(chunk_index, chunk)
            .expect("canonical component material descriptor chunk");
    }
    let descriptor = descriptor_writer
        .finish()
        .expect("canonical component material descriptor");
    let descriptor_bytes = descriptor
        .encode()
        .expect("canonical component material descriptor bytes");

    authenticate_evaluation_key_share_component_material_stream(
        proof_family,
        &material_root,
        &descriptor_bytes,
        &material_bytes,
        chunk_size,
        accepted_setup_session,
    );

    let level = record["level"].as_u64().expect("component material level");
    AuthenticatedEvaluationKeyShareComponentMaterialFixture {
        material_root: material_root.clone(),
        transported_material: serde_json::json!({
            "objectType": "SetupTransportedEvaluationKeyShareComponentMaterial",
            "proofFamily": proof_family.proof_family(),
            "keySwitchMaterialEncoding": EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING,
            "trusteeIdentity": record["trusteeIdentity"],
            "trusteeRosterPosition": record["trusteeRosterPosition"],
            "keySwitchDomain": record["keySwitchDomain"],
            "keySwitchSeedHex": record["keySwitchSeedHex"],
            "level": level,
            "ringDegree": record["ringDegree"],
            "keySwitchComponentVectorRoot": record["keySwitchComponentVectorRoot"],
            "keySwitchComponentMaterialRoot": material_root,
        }),
    }
}

fn encode_evaluation_key_share_component_material(
    record: &serde_json::Value,
    component_b_by_digit: &[Vec<Vec<u64>>],
) -> Vec<u8> {
    const COMPONENT_MATERIAL_MAGIC: &[u8; 8] = b"SLEKCMV1";

    let level = record["level"].as_u64().expect("component material level");
    let ring_degree = record["ringDegree"]
        .as_u64()
        .expect("component material ring degree");
    let digit_count = level
        .checked_add(1)
        .expect("component material digit count");
    let expected_digit_count =
        usize::try_from(digit_count).expect("component material digit count fits usize");
    let expected_ring_degree =
        usize::try_from(ring_degree).expect("component material ring degree fits usize");
    assert_eq!(component_b_by_digit.len(), expected_digit_count);

    let mut bytes = Vec::new();
    bytes.extend_from_slice(COMPONENT_MATERIAL_MAGIC);
    for word in [level, ring_degree] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    for component_b_by_limb in component_b_by_digit {
        assert_eq!(component_b_by_limb.len(), expected_digit_count);
        for coefficients in component_b_by_limb {
            assert_eq!(coefficients.len(), expected_ring_degree);
            for coefficient in coefficients {
                bytes.extend_from_slice(&coefficient.to_le_bytes());
            }
        }
    }

    bytes
}

fn authenticate_evaluation_key_share_component_material_stream(
    proof_family: EvaluationKeyShareProofFamily,
    material_root: &str,
    descriptor_bytes: &[u8],
    material_bytes: &[u8],
    chunk_size: usize,
    accepted_setup_session: crate::bgv::setup::AcceptedSetupProofBindingSession,
) {
    let family_code = match proof_family {
        EvaluationKeyShareProofFamily::Relinearization => crate::bgv::setup::canonical_stream_transport::BGV_CANONICAL_STREAM_FAMILY_RELINEARIZATION_COMPONENT,
        EvaluationKeyShareProofFamily::Galois => crate::bgv::setup::canonical_stream_transport::BGV_CANONICAL_STREAM_FAMILY_GALOIS_COMPONENT,
    };
    let material_root_bytes =
        crate::transcript_core::decode_hex(material_root).expect("component material root bytes");
    let capability = [0x63; crate::foundation::CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH];
    let stream = crate::bgv::setup::begin_accepted_setup_canonical_stream(
        family_code,
        &material_root_bytes,
        descriptor_bytes,
        capability,
        accepted_setup_session,
    )
    .expect("begin authenticated component material stream");
    for (chunk_index, chunk) in material_bytes.chunks(chunk_size).enumerate() {
        crate::bgv::setup::absorb_bgv_canonical_stream_chunk(
            stream.handle,
            &capability,
            u32::try_from(chunk_index).expect("component material chunk index fits u32"),
            chunk,
        )
        .expect("authenticate component material chunk");
    }
    crate::bgv::setup::finish_bgv_canonical_stream(stream.handle, &capability)
        .expect("finish authenticated component material stream");
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
// diagonal, computed per digit field exactly as the package verifier recomputes
// it, so each trustee forms its round-two share from public material only.
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

pub(in super::super) fn evaluation_key_error_coefficients_for_fixture(
    proof_family: EvaluationKeyShareProofFamily,
    trustee_roster_position: u64,
    level: usize,
    rotation: Option<u64>,
    digit_index: usize,
    ring_degree: usize,
) -> Vec<i64> {
    // The fixture secret and base error alias with periods three and five, so
    // their combined material repeats every fifteen roster positions. Using a
    // different position multiplier from position ten onward separates those
    // aliases across the supported range while keeping errors in {-2..2}.
    const FOUNDATION_ROSTER_SIZE: u64 = 10;
    let position_multiplier = if trustee_roster_position < FOUNDATION_ROSTER_SIZE {
        5
    } else {
        1
    };
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
                + coefficient_position * position_multiplier
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

fn evaluation_key_component_vector_root(
    proof_family: EvaluationKeyShareProofFamily,
    key_switch_domain: &str,
    key_switch_seed_hex: &str,
    level: usize,
    ring_degree: usize,
    component_b_by_digit: &[Vec<Vec<u64>>],
) -> String {
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
                        "coefficientVectorHash512": evaluation_key_share_component_vector_hash(coefficients),
                        "coefficientsLeHex": coefficient_vector_le_hex(coefficients),
                    })
                })
        })
        .collect::<Vec<_>>();
    evaluation_key_share_component_vector_root(
        proof_family,
        key_switch_domain,
        key_switch_seed_hex,
        level,
        ring_degree,
        &entries,
    )
    .expect("evaluation-key component vector root")
}

// The shared relinearization key-switch sample seed, byte-identical to the
// accepted-setup verifier's `expected_relinearization_key_switch_seed`: the
// canonical hash of the schedule slot binds every trustee to the same sampler
// and no profile-identifier fields enter the preimage.
pub(in super::super) fn relinearization_key_switch_seed_for_test(
    schedule: &serde_json::Value,
    round: &str,
    level: u64,
) -> String {
    derive_canonical_object_hash(&serde_json::json!({
        "objectType": "RelinearizationKeySwitchPublicSampleSeed",
        "proofFamily": "relinearization-key-share",
        "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
        "relinearizationCrpRoot": schedule["relinearizationCrpRoot"],
        "round": round,
        "level": level,
    }))
    .expect("relinearization key-switch seed")
}

// The shared Galois key-switch sample seed, byte-identical to the
// accepted-setup verifier's `expected_galois_key_switch_seed`.
pub(in super::super) fn galois_key_switch_seed_for_test(
    schedule: &serde_json::Value,
    rotation: u64,
    level: u64,
) -> String {
    derive_canonical_object_hash(&serde_json::json!({
        "objectType": "GaloisKeySwitchPublicSampleSeed",
        "proofFamily": "galois-key-share",
        "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
        "galoisKeyCrpRoot": schedule["galoisKeyCrpRoot"],
        "requiredGaloisSetHash": schedule["requiredGaloisSetHash"],
        "rotation": rotation,
        "level": level,
    }))
    .expect("Galois key-switch seed")
}

pub(in super::super) struct KeySwitchComponentBFixtureInput<'a> {
    pub(in super::super) key_switch_domain: &'a str,
    pub(in super::super) key_switch_seed_hex: &'a str,
    pub(in super::super) digit_index: usize,
    pub(in super::super) source_coefficients: &'a [i128],
    pub(in super::super) secret_coefficients: &'a [i64],
    pub(in super::super) error_coefficients: &'a [i64],
    pub(in super::super) modulus: u64,
    pub(in super::super) ring_degree: usize,
}

// BGV key-switch hint b_i = source_i - a_i*s + p*e_i: the secret is masked by
// the shared public sample a and a plaintext-modulus-scaled error, so
// key-switching preserves the message mod p. The public sample is the same
// deterministic key-switch sample the relation verifier recomputes.
pub(in super::super) fn key_switch_component_b_for_evaluation_key_fixture(
    input: KeySwitchComponentBFixtureInput<'_>,
) -> Vec<u64> {
    let public_sample = public_key_switch_sample(
        input.key_switch_domain,
        input.key_switch_seed_hex,
        input.digit_index,
        input.modulus,
        input.ring_degree,
    );
    let secret_residues = input
        .secret_coefficients
        .iter()
        .map(|coefficient| signed_i64_residue_for_fixture(*coefficient, input.modulus))
        .collect::<Vec<_>>();
    let public_sample_secret_product =
        negacyclic_product_mod(&public_sample, &secret_residues, input.modulus)
            .expect("public-sample secret product");
    let plaintext_modulus = PLAINTEXT_MODULUS % input.modulus;
    (0..input.ring_degree)
        .map(|coefficient_index| {
            let scaled_error = mul_mod(
                plaintext_modulus,
                signed_i64_residue_for_fixture(
                    input.error_coefficients[coefficient_index],
                    input.modulus,
                ),
                input.modulus,
            )
            .expect("scaled error");
            let without_sample = sub_mod(
                scaled_error,
                public_sample_secret_product[coefficient_index],
                input.modulus,
            )
            .expect("component without sample");
            add_mod(
                without_sample,
                signed_i128_residue_for_fixture(
                    input.source_coefficients[coefficient_index],
                    input.modulus,
                ),
                input.modulus,
            )
            .expect("evaluation-key component b")
        })
        .collect()
}

// The negacyclic automorphism s(X) -> s(X^g) on lifted integer coefficients:
// X^N = -1 folds an image exponent in [N, 2N) back with a sign flip. This is
// the Galois source the diagonal_source relation checks against.
pub(in super::super) fn automorphism_i128_for_evaluation_key_fixture(
    input: &[i128],
    galois_element: usize,
) -> Vec<i128> {
    let ring_degree = input.len();
    assert!(
        ring_degree > 0,
        "evaluation-key automorphism input must be non-empty"
    );
    let two_n = ring_degree * 2;
    let mut output = vec![0_i128; ring_degree];
    for (coefficient_index, value) in input.iter().enumerate() {
        let exponent = (coefficient_index * galois_element) % two_n;
        if exponent < ring_degree {
            output[exponent] += *value;
        } else {
            output[exponent - ring_degree] -= *value;
        }
    }

    output
}

// Signed i128 coefficient reduced into the canonical non-negative residue mod
// the given modulus.
fn signed_i128_residue_for_fixture(value: i128, modulus: u64) -> u64 {
    let modulus_i128 = i128::from(modulus);
    let residue = value.rem_euclid(modulus_i128);
    u64::try_from(residue).expect("signed i128 residue fits u64")
}

#[cfg(test)]
mod tests {
    use super::*;

    // The exact per-digit, per-limb relation the accepted-setup verifier's
    // succinct argument enforces for one key share:
    //   b_{j,l} + a_{j,l} (*) s - p * e_j - [l == j] * source_j == 0 in R_{q_l}.
    // Recomputing it directly over the generated component material catches any
    // divergence between the fixture generator and the relation the real
    // prover/verifier check, without paying full proof cost.
    fn assert_key_share_relation_holds(
        proof_family: EvaluationKeyShareProofFamily,
        trustee_roster_position: u64,
        level: usize,
        rotation: Option<u64>,
        ring_degree: usize,
        source_by_digit: &[Vec<i128>],
        material: &EvaluationKeyShareFixtureMaterial,
    ) {
        let secret =
            evaluation_key_secret_coefficients_for_fixture(trustee_roster_position, ring_degree);
        let key_switch_domain = match proof_family {
            EvaluationKeyShareProofFamily::Relinearization => "relinearization".to_string(),
            EvaluationKeyShareProofFamily::Galois => {
                format!("galois-{}", rotation.expect("Galois rotation"))
            }
        };
        let key_switch_seed_hex = match proof_family {
            EvaluationKeyShareProofFamily::Relinearization => repeated_test_seed(0xa1),
            EvaluationKeyShareProofFamily::Galois => repeated_test_seed(0xb2),
        };
        assert_eq!(material.component_b_by_digit.len(), level + 1);
        for (digit_index, component_b_by_limb) in material.component_b_by_digit.iter().enumerate() {
            let error = evaluation_key_error_coefficients_for_fixture(
                proof_family,
                trustee_roster_position,
                level,
                rotation,
                digit_index,
                ring_degree,
            );
            assert_eq!(component_b_by_limb.len(), level + 1);
            for (rns_limb_index, component_b) in component_b_by_limb.iter().enumerate() {
                let modulus = DATA_PRIMES[rns_limb_index];
                let public_sample = public_key_switch_sample(
                    &key_switch_domain,
                    &key_switch_seed_hex,
                    digit_index,
                    modulus,
                    ring_degree,
                );
                let secret_residues = secret
                    .iter()
                    .map(|coefficient| signed_i64_residue_for_fixture(*coefficient, modulus))
                    .collect::<Vec<_>>();
                let sample_secret_product =
                    negacyclic_product_mod(&public_sample, &secret_residues, modulus)
                        .expect("public-sample secret product");
                let plaintext_modulus = PLAINTEXT_MODULUS % modulus;
                for coefficient_index in 0..ring_degree {
                    let source_residue = if rns_limb_index == digit_index {
                        signed_i128_residue_for_fixture(
                            source_by_digit[digit_index][coefficient_index],
                            modulus,
                        )
                    } else {
                        0
                    };
                    let scaled_error = mul_mod(
                        plaintext_modulus,
                        signed_i64_residue_for_fixture(error[coefficient_index], modulus),
                        modulus,
                    )
                    .expect("scaled error");
                    let with_sample = add_mod(
                        component_b[coefficient_index],
                        sample_secret_product[coefficient_index],
                        modulus,
                    )
                    .expect("component plus sample-secret");
                    let residual = sub_mod(
                        with_sample,
                        add_mod(scaled_error, source_residue, modulus).expect("error plus source"),
                        modulus,
                    )
                    .expect("relation residual");
                    assert_eq!(
                        residual, 0,
                        "key-share relation must vanish (family {proof_family:?}, digit {digit_index}, limb {rns_limb_index}, coefficient {coefficient_index})"
                    );
                }
            }
        }
    }

    fn repeated_test_seed(byte: u8) -> String {
        std::iter::repeat_n(format!("{byte:02x}"), 64).collect()
    }

    #[test]
    fn relinearization_round_one_component_material_satisfies_the_key_share_relation() {
        let ring_degree = 16;
        for trustee_roster_position in [0_u64, 4] {
            for level in [0_usize, 2] {
                let source = relinearization_round_one_source_by_digit_for_fixture(
                    trustee_roster_position,
                    ring_degree,
                    level + 1,
                );
                let material = evaluation_key_share_fixture_material(
                    EvaluationKeyShareProofFamily::Relinearization,
                    trustee_roster_position,
                    level as u64,
                    None,
                    ring_degree,
                    &repeated_test_seed(0xa1),
                    Some(&source),
                );
                assert_key_share_relation_holds(
                    EvaluationKeyShareProofFamily::Relinearization,
                    trustee_roster_position,
                    level,
                    None,
                    ring_degree,
                    &source,
                    &material,
                );
            }
        }
    }

    #[test]
    fn relinearization_round_two_component_material_satisfies_the_key_share_relation() {
        let ring_degree = 16;
        let trustee_roster_position = 2_u64;
        let level = 2_usize;
        // A deterministic public round-one aggregate diagonal per digit field,
        // the same public material every trustee multiplies its secret against.
        let aggregate_diagonals = (0..=level)
            .map(|digit_index| {
                let modulus = DATA_PRIMES[digit_index];
                (0..ring_degree)
                    .map(|coefficient_index| {
                        ((digit_index as u64 * 7 + coefficient_index as u64 * 3 + 5) % modulus)
                            .max(1)
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let source = relinearization_round_two_source_by_digit_for_fixture(
            trustee_roster_position,
            ring_degree,
            &aggregate_diagonals,
        );
        let material = evaluation_key_share_fixture_material(
            EvaluationKeyShareProofFamily::Relinearization,
            trustee_roster_position,
            level as u64,
            None,
            ring_degree,
            &repeated_test_seed(0xa1),
            Some(&source),
        );
        assert_key_share_relation_holds(
            EvaluationKeyShareProofFamily::Relinearization,
            trustee_roster_position,
            level,
            None,
            ring_degree,
            &source,
            &material,
        );
    }

    #[test]
    fn galois_component_material_satisfies_the_key_share_relation() {
        let ring_degree = 16;
        for rotation in [3_u64, 5] {
            let trustee_roster_position = 1_u64;
            let level = 1_usize;
            let secret = evaluation_key_secret_coefficients_for_fixture(
                trustee_roster_position,
                ring_degree,
            )
            .into_iter()
            .map(i128::from)
            .collect::<Vec<_>>();
            let galois_source = automorphism_i128_for_evaluation_key_fixture(
                &secret,
                usize::try_from(rotation).expect("rotation fits usize"),
            );
            let source = vec![galois_source; level + 1];
            let material = evaluation_key_share_fixture_material(
                EvaluationKeyShareProofFamily::Galois,
                trustee_roster_position,
                level as u64,
                Some(rotation),
                ring_degree,
                &repeated_test_seed(0xb2),
                None,
            );
            assert_key_share_relation_holds(
                EvaluationKeyShareProofFamily::Galois,
                trustee_roster_position,
                level,
                Some(rotation),
                ring_degree,
                &source,
                &material,
            );
        }
    }
}
