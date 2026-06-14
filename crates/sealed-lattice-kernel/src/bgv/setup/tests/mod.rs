use super::sampling::{
    reduce_unbiased_u64, sample_centered_binomial_eta2, sample_residue, sample_small_distribution,
};
use super::sharing::{
    RnsShamirShare, canonical_trustee_point, evaluate_shamir_polynomial,
    interpolate_shamir_constant_with_threshold,
};
use super::validation::{validate_setup_package_internal_bindings, validate_setup_package_shape};
use super::vss::{evaluate_unreduced_shamir_polynomial, verify_carry_aware_vss_share_opening};
use super::{
    DATA_PRIMES, PASSIVE_SETUP_PROFILE_ID, POLYNOMIAL_DEGREE,
    abort_threshold_share_commitment_transport_derivation_stream_request,
    absorb_threshold_share_commitment_transport_derivation_stream_chunk_request,
    begin_threshold_share_commitment_transport_derivation_stream_request, data_basis_modulus_bits,
    dense_centered_binomial_coefficients,
    derive_collective_bgv_setup_public_derivations_from_request,
    derive_threshold_share_commitments_from_request,
    derive_threshold_share_commitments_from_transport_request,
    describe_collective_bgv_setup_profile, development_evaluator_key_from_passive_setup_package,
    extended_basis_modulus_bits,
    finish_threshold_share_commitment_transport_derivation_stream_request,
    generate_passive_setup_package_from_request, read_public_evaluation_key_rotation_requests,
    release_verified_transported_vss_material_request, sample_public_residues,
    selected_public_evaluation_key_rotation_requests,
    verify_collective_bgv_setup_package_from_request,
    verify_local_trustee_setup_state_from_request, verify_passive_setup_package_from_request,
    verify_private_vss_share_envelope_from_request,
};
use super::{
    commitment::{
        SETUP_COMMITMENT_MODULUS_LIMB_INDICES, SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND,
        SETUP_COMMITMENT_RANDOMNESS_WIDTH, SETUP_COMMITMENT_ROW_COUNT,
        compute_setup_commitment_for_tests, parse_setup_commitment_full_value,
        setup_commitment_full_value, setup_commitment_root,
    },
    private_vss_share_proof::{
        PrivateVssShareSuccinctProofGenerationInput, PrivateVssShareSuccinctProofVerificationInput,
        PrivateVssShareSuccinctProofWitness, private_vss_share_succinct_proof_record,
        verify_private_vss_share_succinct_relation_proof,
    },
    trustee_evaluation_key_proof::{
        PRIVATE_VSS_SHARE_SUCCINCT_PROOF_MODEL_STATUS,
        PRIVATE_VSS_SHARE_SUCCINCT_PROOF_VERIFICATION_STATUS,
        succinct_private_vss_share_accounting_hash,
    },
    vss::{CarryAwareVssCommitmentOpeningInput, verify_carry_aware_vss_commitment_opening},
};
use crate::bgv::evaluator::{
    circuit::{EvaluatorContext, modulus_switch_to, multiply},
    engine::{DevelopmentBgvKey, ciphertext_tensor, encode_slots_to_coefficients},
    key_switch::{generate_galois_key, generate_relinearization_key, relinearize, rotate},
    top_k::DIRECT_COMPARISON_OUTPUT_LEVEL,
};
use crate::bgv::modular_arithmetic::{add_mod, mul_mod, sub_mod};
use crate::bgv::ntt::forward_negacyclic_ntt;
use crate::bgv::profile::PLAINTEXT_MODULUS;
use crate::hashing::{derive_protocol_hash, hash512};
use std::sync::OnceLock;

mod accepted_setup;
mod evaluation_key_material;
mod generation_and_certificate;
mod local_trustee_state;
mod payload_rejection;
mod private_vss;
mod sampling;
mod sharing_algebra;
mod threshold_share_commitments;
mod vss_share_relation;

type SetupPackageMutation = (&'static str, Box<dyn Fn(&mut serde_json::Value)>);

const EXPECTED_PASSIVE_SETUP_TEST_PACKAGE_HASH: &str = "e35201936f42d2e397cee7e9ca91e25fbe955017e9a794019a0173d56269c7bb4935a9a8b4826202db1df2af3462b86dd42160e5ad17fef72aa24c417a1a6ccd";

static PASSIVE_SETUP_TEST_PACKAGE: OnceLock<serde_json::Value> = OnceLock::new();
static PASSIVE_SETUP_TEST_EVALUATOR_KEY: OnceLock<DevelopmentBgvKey> = OnceLock::new();
static PASSIVE_SETUP_LEVEL_ONE_PUBLIC_MATERIAL: OnceLock<serde_json::Value> = OnceLock::new();
static PASSIVE_SETUP_LEVEL_ONE_PUBLIC_CONTEXT: OnceLock<EvaluatorContext> = OnceLock::new();
static PASSIVE_SETUP_ROTATION_PUBLIC_MATERIAL: OnceLock<serde_json::Value> = OnceLock::new();
static PASSIVE_SETUP_ROTATION_PUBLIC_CONTEXT: OnceLock<EvaluatorContext> = OnceLock::new();

fn request() -> serde_json::Value {
    serde_json::json!({
        "ceremonyId": "ceremony-main",
        "manifestHash": derive_protocol_hash(
            "ElectionManifestHash",
            &serde_json::json!({ "manifest": "passive-bgv-setup-test" }),
        ).expect("manifest hash"),
        "rosterHash": derive_protocol_hash(
            "RosterHash",
            &serde_json::json!({ "roster": "passive-bgv-setup-test" }),
        ).expect("roster hash"),
        "thresholdProfileHash": derive_protocol_hash(
            "ThresholdProfileHash",
            &serde_json::json!({ "threshold": "passive-bgv-setup-test" }),
        ).expect("threshold hash"),
        "participants": [
            { "trusteeIdentity": "trustee-1", "rosterPosition": 0, "boardPosition": 3 },
            { "trusteeIdentity": "trustee-2", "rosterPosition": 1, "boardPosition": 4 },
            { "trusteeIdentity": "trustee-3", "rosterPosition": 2, "boardPosition": 5 }
        ],
        "setupSeed": "passive-bgv-setup-test-seed",
    })
}

fn setup_package_ref() -> &'static serde_json::Value {
    PASSIVE_SETUP_TEST_PACKAGE
        .get_or_init(|| generate_passive_setup_package_from_request(&request()).expect("setup"))
}

fn setup_package() -> serde_json::Value {
    setup_package_ref().clone()
}

fn rebind_setup_package_hash(package: &mut serde_json::Value) {
    let mut hash_input = package.clone();
    hash_input
        .as_object_mut()
        .expect("setup package must be an object")
        .remove("setupPackageHash");
    package["setupPackageHash"] = serde_json::json!(
        derive_protocol_hash("BGVPassiveSetupPackageHash", &hash_input)
            .expect("setup package hash")
    );
}

fn valid_hash(fill: char) -> String {
    fill.to_string().repeat(128)
}

fn setup_derived_evaluator_key() -> &'static DevelopmentBgvKey {
    PASSIVE_SETUP_TEST_EVALUATOR_KEY.get_or_init(|| {
        let package = setup_package_ref();
        setup_derived_evaluator_key_from_package(package)
    })
}

fn setup_derived_evaluator_key_from_package(package: &serde_json::Value) -> DevelopmentBgvKey {
    let private_setup_seed_hash =
        super::input::private_passive_setup_seed_hash_from_package_witness(
            package,
            "passive-bgv-setup-test-seed",
        )
        .expect("private setup seed hash");
    let participant_identities = package["participants"]
        .as_array()
        .expect("participants")
        .iter()
        .map(|participant| {
            participant["trusteeIdentity"]
                .as_str()
                .expect("trustee identity")
                .to_string()
        })
        .collect::<Vec<_>>();
    let (collective_secret, _) =
        super::key_material::collective_signed_secret_and_error_coefficients(
            &private_setup_seed_hash,
            &participant_identities,
        );
    let public_key_coefficients =
        super::key_material::collective_public_key_coefficients_by_modulus_from_setup_package(
            package,
        )
        .expect("collective public key coefficients");
    let public_b = public_key_coefficients
        .iter()
        .map(|coefficients| coefficients.component_zero_coefficients.clone())
        .collect::<Vec<_>>();
    let public_a = public_key_coefficients
        .iter()
        .map(|coefficients| coefficients.component_one_coefficients.clone())
        .collect::<Vec<_>>();

    DevelopmentBgvKey::from_collective_components(collective_secret, public_b, public_a)
        .expect("setup-derived evaluator key")
}

fn level_one_public_material() -> &'static serde_json::Value {
    PASSIVE_SETUP_LEVEL_ONE_PUBLIC_MATERIAL.get_or_init(|| {
        super::generate_passive_setup_public_evaluation_key_material_from_request(
            &serde_json::json!({
                "setupPackage": setup_package_ref().clone(),
                "setupPrivateWitness": {
                    "setupSeed": "passive-bgv-setup-test-seed",
                },
                "workingLevel": 1,
            }),
        )
        .expect("public evaluation-key material")
    })
}

fn level_one_public_context() -> &'static EvaluatorContext {
    PASSIVE_SETUP_LEVEL_ONE_PUBLIC_CONTEXT.get_or_init(|| {
        EvaluatorContext::from_passive_setup_public_material(
            setup_package_ref(),
            level_one_public_material(),
            1,
        )
        .expect("public evaluator context")
    })
}

fn direct_comparison_rotation_request() -> (usize, usize) {
    // Every scheduled rotation key now sits at the working level; the return
    // rotation entry exercises truncated use at the comparison output level.
    let rotation_request = setup_package_ref()["evaluationKeys"]["rotationKeyRoots"]
        .as_array()
        .expect("rotation key roots")
        .iter()
        .find(|entry| {
            entry["purpose"].as_str() == Some("generator-ordered-packed-rank-return-basis")
        })
        .expect("packed-rank return rotation key");
    let galois_element = rotation_request["rotation"]
        .as_u64()
        .expect("rotation")
        .try_into()
        .expect("rotation fits usize");
    let level = rotation_request["level"]
        .as_u64()
        .expect("level")
        .try_into()
        .expect("level fits usize");

    (galois_element, level)
}

fn rotation_public_material() -> &'static serde_json::Value {
    PASSIVE_SETUP_ROTATION_PUBLIC_MATERIAL.get_or_init(|| {
        let (galois_element, level) = direct_comparison_rotation_request();
        super::generate_passive_setup_public_evaluation_key_material_from_request(
            &serde_json::json!({
                "setupPackage": setup_package_ref().clone(),
                "setupPrivateWitness": {
                    "setupSeed": "passive-bgv-setup-test-seed",
                },
                "workingLevel": 1,
                "rotationKeys": [
                    {
                        "rotation": galois_element,
                        "level": level,
                    }
                ],
            }),
        )
        .expect("public evaluation-key material")
    })
}

fn rotation_public_context() -> &'static EvaluatorContext {
    PASSIVE_SETUP_ROTATION_PUBLIC_CONTEXT.get_or_init(|| {
        EvaluatorContext::from_passive_setup_public_material(
            setup_package_ref(),
            rotation_public_material(),
            1,
        )
        .expect("public evaluator context")
    })
}

fn rebind_public_evaluation_key_material_hash(material: &mut serde_json::Value) {
    material
        .as_object_mut()
        .expect("public evaluation-key material must be an object")
        .remove("publicEvaluationKeyMaterialHash");
    material["publicEvaluationKeyMaterialHash"] = serde_json::json!(
        derive_protocol_hash("EvaluationKeySetHash", material)
            .expect("public evaluation-key material hash")
    );
}

fn public_evaluation_key_material_error(
    package: &serde_json::Value,
    material: &serde_json::Value,
    working_level: usize,
) -> crate::encoding::CanonicalError {
    match super::public_evaluation_keys_from_material(package, material, working_level) {
        Ok(_) => panic!("public evaluation-key material mutation must reject"),
        Err(error) => error,
    }
}

fn automorphism_residues(input: &[u64], galois_element: usize, modulus: u64) -> Vec<u64> {
    let ring_order = 2 * POLYNOMIAL_DEGREE;
    let mut output = vec![0_u64; POLYNOMIAL_DEGREE];
    for (coefficient_index, value) in input.iter().enumerate() {
        let exponent = (coefficient_index * galois_element) % ring_order;
        if exponent < POLYNOMIAL_DEGREE {
            output[exponent] =
                add_mod(output[exponent], *value, modulus).expect("automorphism add");
        } else {
            output[exponent - POLYNOMIAL_DEGREE] =
                sub_mod(output[exponent - POLYNOMIAL_DEGREE], *value, modulus)
                    .expect("automorphism subtract");
        }
    }

    output
}

fn assert_setup_package_payload_is_rejected(
    package: serde_json::Value,
    mutation_description: &str,
) {
    assert!(
        validate_setup_package_shape(&package)
            .and_then(|_| validate_setup_package_internal_bindings(&package))
            .is_err(),
        "{mutation_description} should be rejected"
    );
}

fn centered_binomial_eta2_value_from_byte(byte: u8) -> i64 {
    i64::from(byte & 1) + i64::from((byte >> 1) & 1)
        - i64::from((byte >> 2) & 1)
        - i64::from((byte >> 3) & 1)
}
