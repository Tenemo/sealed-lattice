//! Full-ring gate benchmark for the limb-group key-switch digit atom path.
//!
//! Run explicitly (single-threaded process, optimized test profile):
//!
//! ```text
//! cargo test -p sealed-lattice-kernel limb_group_atom_full_ring_gate_benchmark \
//!     -- --ignored --nocapture --test-threads=1
//! ```
//!
//! The benchmark verifies real level-15 kernel keygen material against the
//! limb-group digit atoms, measures the proof-field primitives that dominate a
//! Buckler-style prover (big-field NTT, CRT recombination, witness digit
//! encoding, Ajtai commitment folds), and prints a projection of per-atom,
//! per-key, and per-trustee prover cost from an explicit operation-count model.
//! Timings are printed, never asserted.

use std::time::{Duration, Instant};

use super::commitment_round::{
    COMMITMENT_RING_MODULUS, COMMITMENT_RING_PRIMITIVE_65536TH_ROOT, commit_digit_message,
    measurement_scale_configuration,
};
use super::limb_group_statement::{
    DigitAtomSource, LimbGroupContext, LimbGroupDigitAtomInput, verify_limb_group_digit_atom,
};
use super::negacyclic_transform::NegacyclicDomain;
use super::proof_field::{
    eight_limb_group_field_parameters, single_limb_field_parameters,
    sixteen_limb_group_field_parameters,
};
use super::witness_encoding::{ENCODED_DIGIT_COUNT, encode_signed_digits};
use crate::bgv::evaluator::engine::DevelopmentBgvKey;
use crate::bgv::evaluator::key_switch::{
    KEY_SWITCH_ERROR_DOMAIN, KEY_SWITCH_SAMPLE_DOMAIN, generate_galois_key,
};
use crate::bgv::evaluator::prg::DeterministicSampler;
use crate::bgv::parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE};

const GATE_LEVEL: usize = 15;
const GALOIS_ELEMENT: usize = 3;
const GATE_SEED: &str = "limb-group-atom-gate-benchmark-seed";

/// Operation-count model for one limb-group digit atom inside a Buckler-style
/// prover: committed polynomials per atom, forward/inverse transforms for
/// randomized encoding and commitment, quotient-phase transforms, and
/// opening-replay transforms.
const MODEL_COMMITTED_POLYNOMIALS_PER_ATOM: usize = 12;
const MODEL_TRANSFORMS_PER_POLYNOMIAL: usize = 4;
const MODEL_QUOTIENT_TRANSFORMS_PER_ATOM: usize = 8;
const MODEL_DIGIT_ATOMS_PER_KEY: usize = 16;
const MODEL_KEYS_PER_TRUSTEE: usize = 25;

fn milliseconds(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

#[test]
#[ignore = "full-ring gate benchmark; run explicitly with --ignored --nocapture"]
fn limb_group_atom_full_ring_gate_benchmark() {
    println!("== limb-group key-switch atom gate benchmark ==");
    println!(
        "ring degree {POLYNOMIAL_DEGREE}, level {GATE_LEVEL}, limb group {} primes",
        GATE_LEVEL + 1
    );

    let parameters = sixteen_limb_group_field_parameters();
    let domain_build_start = Instant::now();
    let domain =
        NegacyclicDomain::new(&parameters, POLYNOMIAL_DEGREE).expect("full-ring domain builds");
    println!(
        "sixteen-limb field domain build: {:.1} ms",
        milliseconds(domain_build_start.elapsed())
    );

    let forward_transform_ms = measure_transform(&parameters, &domain);
    println!(
        "sixteen-limb field ntt (32768, 13 limbs): {forward_transform_ms:.2} ms per transform"
    );

    let eight_parameters = eight_limb_group_field_parameters();
    let eight_domain = NegacyclicDomain::new(&eight_parameters, POLYNOMIAL_DEGREE)
        .expect("eight-limb domain builds");
    let eight_transform_ms = measure_transform(&eight_parameters, &eight_domain);
    println!("eight-limb field ntt (32768, 7 limbs): {eight_transform_ms:.2} ms per transform");

    let group_primes = &DATA_PRIMES[..=GATE_LEVEL];
    let group = LimbGroupContext::new(&parameters, group_primes).expect("limb group builds");

    let keygen_start = Instant::now();
    let key = DevelopmentBgvKey::generate("00112233445566778899aabbccddeeff")
        .expect("development key generates");
    let galois_key = generate_galois_key(&key, GALOIS_ELEMENT, GATE_LEVEL, GATE_SEED)
        .expect("level-15 galois key generates");
    println!(
        "kernel level-15 galois keygen (16 digits x 16 limbs): {:.0} ms",
        milliseconds(keygen_start.elapsed())
    );

    let key_switch_domain = format!("galois-{GALOIS_ELEMENT}");
    let rotated_secret = rotated_secret(key.secret(), GALOIS_ELEMENT);

    let mut derivation_total = Duration::ZERO;
    let mut verification_total = Duration::ZERO;
    let mut slowest_atom = Duration::ZERO;
    let mut maximum_carry = 0_u64;
    for (digit_index, component) in galois_key.components.iter().enumerate() {
        let component_b = component
            .component_b
            .as_ref()
            .expect("generated keys retain component b");
        let digit_bytes = (digit_index as u64).to_le_bytes();

        let derivation_start = Instant::now();
        let error = DeterministicSampler::new(
            KEY_SWITCH_ERROR_DOMAIN,
            &[
                key_switch_domain.as_bytes(),
                GATE_SEED.as_bytes(),
                &digit_bytes,
            ],
        )
        .centered_binomial_eta2(POLYNOMIAL_DEGREE);
        let public_sample_by_limb = group_primes
            .iter()
            .map(|modulus| {
                let modulus_bytes = modulus.to_le_bytes();
                DeterministicSampler::new(
                    KEY_SWITCH_SAMPLE_DOMAIN,
                    &[
                        key_switch_domain.as_bytes(),
                        GATE_SEED.as_bytes(),
                        &digit_bytes,
                        &modulus_bytes,
                    ],
                )
                .uniform_residues(*modulus, POLYNOMIAL_DEGREE)
            })
            .collect::<Vec<_>>();
        derivation_total += derivation_start.elapsed();

        let verification_start = Instant::now();
        let report = verify_limb_group_digit_atom(LimbGroupDigitAtomInput {
            group: &group,
            domain: &domain,
            diagonal_group_position: Some(digit_index),
            component_b_by_limb: component_b,
            public_sample_by_limb: &public_sample_by_limb,
            secret_coefficients: key.secret(),
            error_coefficients: &error,
            source: DigitAtomSource::DiagonalSignedPolynomial(&rotated_secret),
        })
        .expect("kernel level-15 digit material satisfies the limb-group atom");
        let atom_elapsed = verification_start.elapsed();
        verification_total += atom_elapsed;
        slowest_atom = slowest_atom.max(atom_elapsed);
        maximum_carry = maximum_carry.max(report.maximum_carry_magnitude);
    }
    let digit_count = galois_key.components.len();
    println!("all {digit_count} limb-group digit atoms verified against kernel keygen material");
    println!(
        "witness/sample re-derivation: {:.0} ms total ({:.0} ms per digit)",
        milliseconds(derivation_total),
        milliseconds(derivation_total) / digit_count as f64
    );
    let relation_check_ms = milliseconds(verification_total) / digit_count as f64;
    println!(
        "limb-group relation check: {:.0} ms per digit atom (slowest {:.0} ms), maximum carry magnitude {maximum_carry} (bound {})",
        relation_check_ms,
        milliseconds(slowest_atom),
        POLYNOMIAL_DEGREE + 1
    );

    let (encode_ms_per_polynomial, commit_ms_per_polynomial, retained_digit_bytes) =
        measure_encoding_and_commitment(&parameters, &group, &public_sample_limbs_for_encoding());

    println!("witness digit encoding: {encode_ms_per_polynomial:.0} ms per full-ring polynomial");
    println!("ajtai commitment fold: {commit_ms_per_polynomial:.0} ms per full-ring polynomial");
    println!(
        "retained digit material: {:.1} MiB per polynomial (streaming keeps one)",
        retained_digit_bytes as f64 / (1024.0 * 1024.0)
    );

    let per_atom_transform_ms = forward_transform_ms
        * (MODEL_COMMITTED_POLYNOMIALS_PER_ATOM * MODEL_TRANSFORMS_PER_POLYNOMIAL
            + MODEL_QUOTIENT_TRANSFORMS_PER_ATOM) as f64;
    let per_atom_encode_commit_ms = (encode_ms_per_polynomial + commit_ms_per_polynomial)
        * MODEL_COMMITTED_POLYNOMIALS_PER_ATOM as f64;
    let per_atom_ms = per_atom_transform_ms + per_atom_encode_commit_ms + relation_check_ms;
    let per_key_ms = per_atom_ms * MODEL_DIGIT_ATOMS_PER_KEY as f64;
    let per_trustee_minutes = per_key_ms * MODEL_KEYS_PER_TRUSTEE as f64 / 60_000.0;
    println!("== prover cost projection (single thread, operation-count model) ==");
    println!(
        "model: {MODEL_COMMITTED_POLYNOMIALS_PER_ATOM} committed polynomials per atom x {MODEL_TRANSFORMS_PER_POLYNOMIAL} transforms + {MODEL_QUOTIENT_TRANSFORMS_PER_ATOM} quotient transforms"
    );
    println!(
        "projected per-atom prove: {:.1} s (transforms {:.1} s, encode+commit {:.1} s, relation floor {:.1} s)",
        per_atom_ms / 1_000.0,
        per_atom_transform_ms / 1_000.0,
        per_atom_encode_commit_ms / 1_000.0,
        relation_check_ms / 1_000.0
    );
    println!(
        "projected per-key prove ({MODEL_DIGIT_ATOMS_PER_KEY} digit atoms): {:.1} min",
        per_key_ms / 60_000.0
    );
    println!(
        "projected per-trustee prove ({MODEL_KEYS_PER_TRUSTEE} keys): {per_trustee_minutes:.1} min"
    );
}

fn measure_transform<const LIMB_COUNT: usize>(
    parameters: &super::proof_field::ProofFieldParameters<LIMB_COUNT>,
    domain: &NegacyclicDomain<'_, LIMB_COUNT>,
) -> f64 {
    let mut values = deterministic_field_values(parameters, POLYNOMIAL_DEGREE, 0xbe7ac);
    domain.forward_in_place(&mut values);
    domain.inverse_in_place(&mut values);
    let repetitions = 6;
    let start = Instant::now();
    for _ in 0..repetitions {
        domain.forward_in_place(&mut values);
        domain.inverse_in_place(&mut values);
    }
    milliseconds(start.elapsed()) / (repetitions as f64 * 2.0)
}

fn deterministic_field_values<const LIMB_COUNT: usize>(
    parameters: &super::proof_field::ProofFieldParameters<LIMB_COUNT>,
    count: usize,
    seed: u64,
) -> Vec<[u64; LIMB_COUNT]> {
    let mut state = seed;
    (0..count)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            parameters.unsigned_word_to_element(state)
        })
        .collect()
}

fn rotated_secret(secret: &[i64], galois_element: usize) -> Vec<i64> {
    let two_n = 2 * POLYNOMIAL_DEGREE;
    let mut rotated = vec![0_i64; POLYNOMIAL_DEGREE];
    for (coefficient_index, value) in secret.iter().enumerate() {
        let exponent = (coefficient_index * galois_element) % two_n;
        if exponent < POLYNOMIAL_DEGREE {
            rotated[exponent] += value;
        } else {
            rotated[exponent - POLYNOMIAL_DEGREE] -= value;
        }
    }
    rotated
}

fn public_sample_limbs_for_encoding() -> Vec<Vec<u64>> {
    DATA_PRIMES[..=GATE_LEVEL]
        .iter()
        .map(|modulus| {
            let modulus_bytes = modulus.to_le_bytes();
            DeterministicSampler::new(
                KEY_SWITCH_SAMPLE_DOMAIN,
                &[b"encoding-material", &modulus_bytes[..]],
            )
            .uniform_residues(*modulus, POLYNOMIAL_DEGREE)
        })
        .collect()
}

/// Encodes and commits one full-ring recombined polynomial repeatedly and
/// returns (encode ms per polynomial, commit ms per polynomial, retained
/// digit bytes per polynomial).
fn measure_encoding_and_commitment<const LIMB_COUNT: usize>(
    parameters: &super::proof_field::ProofFieldParameters<LIMB_COUNT>,
    group: &LimbGroupContext<LIMB_COUNT>,
    sample_limbs: &[Vec<u64>],
) -> (f64, f64, usize) {
    let recombined = group
        .recombine_centered(parameters, sample_limbs, POLYNOMIAL_DEGREE)
        .expect("encoding material recombines");

    let encode_start = Instant::now();
    let mut digits = Vec::with_capacity(POLYNOMIAL_DEGREE * ENCODED_DIGIT_COUNT);
    for element in &recombined {
        let raw = parameters.to_raw_value(element);
        digits.extend_from_slice(&encode_signed_digits(parameters, &raw));
    }
    let encode_ms = milliseconds(encode_start.elapsed());
    let retained_digit_bytes = digits.len() * std::mem::size_of::<i32>();

    let commitment_parameters = single_limb_field_parameters(
        COMMITMENT_RING_MODULUS,
        COMMITMENT_RING_PRIMITIVE_65536TH_ROOT,
    );
    let configuration = measurement_scale_configuration();
    let commitment_domain =
        NegacyclicDomain::new(&commitment_parameters, configuration.ring_dimension)
            .expect("commitment domain builds");
    let commit_start = Instant::now();
    let commitment = commit_digit_message(
        &commitment_parameters,
        &commitment_domain,
        &configuration,
        0x5ea1ed,
        0,
        &digits,
    );
    let commit_ms = milliseconds(commit_start.elapsed());
    assert_eq!(commitment.len(), configuration.module_rank);

    (encode_ms, commit_ms, retained_digit_bytes)
}
