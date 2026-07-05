//! Ignored gate benchmark for the atom family backend: measures per-key
//! round-one prove/verify wall time and an estimated serialized proof size at
//! development-and-above ring degrees that fit the field's 65536 two-adic order
//! without column splitting (`N <= 8192`, since the coset is `8N`).
//!
//! Run with:
//! `cargo test -p sealed-lattice-kernel --release --lib
//!  family_backend::bench::round_one_key_prover_cost -- --ignored --nocapture`
//!
//! This is native development measurement only, at unsplit ring degrees. It is
//! not full-profile (`N = 32768`) evidence, not browser or WASM evidence, and
//! not supported-phone evidence. Full-profile sizing needs the column split
//! recorded in the family-implementation decision record.

use super::super::proof_field::sixteen_limb_group_field_parameters;
use super::key_proof::{
    DigitPublic, DigitWitness, KeyFriProof, KeyFriProofParameters, KeyPublic,
    prove_round_one_key_fri, verify_round_one_key_fri,
};

const LIMB_BYTES: usize = 13 * 8;
const DIGEST_BYTES: usize = 32;

// A rough serialized-size estimate for one key proof (the codec is a later
// milestone; this sums the field-element, digest, and salt bytes the proof
// carries).
fn estimate_proof_bytes(proof: &KeyFriProof<13>) -> usize {
    let mut bytes = 2 * DIGEST_BYTES;
    bytes += proof.fri.layer_roots.len() * DIGEST_BYTES;
    bytes += proof.fri.final_coefficients.len() * LIMB_BYTES;
    for answer in &proof.fri.query_answers {
        for layer in &answer.layers {
            bytes += 2 * LIMB_BYTES;
            bytes += layer.value_salt.len() + layer.sibling_salt.len();
            bytes += layer.opening.authentication_nodes.len() * DIGEST_BYTES;
        }
    }
    for opening in [&proof.base_opening, &proof.quotient_opening] {
        for row in &opening.rows {
            bytes += 8 + row.values.len() * LIMB_BYTES + row.salt.len();
        }
        bytes += opening.opening.authentication_nodes.len() * DIGEST_BYTES;
    }
    bytes
}

fn synthetic_key(
    ring_degree: usize,
    digit_count: usize,
) -> (Vec<i64>, Vec<DigitWitness>, KeyPublic<13>) {
    use super::super::negacyclic_transform::NegacyclicDomain;
    let parameters = sixteen_limb_group_field_parameters();
    let domain = NegacyclicDomain::new(&parameters, ring_degree).expect("domain");
    let secret: Vec<i64> = (0..ring_degree).map(|i| ((i * 7) % 3) as i64 - 1).collect();
    let secret_field: Vec<[u64; 13]> = secret
        .iter()
        .map(|v| parameters.signed_word_to_element(*v))
        .collect();
    let group_modulus = parameters.unsigned_word_to_element(1_000_003);
    let plaintext_modulus = parameters.unsigned_word_to_element(65_537);
    let mut digits = Vec::with_capacity(digit_count);
    let mut public_digits = Vec::with_capacity(digit_count);
    for digit_index in 0..digit_count {
        let error: Vec<i64> = (0..ring_degree)
            .map(|i| (((i + digit_index) * 5) % 5) as i64 - 2)
            .collect();
        let carry: Vec<i64> = (0..ring_degree)
            .map(|i| ((i + digit_index) % 3) as i64 - 1)
            .collect();
        let error_field: Vec<[u64; 13]> = error
            .iter()
            .map(|v| parameters.signed_word_to_element(*v))
            .collect();
        let carry_field: Vec<[u64; 13]> = carry
            .iter()
            .map(|v| parameters.signed_word_to_element(*v))
            .collect();
        let mut sample = Vec::with_capacity(ring_degree);
        let mut state = 0xa5_u64.wrapping_add(digit_index as u64 * 0x1000);
        for _ in 0..ring_degree {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            sample.push(parameters.unsigned_word_to_element(state));
        }
        let gadget_idempotent = parameters.unsigned_word_to_element(0x9e37 + digit_index as u64);
        let a_times_s = domain.negacyclic_product(&sample, &secret_field);
        let mut component_b = vec![parameters.zero(); ring_degree];
        for index in 0..ring_degree {
            let t_e = parameters.multiply(&plaintext_modulus, &error_field[index]);
            let g_s = parameters.multiply(&gadget_idempotent, &secret_field[index]);
            let q_c = parameters.multiply(&group_modulus, &carry_field[index]);
            let mut value = parameters.add(&t_e, &g_s);
            value = parameters.add(&value, &q_c);
            value = parameters.subtract(&value, &a_times_s[index]);
            component_b[index] = value;
        }
        digits.push(DigitWitness { error, carry });
        public_digits.push(DigitPublic {
            recombined_sample: sample,
            recombined_component_b: component_b,
            gadget_idempotent,
        });
    }
    (
        secret,
        digits,
        KeyPublic {
            digits: public_digits,
            group_modulus,
            plaintext_modulus,
        },
    )
}

#[test]
#[ignore = "prover-cost benchmark; run explicitly with --ignored --nocapture"]
fn round_one_key_prover_cost() {
    use std::time::Instant;
    let parameters = sixteen_limb_group_field_parameters();
    // Ring degrees that fit the 65536 two-adic order unsplit (coset = 8N).
    // A level-15 key has 16 digits; benchmark that digit count.
    // A level-15 key has 16 digits. The ZK mask degree must stay below m/2 so
    // the masked quotients (degree m + 2*mask) fit the degree bound 2m; it also
    // needs to cover the opened evaluations (2 per query), so it scales with the
    // ring degree. m/4 satisfies both for these ring degrees.
    // 80 queries at rate 1/4 gives about 128 conditional classical bits under
    // the CS25 accounting the setup families use (SEC-004), not the 128-query
    // (~256-bit) over-provisioning of the first benchmark.
    // The first profile is N = 32768; with the two-adic ceiling raised to 2^20
    // it runs unsplit (coset 2^18), so the column count does not double.
    let digit_count = 16;
    let query_count = 80;
    println!("round-one key ({digit_count} digits, {query_count} queries, mask degree N/4):");
    for ring_degree in [4096_usize, 8192] {
        let proof_parameters = KeyFriProofParameters {
            query_count,
            mask_degree: ring_degree / 4,
        };
        let (secret, digits, public) = synthetic_key(ring_degree, digit_count);
        let mut salt_seed = 0x1234;
        let prove_start = Instant::now();
        let proof = prove_round_one_key_fri(
            &parameters,
            ring_degree,
            &public,
            &secret,
            &digits,
            &proof_parameters,
            &mut salt_seed,
        )
        .expect("prove");
        let prove_ms = prove_start.elapsed().as_secs_f64() * 1000.0;
        let verify_start = Instant::now();
        let accepted =
            verify_round_one_key_fri(&parameters, ring_degree, &public, &proof, &proof_parameters)
                .expect("verify");
        let verify_ms = verify_start.elapsed().as_secs_f64() * 1000.0;
        assert!(accepted, "benchmark proof must verify");
        let proof_kib = estimate_proof_bytes(&proof) as f64 / 1024.0;
        println!(
            "  N = {ring_degree:5}: prove {prove_ms:9.1} ms, verify {verify_ms:8.1} ms, proof ~{proof_kib:8.1} KiB"
        );
    }
}
