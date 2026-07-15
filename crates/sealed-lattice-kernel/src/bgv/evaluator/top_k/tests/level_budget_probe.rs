// Manual measurement of the production rank-evaluation path. Run through the
// guarded focused Rust measurement lane; it is not part of routine verification.

use num_bigint::BigInt;
use num_traits::{Signed, Zero};

use super::*;
use crate::bgv::{
    evaluator::{
        circuit::modulus_switch_to,
        engine::{Ciphertext, DevelopmentBgvKey, negacyclic_mul, signed_residue},
    },
    modular_arithmetic::{add_mod, inverse_mod},
    parameters::{PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE},
};

fn ciphertext_noise_bits(key: &DevelopmentBgvKey, ciphertext: &Ciphertext) -> f64 {
    let primes = ciphertext.primes();
    let secret_residues: Vec<Vec<u64>> = primes
        .iter()
        .map(|modulus| {
            key.secret()
                .iter()
                .map(|coefficient| signed_residue(*coefficient, *modulus))
                .collect()
        })
        .collect();
    let mut accumulator = ciphertext.components[0].clone();
    let mut secret_power = secret_residues.clone();
    for (component_index, component) in ciphertext.components.iter().enumerate().skip(1) {
        if component_index > 1 {
            secret_power = secret_power
                .iter()
                .zip(&secret_residues)
                .zip(primes)
                .map(|((power_limb, secret_limb), modulus)| {
                    negacyclic_mul(power_limb, secret_limb, *modulus).expect("secret power")
                })
                .collect();
        }
        for (limb_index, modulus) in primes.iter().enumerate() {
            let term = negacyclic_mul(&component[limb_index], &secret_power[limb_index], *modulus)
                .expect("component times secret power");
            for (accumulated, added) in accumulator[limb_index].iter_mut().zip(&term) {
                *accumulated = add_mod(*accumulated, *added, *modulus).expect("accumulate");
            }
        }
    }

    let modulus: BigInt = primes.iter().map(|prime| BigInt::from(*prime)).product();
    let half_modulus = &modulus / 2;
    let crt_factors: Vec<BigInt> = primes
        .iter()
        .map(|prime| {
            let prime_big = BigInt::from(*prime);
            let cofactor = &modulus / &prime_big;
            let cofactor_residue = num_traits::ToPrimitive::to_u64(&(&cofactor % &prime_big))
                .expect("cofactor residue fits u64");
            let inverse = inverse_mod(cofactor_residue, *prime).expect("cofactor invertible");
            (&cofactor * BigInt::from(inverse)) % &modulus
        })
        .collect();
    let plaintext_modulus = BigInt::from(PLAINTEXT_MODULUS);
    let half_plaintext_modulus = &plaintext_modulus / 2;
    let mut maximum_noise = BigInt::zero();
    for coefficient_index in 0..POLYNOMIAL_DEGREE {
        let mut value = BigInt::zero();
        for (limb_index, factor) in crt_factors.iter().enumerate() {
            value += BigInt::from(accumulator[limb_index][coefficient_index]) * factor;
        }
        value %= &modulus;
        if value > half_modulus {
            value -= &modulus;
        }
        let mut message_residue = &value % &plaintext_modulus;
        if message_residue.is_negative() {
            message_residue += &plaintext_modulus;
        }
        if message_residue > half_plaintext_modulus {
            message_residue -= &plaintext_modulus;
        }
        let noise_magnitude = ((&value - &message_residue) / &plaintext_modulus).abs();
        maximum_noise = maximum_noise.max(noise_magnitude);
    }

    if maximum_noise.is_zero() {
        0.0
    } else {
        maximum_noise.bits() as f64
    }
}

fn decode_margin_bits(ciphertext: &Ciphertext) -> f64 {
    let modulus: BigInt = ciphertext
        .primes()
        .iter()
        .map(|prime| BigInt::from(*prime))
        .product();
    modulus.bits() as f64 - 1.0 - (PLAINTEXT_MODULUS as f64).log2()
}

#[test]
#[ignore = "manual production evaluator measurement; run through the guarded Rust measurement lane"]
fn production_rank_lookup_level_budget_measurement() {
    let context = EvaluatorContext::new(
        "production-rank-lookup-level-budget",
        SELECTED_EVALUATOR_WORKING_LEVEL,
    )
    .expect("evaluator context");
    let scores = [0_u64, 2, 2];
    let encrypted_scores = context
        .key()
        .encrypt_slots(&scores, "production-rank-lookup-level-budget-scores")
        .expect("encrypted scores");
    let working_scores = modulus_switch_to(&encrypted_scores, context.working_level())
        .expect("working-level scores");
    let packed_scores =
        pack_direct_score_slots(&context, &working_scores, scores.len()).expect("packed scores");
    let evaluated = evaluate_packed_rank_evaluation_from_packed_scores_with_batched_pairs(
        &context,
        &packed_scores,
        scores.len(),
        2,
    )
    .expect("production rank evaluation");
    let decrypted = context
        .key()
        .decrypt_to_slots(&evaluated.packed_ranks)
        .expect("decrypted ranks");
    assert_eq!(&decrypted[..scores.len()], &[2, 0, 1]);

    let noise_bits = ciphertext_noise_bits(context.key(), &evaluated.packed_ranks);
    let margin_bits = decode_margin_bits(&evaluated.packed_ranks);
    let headroom_bits = margin_bits - noise_bits;
    println!(
        "production rank lookup: level={}, noise_bits={noise_bits:.1}, margin_bits={margin_bits:.1}, headroom_bits={headroom_bits:.1}",
        evaluated.packed_ranks.level,
    );
    assert!(
        headroom_bits > 0.0,
        "the measured ciphertext must remain decryptable"
    );
}
