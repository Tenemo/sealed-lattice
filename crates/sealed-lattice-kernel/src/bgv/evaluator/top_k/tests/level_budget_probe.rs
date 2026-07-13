// Ignored exact-noise probe at the comparison handoff, rank lookup, and target.
// It uses the production multiplication operations and a faithful rank-lookup
// replica whose level-floor zero matches production.
//
// Run through the guarded focused Rust runner:
//   pnpm run test:rust:kernel:accepted-setup -- level_budget_probe

use num_bigint::BigInt;
use num_traits::{Signed, Zero};

use super::super::{
    DIRECT_COMPARISON_OUTPUT_LEVEL, RANK_LOOKUP_BABY_STEP_COUNT, evaluate_rank_lookup,
};
use super::*;
use crate::bgv::evaluator::circuit::{
    broadcast_constant_coefficients, modulus_switch_to, multiply,
    multiply_without_immediate_modulus_switch, normalize_scaling,
};
use crate::bgv::evaluator::engine::{
    Ciphertext, DevelopmentBgvKey, add_plaintext_coefficients, ciphertext_add, negacyclic_mul,
    scalar_mul, signed_residue,
};
use crate::bgv::modular_arithmetic::inverse_mod;
use crate::bgv::parameters::DATA_PRIMES;

// The comparison at the full m = 20 option count is the slow part of the pipeline
// (about 190 pair rotations). The lookup, which the level budget changes, is
// always degree 19 regardless: the probe evaluates the degree-19 lookup on the
// real level-6 comparison handoff, so a smaller option count gives a faithful
// lookup input whose noise is within a few bits of the m = 20 handoff (the
// pair-count term is additive, about log2(190 / pair_count)). Raise to 20 for the
// exact handoff figure.
const RANK_LOOKUP_DEGREE_OPTION_COUNT: usize = 20;
const DEVELOPMENT_SEED: &str = "level-budget-probe-seed";

// True residual noise of a ciphertext under the development key, in bits
// (ceil log2 of the infinity norm of the noise polynomial). Decryption computes
// the accumulator sum_k c_k * s^k per limb, CRT-combines and centers into
// (-q/2, q/2]; the message is the centered value reduced mod p, and the noise is
// e = (v - centered_mod_p(v)) / p. Decoding is correct iff max|e| < q / (2p).
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

    let mut accumulator: Vec<Vec<u64>> = ciphertext.components[0].clone();
    let mut secret_power = secret_residues.clone();
    for (component_index, component) in ciphertext.components.iter().enumerate().skip(1) {
        if component_index > 1 {
            secret_power = secret_power
                .iter()
                .zip(secret_residues.iter())
                .zip(primes.iter())
                .map(|((power_limb, secret_limb), modulus)| {
                    negacyclic_mul(power_limb, secret_limb, *modulus).expect("secret power")
                })
                .collect();
        }
        for (limb_index, modulus) in primes.iter().enumerate() {
            let term = negacyclic_mul(&component[limb_index], &secret_power[limb_index], *modulus)
                .expect("component times secret power");
            for (accumulated, added) in accumulator[limb_index].iter_mut().zip(term.iter()) {
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

    let mut max_noise = BigInt::zero();
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
        let noise = (&value - &message_residue) / &plaintext_modulus;
        let noise_magnitude = noise.abs();
        if noise_magnitude > max_noise {
            max_noise = noise_magnitude;
        }
    }

    if max_noise.is_zero() {
        0.0
    } else {
        max_noise.bits() as f64
    }
}

// The decode margin log2(q / (2p)) in bits for a ciphertext's active basis.
fn decode_margin_bits(ciphertext: &Ciphertext) -> f64 {
    let modulus: BigInt = ciphertext
        .primes()
        .iter()
        .map(|prime| BigInt::from(*prime))
        .product();

    modulus.bits() as f64 - 1.0 - (PLAINTEXT_MODULUS as f64).log2()
}

// Faithful replica of circuit.rs build_power_table, with a level floor: a multiply
// whose rescaled output would fall below `level_floor` is deferred (kept at its
// input level, paying un-rescaled product noise) instead of rescaled. A floor of 0
// never defers and reproduces build_power_table exactly.
fn build_power_table_with_level_floor(
    context: &EvaluatorContext,
    base: &Ciphertext,
    highest_power: usize,
    level_floor: usize,
    key: &DevelopmentBgvKey,
    trace_label: &str,
) -> Vec<Option<Ciphertext>> {
    let mut powers: Vec<Option<Ciphertext>> = vec![None; highest_power + 1];
    if highest_power >= 1 {
        powers[1] = Some(base.clone());
    }
    for power in 2..=highest_power {
        let low = power / 2;
        let high = power - low;
        let low_power = powers[low].clone().expect("low power built");
        let high_power = powers[high].clone().expect("high power built");
        let target_level = low_power.level.min(high_power.level);
        let deferred = target_level.saturating_sub(1) < level_floor;
        let product = if deferred {
            multiply_without_immediate_modulus_switch(context, &low_power, &high_power)
                .expect("deferred multiply")
        } else {
            multiply(context, &low_power, &high_power).expect("multiply")
        };
        if !trace_label.is_empty() {
            println!(
                "    {trace_label} x^{power}{}: level {}, noise {:.1} bits",
                if deferred { " [deferred]" } else { "" },
                product.level,
                ciphertext_noise_bits(key, &product)
            );
        }
        powers[power] = Some(product);
    }

    powers
}

// Faithful replica of circuit.rs linear_combination_from_powers (level-preserving).
fn linear_combination_from_powers(
    reference: &Ciphertext,
    powers: &[Option<Ciphertext>],
    coefficients: &[u64],
) -> Ciphertext {
    let target_level = coefficients
        .iter()
        .enumerate()
        .skip(1)
        .filter(|(_, coefficient)| **coefficient != 0)
        .filter_map(|(power, _)| powers[power].as_ref().map(|ciphertext| ciphertext.level))
        .min();
    let anchor_level = target_level.unwrap_or(reference.level);
    let anchor =
        normalize_scaling(&modulus_switch_to(reference, anchor_level).expect("anchor level"))
            .expect("anchor scaling");
    let mut result = add_plaintext_coefficients(
        &scalar_mul(&anchor, 0).expect("zero anchor"),
        &broadcast_constant_coefficients(coefficients[0]),
    )
    .expect("constant term");
    for (power, coefficient) in coefficients.iter().enumerate().skip(1) {
        if *coefficient == 0 {
            continue;
        }
        let power_ciphertext = powers[power].as_ref().expect("power present");
        let leveled = normalize_scaling(
            &modulus_switch_to(power_ciphertext, anchor_level).expect("power to anchor level"),
        )
        .expect("power scaling");
        let scaled = scalar_mul(
            &leveled,
            i64::try_from(*coefficient).expect("coefficient fits i64"),
        )
        .expect("scale power");
        result = ciphertext_add(&result, &scaled).expect("accumulate term");
    }

    result
}

// Faithful replica of circuit.rs sum_ciphertexts_at_common_level.
fn sum_ciphertexts_at_common_level(ciphertexts: &[Ciphertext]) -> Ciphertext {
    let target_level = ciphertexts
        .iter()
        .map(|ciphertext| ciphertext.level)
        .min()
        .expect("non-empty term set");
    let mut accumulator =
        normalize_scaling(&modulus_switch_to(&ciphertexts[0], target_level).expect("term level"))
            .expect("term scaling");
    for ciphertext in &ciphertexts[1..] {
        let aligned =
            normalize_scaling(&modulus_switch_to(ciphertext, target_level).expect("term level"))
                .expect("term scaling");
        accumulator = ciphertext_add(&accumulator, &aligned).expect("sum terms");
    }

    accumulator
}

// Faithful replica of circuit.rs evaluate_polynomial_paterson_stockmeyer_with_baby_step_count
// (defer_terminal_modulus_switch = true), with the added power-table level floor.
// A floor of 0 reproduces the production rank lookup exactly.
#[allow(clippy::too_many_arguments)]
fn evaluate_lookup_with_level_floor(
    context: &EvaluatorContext,
    input: &Ciphertext,
    coefficients: &[u64],
    baby_step_count: usize,
    level_floor: usize,
    key: &DevelopmentBgvKey,
    trace: bool,
    defer_terminal: bool,
) -> Ciphertext {
    let degree = coefficients.len() - 1;
    assert!(
        degree >= baby_step_count,
        "probe lookup expects a full block structure"
    );
    let block_count = coefficients.len().div_ceil(baby_step_count);
    let working_input =
        modulus_switch_to(input, context.working_level()).expect("input to working level");

    let baby_powers = build_power_table_with_level_floor(
        context,
        &working_input,
        baby_step_count,
        level_floor,
        key,
        if trace { "baby" } else { "" },
    );
    let giant_base = baby_powers[baby_step_count]
        .as_ref()
        .expect("giant base built")
        .clone();
    let giant_powers = build_power_table_with_level_floor(
        context,
        &giant_base,
        block_count.saturating_sub(1),
        level_floor,
        key,
        if trace { "giant" } else { "" },
    );

    let mut terms = Vec::new();
    for (block_index, giant_power) in giant_powers.iter().enumerate().take(block_count) {
        let start = block_index * baby_step_count;
        let end = coefficients.len().min(start + baby_step_count);
        let block_coefficients = &coefficients[start..end];
        if block_coefficients
            .iter()
            .all(|coefficient| *coefficient == 0)
        {
            continue;
        }
        let block_value =
            linear_combination_from_powers(&working_input, &baby_powers, block_coefficients);
        if block_index == 0 {
            terms.push(block_value);
            continue;
        }
        let giant_power = giant_power.as_ref().expect("giant power present");
        if block_coefficients[1..]
            .iter()
            .all(|coefficient| *coefficient == 0)
        {
            terms.push(
                scalar_mul(
                    giant_power,
                    i64::try_from(block_coefficients[0]).expect("coefficient fits i64"),
                )
                .expect("scalar block"),
            );
        } else {
            // Production defers the terminal block products (defer_terminal = true);
            // defer_terminal = false rescales them instead (one extra level, lower noise).
            let product = if defer_terminal {
                multiply_without_immediate_modulus_switch(context, &block_value, giant_power)
                    .expect("deferred block product")
            } else {
                multiply(context, &block_value, giant_power).expect("rescaled block product")
            };
            if trace {
                println!(
                    "    block {block_index} product [{}]: level {}, noise {:.1} bits",
                    if defer_terminal {
                        "deferred"
                    } else {
                        "rescaled"
                    },
                    product.level,
                    ciphertext_noise_bits(key, &product)
                );
            }
            terms.push(product);
        }
    }

    sum_ciphertexts_at_common_level(&terms)
}

// A representative aggregate-score vector for m = 20 with n = 10 ballots:
// distinct values across the bounded aggregate domain [10, 100].
fn clean_level_six_rank_input(_context: &EvaluatorContext, key: &DevelopmentBgvKey) -> Ciphertext {
    let mut slots = vec![0u64; RANK_LOOKUP_DEGREE_OPTION_COUNT];
    for (rank, slot) in slots.iter_mut().enumerate() {
        *slot = rank as u64;
    }
    let fresh = key
        .encrypt_slots(&slots, "level-budget-probe-clean-ranks")
        .expect("clean ranks ciphertext");
    let at_level_six = modulus_switch_to(&fresh, DIRECT_COMPARISON_OUTPUT_LEVEL)
        .expect("clean ranks to level six");

    normalize_scaling(&at_level_six).expect("normalize clean input")
}

#[test]
#[ignore = "development-only noise probe; run via the guarded accepted-setup runner"]
fn level_budget_rank_lookup_noise_probe() {
    let context = EvaluatorContext::new(DEVELOPMENT_SEED, SELECTED_EVALUATOR_WORKING_LEVEL)
        .expect("evaluator context");
    let key = context.key();
    let selection_threshold = 10usize;

    println!("\n=== target level budget: rank-lookup noise probe (clean level-6 input) ===");
    println!(
        "ring N = {POLYNOMIAL_DEGREE}, data primes = {}, working level = {}, lookup degree = {}, k = {selection_threshold}",
        DATA_PRIMES.len(),
        SELECTED_EVALUATOR_WORKING_LEVEL,
        RANK_LOOKUP_DEGREE_OPTION_COUNT - 1,
    );

    // --- decode margins per level (from the actual primes) ---
    println!("\n-- decode margin q/(2p) per exit level --");
    for level in [1usize, 3, 4, 6] {
        let probe = Ciphertext {
            components: vec![vec![vec![0u64; POLYNOMIAL_DEGREE]; level + 1]; 2],
            level,
            decrypt_scaling: 1,
        };
        println!(
            "  level {level} ({} limbs): margin {:.1} bits",
            level + 1,
            decode_margin_bits(&probe)
        );
    }

    // --- fresh full-level noise (is working level 16 free?) ---
    let fresh_full = key
        .encrypt_slots(&[1, 2, 3], "level-budget-probe-fresh")
        .expect("fresh ciphertext");
    println!(
        "\n-- fresh ciphertext: level {}, noise {:.1} bits, margin {:.1} bits (level 16 free if noise << margin) --",
        fresh_full.level,
        ciphertext_noise_bits(key, &fresh_full),
        decode_margin_bits(&fresh_full)
    );

    // --- clean level-6 lookup input (isolates the lookup from the comparison) ---
    let input = clean_level_six_rank_input(&context, key);
    assert_eq!(input.level, 6, "clean lookup input must be at level 6");
    let input_slots = key.decrypt_to_slots(&input).expect("input slots");
    assert_eq!(
        &input_slots[..RANK_LOOKUP_DEGREE_OPTION_COUNT],
        (0..RANK_LOOKUP_DEGREE_OPTION_COUNT as u64)
            .collect::<Vec<_>>()
            .as_slice(),
        "clean input must hold ranks 0..19 in the first slots"
    );
    println!(
        "\n-- clean level-6 lookup input: level {}, noise {:.1} bits, margin {:.1} bits --",
        input.level,
        ciphertext_noise_bits(key, &input),
        decode_margin_bits(&input)
    );

    let indicator_values = (0..RANK_LOOKUP_DEGREE_OPTION_COUNT)
        .map(|rank| u64::from(rank < selection_threshold))
        .collect::<Vec<_>>();
    let lookup_coefficients = interpolate_coefficients(&indicator_values).expect("interpolate");

    // --- baseline: production rank lookup (terminal level 1) ---
    println!("\n-- production rank lookup (current, level-floor 0) --");
    let production_terminal =
        evaluate_rank_lookup(&context, &input, &indicator_values).expect("production lookup");
    let production_noise = ciphertext_noise_bits(key, &production_terminal);
    let production_margin = decode_margin_bits(&production_terminal);
    println!(
        "production terminal: level {}, noise {:.1} bits, margin {:.1} bits, headroom {:.1} bits",
        production_terminal.level,
        production_noise,
        production_margin,
        production_margin - production_noise,
    );

    // --- faithfulness: replica at level-floor 0 must match production exactly ---
    let replica_current = evaluate_lookup_with_level_floor(
        &context,
        &input,
        &lookup_coefficients,
        RANK_LOOKUP_BABY_STEP_COUNT,
        0,
        key,
        false,
        true,
    );
    let production_slots = key
        .decrypt_to_slots(&production_terminal)
        .expect("production slots");
    let replica_slots = key
        .decrypt_to_slots(&replica_current)
        .expect("replica slots");
    assert_eq!(
        production_slots, replica_slots,
        "level-floor-0 replica must decrypt identically to the production lookup"
    );
    assert_eq!(
        production_terminal.level, replica_current.level,
        "level-floor-0 replica must exit at the production level"
    );
    // correctness: indicator flips at k on the clean ranks 0..19.
    for (rank, slot) in production_slots
        .iter()
        .enumerate()
        .take(RANK_LOOKUP_DEGREE_OPTION_COUNT)
    {
        assert_eq!(
            *slot,
            u64::from(rank < selection_threshold),
            "indicator at rank {rank}"
        );
    }
    println!(
        "faithfulness + correctness passed: replica(floor 0) == production, indicator flips at k = {selection_threshold}"
    );

    // --- deferred policies: measure (exit level, terminal noise, headroom) ---
    for level_floor in [3usize, 4] {
        println!("\n-- deferred rescale policy: power-table level floor {level_floor} --");
        let terminal = evaluate_lookup_with_level_floor(
            &context,
            &input,
            &lookup_coefficients,
            RANK_LOOKUP_BABY_STEP_COUNT,
            level_floor,
            key,
            true,
            true,
        );
        let terminal_noise = ciphertext_noise_bits(key, &terminal);
        let margin = decode_margin_bits(&terminal);
        let terminal_slots = key.decrypt_to_slots(&terminal).expect("terminal slots");
        let decrypts_correctly = (0..RANK_LOOKUP_DEGREE_OPTION_COUNT)
            .all(|rank| terminal_slots[rank] == u64::from(rank < selection_threshold));
        println!(
            "  TERMINAL: exit level {}, noise {:.1} bits, margin {:.1} bits, headroom {:.1} bits, decrypts correctly = {decrypts_correctly}",
            terminal.level,
            terminal_noise,
            margin,
            margin - terminal_noise,
        );
    }

    // --- K = full sparse target (no lookup): noise-only, stays at level 6 ---
    let rank_evaluation = super::super::PackedRankEvaluation {
        packed_ranks: input.clone(),
    };
    let full_target = project_packed_sparse_target_from_rank_evaluation(
        &context,
        &rank_evaluation,
        RANK_LOOKUP_DEGREE_OPTION_COUNT,
        RANK_LOOKUP_DEGREE_OPTION_COUNT,
    )
    .expect("full target");
    println!(
        "\n-- K_top = m sparse target (no lookup): target_id level {}, noise {:.1} bits; target_order level {}, noise {:.1} bits --",
        full_target.target_id.level,
        ciphertext_noise_bits(key, &full_target.target_id),
        full_target.target_order.level,
        ciphertext_noise_bits(key, &full_target.target_order),
    );

    println!("\n=== rank-lookup probe complete ===\n");
}

fn clean_rank_input_at_level(
    _context: &EvaluatorContext,
    key: &DevelopmentBgvKey,
    level: usize,
) -> Ciphertext {
    let mut slots = vec![0u64; RANK_LOOKUP_DEGREE_OPTION_COUNT];
    for (rank, slot) in slots.iter_mut().enumerate() {
        *slot = rank as u64;
    }
    let fresh = key
        .encrypt_slots(&slots, "level-budget-probe-clean-ranks-at-level")
        .expect("clean ranks ciphertext");
    let at_level = modulus_switch_to(&fresh, level).expect("clean ranks to level");

    normalize_scaling(&at_level).expect("normalize clean input")
}

// Step 4: natural (no-deferral) lookup exit and smudging headroom as a function of the
// handoff level. Degree-19 has multiplicative depth 5, so the natural exit is
// handoff - 5 at the natural B_eval; raising the handoff is the only lever that raises
// the exit level without paying deferral noise.
#[test]
#[ignore = "development-only natural-exit probe; run via the guarded accepted-setup runner"]
fn natural_exit_headroom_by_handoff_level() {
    let context = EvaluatorContext::new(DEVELOPMENT_SEED, SELECTED_EVALUATOR_WORKING_LEVEL)
        .expect("evaluator context");
    let key = context.key();
    let selection_threshold = 10usize;
    let indicator_values = (0..RANK_LOOKUP_DEGREE_OPTION_COUNT)
        .map(|rank| u64::from(rank < selection_threshold))
        .collect::<Vec<_>>();

    println!("\n=== natural-exit headroom vs handoff level (no deferral, natural B_eval) ===");
    println!(
        "degree-19 depth 5 -> natural exit = handoff - 5; smudging headroom = margin(exit) - B_eval."
    );
    for handoff_level in [6usize, 7, 8, 9] {
        let input = clean_rank_input_at_level(&context, key, handoff_level);
        assert_eq!(input.level, handoff_level, "clean input level");
        let terminal = evaluate_rank_lookup(&context, &input, &indicator_values).expect("lookup");
        let b_eval = ciphertext_noise_bits(key, &terminal);
        let margin = decode_margin_bits(&terminal);
        let terminal_slots = key.decrypt_to_slots(&terminal).expect("terminal slots");
        let correct = (0..RANK_LOOKUP_DEGREE_OPTION_COUNT)
            .all(|rank| terminal_slots[rank] == u64::from(rank < selection_threshold));
        println!(
            "  handoff {handoff_level} -> exit level {}, B_eval {:.1} bits, margin {:.1} bits, headroom {:.1} bits, correct = {correct}",
            terminal.level,
            b_eval,
            margin,
            margin - b_eval,
        );
    }
    println!("\n=== natural-exit probe complete ===\n");
}

fn gcd_i128(mut a: i128, mut b: i128) -> i128 {
    a = a.abs();
    b = b.abs();
    while b != 0 {
        let remainder = a % b;
        a = b;
        b = remainder;
    }
    a
}

fn lcm_i128(a: i128, b: i128) -> i128 {
    if a == 0 || b == 0 {
        0
    } else {
        (a / gcd_i128(a, b)) * b
    }
}

// Step 3: exact worst-case L1 norm of the denominator-cleared Lagrange recombination
// coefficients over all q_dec-of-n quorums (the KLLPS26 C4 lever). Trustee points are
// {1..n}; the Lagrange basis is evaluated at 0 (the secret); each quorum is cleared by
// the minimal integer factor (lcm of the reduced denominators). The worst-case L1 sets
// the C4 smudging need ~ lambda + log2(N) + log2(L1) + log2(t).
#[test]
#[ignore = "development-only Lagrange probe; run via the guarded accepted-setup runner"]
fn lagrange_cleared_l1_worst_case() {
    let participant_count = 10i128;
    let quorum_size = 4usize;
    let points: Vec<i128> = (1..=participant_count).collect();

    let lagrange_coefficient_at_zero = |quorum: &[i128], selected: i128| -> (i128, i128) {
        let mut numerator = 1i128;
        let mut denominator = 1i128;
        for &other in quorum {
            if other == selected {
                continue;
            }
            numerator *= -other; // (0 - other)
            denominator *= selected - other; // (selected - other)
        }
        let divisor = gcd_i128(numerator, denominator);
        let mut reduced_numerator = numerator / divisor;
        let mut reduced_denominator = denominator / divisor;
        if reduced_denominator < 0 {
            reduced_numerator = -reduced_numerator;
            reduced_denominator = -reduced_denominator;
        }
        (reduced_numerator, reduced_denominator)
    };

    let cleared_l1 = |quorum: &[i128]| -> (i128, i128, Vec<i128>) {
        let fractions: Vec<(i128, i128)> = quorum
            .iter()
            .map(|&selected| lagrange_coefficient_at_zero(quorum, selected))
            .collect();
        let clearing_factor = fractions
            .iter()
            .fold(1i128, |accumulator, &(_, denominator)| {
                lcm_i128(accumulator, denominator)
            });
        let cleared: Vec<i128> = fractions
            .iter()
            .map(|&(numerator, denominator)| numerator * (clearing_factor / denominator))
            .collect();
        let l1 = cleared.iter().map(|coefficient| coefficient.abs()).sum();
        (l1, clearing_factor, cleared)
    };

    println!(
        "\n=== worst-case cleared-Lagrange L1 over all q_dec-of-n quorums (n={participant_count}, t={quorum_size}) ==="
    );
    for example in [[7i128, 8, 9, 10], [1, 5, 9, 10]] {
        let (l1, clearing, cleared) = cleared_l1(&example);
        println!("  quorum {example:?}: clearing {clearing}, cleared {cleared:?}, L1 = {l1}");
    }

    let mut worst_l1 = 0i128;
    let mut worst_quorum = Vec::new();
    let mut worst_cleared = Vec::new();
    let mut quorum_count = 0usize;
    for a in 0..points.len() {
        for b in (a + 1)..points.len() {
            for c in (b + 1)..points.len() {
                for d in (c + 1)..points.len() {
                    let quorum = [points[a], points[b], points[c], points[d]];
                    let (l1, _clearing, cleared) = cleared_l1(&quorum);
                    quorum_count += 1;
                    if l1 > worst_l1 {
                        worst_l1 = l1;
                        worst_quorum = quorum.to_vec();
                        worst_cleared = cleared;
                    }
                }
            }
        }
    }
    assert_eq!(quorum_count, 210, "expected C(10,4) = 210 quorums");
    let l1_bits = (worst_l1 as f64).log2();
    println!(
        "\n  WORST L1 over {quorum_count} quorums = {worst_l1} (log2 = {l1_bits:.2}) at quorum {worst_quorum:?}, cleared {worst_cleared:?}"
    );
    println!(
        "  => C4 need ~ lambda + log2(N) + log2(L1) + log2(t) = lambda + {:.2} + {l1_bits:.2} + {:.2} = lambda + {:.2} bits",
        (POLYNOMIAL_DEGREE as f64).log2(),
        (quorum_size as f64).log2(),
        (POLYNOMIAL_DEGREE as f64).log2() + l1_bits + (quorum_size as f64).log2(),
    );
    println!("\n=== L1 enumeration complete ===\n");
}

#[test]
#[ignore = "development-only rank-lookup probe; run via the guarded accepted-setup runner"]
fn rank_lookup_terminal_by_k() {
    let context = EvaluatorContext::new(DEVELOPMENT_SEED, SELECTED_EVALUATOR_WORKING_LEVEL)
        .expect("evaluator context");
    let key = context.key();
    let input = clean_level_six_rank_input(&context, key);
    assert_eq!(input.level, 6, "clean lookup input must be at level 6");
    println!("\n== rank-lookup terminal per K (clean level-6 input, degree-19, baby-step 5) ==");
    for k in [1usize, 10, 19] {
        let indicator = (0..RANK_LOOKUP_DEGREE_OPTION_COUNT)
            .map(|rank| u64::from(rank < k))
            .collect::<Vec<_>>();
        let terminal = evaluate_rank_lookup(&context, &input, &indicator).expect("lookup");
        let b_eval = ciphertext_noise_bits(key, &terminal);
        let margin = decode_margin_bits(&terminal);
        let slots = key.decrypt_to_slots(&terminal).expect("terminal slots");
        let correct =
            (0..RANK_LOOKUP_DEGREE_OPTION_COUNT).all(|rank| slots[rank] == u64::from(rank < k));
        println!(
            "  K={k}: exit level {}, B_eval {:.1} bits, margin {:.1} bits, headroom {:.1} bits, correct={correct}",
            terminal.level,
            b_eval,
            margin,
            margin - b_eval,
        );
    }
    println!("  K=20: no lookup (full-ranking branch) -> target stays at level 6.");
    println!("== per-K rank-lookup complete ==\n");
}
