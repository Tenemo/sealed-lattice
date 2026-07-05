use super::*;

// ---------------------------------------------------------------------------
// Fix-decision measurements for the broken D=90 handoff: (1) per-stage real
// comparison-input noise through a line-faithful replica of the packed_rank
// input construction, (2) the D=90 input-noise ceiling refined by injection at
// eval start levels 13/14/15 (start 14 = today; start 15 = the working-16
// branch; start 13 = the add-a-cleaning-switch-at-working-15 branch), and
// (3) the one- and two-switch cleaning floors on the real accumulated input.
// The refresh position (measurement 4) is a code fact: packed_rank.rs applies
// its single modulus switch AFTER every noise-adding packing step and
// immediately BEFORE the comparison, so repositioning it is not available.
// ---------------------------------------------------------------------------

// Line-faithful replica of the packed_rank.rs comparison-INPUT construction
// (rotation, difference, shift constant, mask multiply, window alignment,
// aligned accumulation), instrumented with per-stage noise. Returns the
// accumulated pre-refresh sum and the post-refresh comparison input. Any drift
// in packed_rank.rs must be mirrored here.
fn instrumented_comparison_input(
    context: &EvaluatorContext,
    key: &DevelopmentBgvKey,
    packed_scores: &Ciphertext,
    option_count: usize,
    score_domain_max: u64,
    seed_hex: &str,
    trace: bool,
) -> (Ciphertext, Ciphertext) {
    let shift_constant = broadcast_constant(score_domain_max);
    let mut comparison_input_sum: Option<Ciphertext> = None;
    let mut next_window_offset = 0usize;
    if trace {
        println!(
            "    stage packed_scores: level {}, noise {:.1} bits",
            packed_scores.level,
            ciphertext_noise_bits(key, packed_scores)
        );
    }
    for shift in 1..option_count {
        let pair_window_size = option_count - shift;
        let shifted_scores = rotate_with_compact_positive_generator_basis(
            context,
            packed_scores,
            galois_power(shift),
            packed_scores.level,
            &format!("{seed_hex}-batched-pair-score-shift-{shift}"),
        )
        .expect("score shift rotation");
        if trace && shift == 1 {
            println!(
                "    stage after forward rotation (shift 1): level {}, noise {:.1} bits",
                shifted_scores.level,
                ciphertext_noise_bits(key, &shifted_scores)
            );
        }
        let difference = ciphertext_sub(packed_scores, &shifted_scores).expect("difference");
        let shifted_difference = add_plaintext_coefficients(
            &normalize_scaling(&difference).expect("difference scaling"),
            &shift_constant,
        )
        .expect("shift constant");
        if trace && shift == 1 {
            println!(
                "    stage after difference + shift constant: level {}, noise {:.1} bits",
                shifted_difference.level,
                ciphertext_noise_bits(key, &shifted_difference)
            );
        }
        let lower_pair_inputs = plaintext_mul(
            &normalize_scaling(&shifted_difference).expect("shifted-difference scaling"),
            &packed_pair_lower_mask(option_count, shift).expect("lower mask"),
        )
        .expect("mask multiply");
        if trace && shift == 1 {
            println!(
                "    stage after normalize + lower-mask plaintext_mul: level {}, noise {:.1} bits",
                lower_pair_inputs.level,
                ciphertext_noise_bits(key, &lower_pair_inputs)
            );
        }
        let windowed_inputs = if next_window_offset == 0 {
            lower_pair_inputs
        } else {
            rotate_with_compact_inverse_generator_basis(
                context,
                &lower_pair_inputs,
                next_window_offset,
                lower_pair_inputs.level,
                &format!("{seed_hex}-batched-pair-window-{shift}"),
            )
            .expect("window alignment rotation")
        };
        if trace && shift == 2 {
            println!(
                "    stage after window-alignment rotation (shift 2): level {}, noise {:.1} bits",
                windowed_inputs.level,
                ciphertext_noise_bits(key, &windowed_inputs)
            );
        }
        add_to_aligned_sum(&mut comparison_input_sum, windowed_inputs).expect("aligned sum");
        next_window_offset += pair_window_size;
    }
    let comparison_inputs = require_aligned_sum(
        comparison_input_sum,
        "probe replica did not produce comparison inputs",
    )
    .expect("comparison input sum");
    let refreshed = modulus_switch_to(
        &comparison_inputs,
        comparison_inputs.level.saturating_sub(1),
    )
    .expect("refresh switch");

    (comparison_inputs, refreshed)
}

// Injection sweep at one eval start level: returns (largest passing injected-noise
// bits, smallest failing injected-noise bits) for the D=90 deferred comparison.
fn ceiling_sweep_at_start_level(
    context: &EvaluatorContext,
    key: &DevelopmentBgvKey,
    start_level: usize,
    inject_points: &[u32],
) -> (Option<f64>, Option<f64>) {
    let domain_radius = 90u64;
    let (_, polynomial) = comparison_polynomials(domain_radius).expect("comparison polynomial");
    let baby = direct_comparison_baby_step_count(domain_radius).expect("baby step count");
    let shifted: Vec<u64> = (0..12)
        .map(|i| (i as u64 * 2 * domain_radius / 12).min(2 * domain_radius))
        .collect();
    let expected: Vec<u64> = shifted
        .iter()
        .map(|&value| u64::from(value >= domain_radius))
        .collect();

    let mut largest_pass: Option<f64> = None;
    let mut smallest_fail: Option<f64> = None;
    for &inject_bits in inject_points {
        let fresh = key
            .encrypt_slots(&shifted, "ceiling-sweep")
            .expect("encrypt");
        let mut noisy = modulus_switch_to(&fresh, start_level).expect("to start level");
        if inject_bits > 0 {
            let inject = (1u128 << inject_bits) * u128::from(PLAINTEXT_MODULUS);
            let primes = noisy.primes().to_vec();
            for (limb_index, modulus) in primes.iter().enumerate() {
                let add = (inject % u128::from(*modulus)) as u64;
                for coefficient in noisy.components[0][limb_index].iter_mut() {
                    *coefficient = add_mod(*coefficient, add, *modulus).expect("inject");
                }
            }
        }
        let input_noise = ciphertext_noise_bits(key, &noisy);
        let output = evaluate_direct_comparison_polynomial_with_baby_step_count(
            context,
            &noisy,
            &polynomial,
            baby,
        )
        .expect("comparison");
        let slots = key.decrypt_to_slots(&output).expect("slots");
        let correct = (0..shifted.len()).all(|index| slots[index] == expected[index]);
        println!(
            "    start {start_level}: input_noise {:.0} bits -> exit level {}, output_noise {:.1}, margin {:.1}, correct={correct}",
            input_noise,
            output.level,
            ciphertext_noise_bits(key, &output),
            decode_margin_bits(&output),
        );
        if correct {
            largest_pass = Some(largest_pass.map_or(input_noise, |p: f64| p.max(input_noise)));
        } else {
            smallest_fail = Some(smallest_fail.map_or(input_noise, |f: f64| f.min(input_noise)));
        }
    }

    (largest_pass, smallest_fail)
}

#[test]
#[ignore = "development-only fix-decision measurements for the D=90 handoff break; run with --ignored --nocapture"]
fn fix_decision_probe() {
    let key = DevelopmentBgvKey::generate(DEVELOPMENT_SEED).expect("development key");
    let option_count = 12usize;

    // --- (1) per-stage real comparison-input noise, n=10 distinct aggregates ---
    println!(
        "\n=== (1) real comparison-input noise, per stage (n=10, D=90, option count {option_count}) ==="
    );
    let context = EvaluatorContext::from_key(
        key.clone(),
        "fix-decision-n10",
        SELECTED_EVALUATOR_WORKING_LEVEL,
    )
    .expect("context");
    let ballot_count = 10usize;
    let score_domain_max = 9 * ballot_count as u64;
    // distinct, non-boundary aggregates in [2n, 2n+3*(m-1)] - representative real ballots.
    let aggregate_scores: Vec<u64> = (0..option_count)
        .map(|i| 2 * ballot_count as u64 + 3 * i as u64)
        .collect();
    let aggregate = multiballot_aggregate(&key, &aggregate_scores, ballot_count, "fix-decision");
    let working = modulus_switch_to(&aggregate, context.working_level()).expect("to working");
    let packed = pack_direct_score_slots(&context, &working, option_count, "fix-decision-pack")
        .expect("packed scores");
    let (pre_refresh, post_refresh) = instrumented_comparison_input(
        &context,
        &key,
        &packed,
        option_count,
        score_domain_max,
        "fix-decision-rank",
        true,
    );
    let pre_refresh_noise = ciphertext_noise_bits(&key, &pre_refresh);
    let post_refresh_noise = ciphertext_noise_bits(&key, &post_refresh);
    println!(
        "    accumulated sum PRE-refresh: level {}, noise {:.1} bits",
        pre_refresh.level, pre_refresh_noise
    );
    println!(
        "    post-refresh (= real comparison input today): level {}, noise {:.1} bits",
        post_refresh.level, post_refresh_noise
    );
    // --- (3) cleaning floors: one extra switch, two extra switches ---
    let second_switch = modulus_switch_to(&post_refresh, post_refresh.level.saturating_sub(1))
        .expect("second switch");
    let third_switch = modulus_switch_to(&second_switch, second_switch.level.saturating_sub(1))
        .expect("third switch");
    let second_noise = ciphertext_noise_bits(&key, &second_switch);
    let third_noise = ciphertext_noise_bits(&key, &third_switch);
    println!(
        "    after ONE extra cleaning switch: level {}, noise {:.1} bits",
        second_switch.level, second_noise
    );
    println!(
        "    after TWO extra cleaning switches: level {}, noise {:.1} bits (the switch floor)",
        third_switch.level, third_noise
    );
    // n=5 consistency anchor: its real input must sit under the D=45 ceiling (31..51).
    // Fresh context: rotation keys cache per context, and reusing one context across
    // packing passes accumulates level-15 rotation keys into tens of GB (measured).
    let anchor_context = EvaluatorContext::from_key(
        key.clone(),
        "fix-decision-anchor-context",
        SELECTED_EVALUATOR_WORKING_LEVEL,
    )
    .expect("anchor context");
    let anchor_scores: Vec<u64> = (0..option_count).map(|i| 10 + 3 * i as u64).collect();
    let anchor_aggregate = multiballot_aggregate(&key, &anchor_scores, 5, "fix-decision-anchor");
    let anchor_working = modulus_switch_to(&anchor_aggregate, anchor_context.working_level())
        .expect("anchor working");
    let anchor_packed = pack_direct_score_slots(
        &anchor_context,
        &anchor_working,
        option_count,
        "fix-decision-anchor",
    )
    .expect("anchor packed");
    let (_, anchor_input) = instrumented_comparison_input(
        &anchor_context,
        &key,
        &anchor_packed,
        option_count,
        45,
        "fix-decision-anchor-rank",
        false,
    );
    println!(
        "    n=5 anchor input (must be under the D=45 ceiling 31..51): level {}, noise {:.1} bits",
        anchor_input.level,
        ciphertext_noise_bits(&key, &anchor_input)
    );

    println!(
        "\n=== fix-decision input probe complete (ceilings live in fix_decision_ceiling_probe) ===\n"
    );
}

// The D=90 input-noise ceiling by eval start level. Separate from the input probe
// because the packing replicas accumulate rotation keys in the context cache (tens
// of GB across passes); this test performs no rotations at all, so its footprint is
// one comparison evaluation at a time.
//   start 14 = today's schedule (working 15, refresh kept);
//   start 15 = working-16 with the refresh kept (real input ~40 bits);
//   start 13 = working-15 plus one added cleaning switch (input ~8 bits);
//   start 16 = working-16 with the refresh REMOVED (option B's shape; real input ~87 bits).
#[test]
#[ignore = "development-only: D=90 input-noise ceiling by eval start level; run with --ignored --nocapture"]
fn fix_decision_ceiling_probe() {
    let key = DevelopmentBgvKey::generate(DEVELOPMENT_SEED).expect("development key");

    println!("\n=== D=90 input-noise ceiling by eval start level (injection sweep) ===");
    for (start_level, points) in [
        (14usize, &[12u32, 16, 20, 24, 28][..]),
        (15usize, &[12u32, 16, 20, 24, 28][..]),
        (13usize, &[8u32, 16, 24][..]),
        (16usize, &[24u32, 44, 64, 84][..]),
    ] {
        let context = EvaluatorContext::from_key(
            key.clone(),
            &format!("fix-decision-ceiling-{start_level}"),
            SELECTED_EVALUATOR_WORKING_LEVEL,
        )
        .expect("context");
        println!("  -- start level {start_level} --");
        let (largest_pass, smallest_fail) =
            ceiling_sweep_at_start_level(&context, &key, start_level, points);
        println!(
            "    => ceiling bracket at start {start_level}: pass up to {:?}, fail from {:?}",
            largest_pass, smallest_fail
        );
    }

    println!("\n=== ceiling probe complete ===\n");
}
