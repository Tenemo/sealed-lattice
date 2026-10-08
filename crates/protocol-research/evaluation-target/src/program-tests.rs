use super::*;
use encrypted_ranking::ranking::{Engine, MAXIMUM_INSTRUCTIONS};
use num_bigint::BigUint;

fn completion() -> Profile {
    Profile::new(10, 10).unwrap()
}

#[test]
fn requested_prefixes_preserve_the_reference_schedule_and_complete_ordering() {
    let complete = RankingProgram::for_profile(completion(), 10).unwrap();
    // Pinned identity of the independently emitted pre-extension schedule.
    assert_eq!(
        complete
            .identity()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        "fea389f6318ffe0fcb36050c9ba22fb24aa60b8462fe026eb20a63b0f8d312a0d6e2fb3666fc6655f0bd602178c808b42fe8a1682ab566a41184042ccae83cf8"
    );
    for top_count in 1..10 {
        let selected = RankingProgram::for_profile(completion(), top_count).unwrap();
        assert_eq!(selected.bytes().len(), complete.bytes().len());
        assert_eq!(selected.bytes()[..16], complete.bytes()[..16]);
        for (before, after) in complete.bytes()[16..]
            .chunks_exact(16)
            .zip(selected.bytes()[16..].chunks_exact(16))
        {
            assert_eq!(before[..12], after[..12]);
            let operation = u32::from_le_bytes(before[..4].try_into().unwrap());
            let parameter = u32::from_le_bytes(before[12..].try_into().unwrap());
            if operation != 4 && !(operation == 5 && parameter == 2) {
                assert_eq!(before, after);
            }
        }
    }
}

// Counts each operation of a program.
fn operations(program: &RankingProgram) -> [usize; 7] {
    let mut counts = [0; 7];
    for bytes in program.bytes()[16..].chunks_exact(16) {
        counts[u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize] += 1;
    }
    counts
}

#[test]
fn every_profile_and_requested_result_length_has_an_executable_program() {
    for profile in Profile::all() {
        let options = profile.options();
        for top_count in [1, options] {
            let program = RankingProgram::for_profile(profile, top_count).unwrap();
            let counts = operations(&program);
            // One input per roster position, one weight per odd
            // comparison coefficient, one rotation per further window
            // slot, one weight per nonconstant rank-equality power and
            // three plaintext additions.
            assert_eq!(counts[0], profile.participants());
            assert_eq!(counts[3], profile.comparison_degree().div_ceil(2));
            assert_eq!(counts[6], profile.rank_window() - 1);
            assert_eq!(counts[4], options - 1);
            assert_eq!(counts[5], 3);
            assert!(counts.iter().sum::<usize>() <= MAXIMUM_INSTRUCTIONS);
        }
        for top_count in [0, options + 1] {
            assert!(matches!(
                RankingProgram::for_profile(profile, top_count),
                Err(Error::UnsupportedTopCount)
            ));
        }
    }
    for (participants, options) in [(3, 2), (3, 20), (10, 10), (20, 2), (20, 20)] {
        let profile = Profile::new(participants, options).unwrap();
        for top_count in [1, options] {
            let program = RankingProgram::for_profile(profile, top_count).unwrap();
            assert!(Engine::new(profile, program.bytes()).is_ok());
        }
        // A program admits only its own profile.
        let program = RankingProgram::for_profile(profile, 1).unwrap();
        let other_options = if options == 2 { 3 } else { options - 1 };
        let other_participants = if participants == 3 {
            4
        } else {
            participants - 1
        };
        for (participants, options) in
            [(participants, other_options), (other_participants, options)]
        {
            let other = Profile::new(participants, options).unwrap();
            assert!(Engine::new(other, program.bytes()).is_err());
        }
    }
}

// A canonical polynomial of pseudorandom coefficients of both signs
// decodes the same whole and in pieces that split coefficients anywhere;
// a sign byte beyond one, a negative zero, a magnitude beyond half the
// modulus, a missing byte and an extra coefficient refuse. A stored
// value's pieces are whole words, no more than the value holds.
#[test]
fn a_polynomial_arriving_in_pieces_decodes_as_it_does_whole() {
    let profile = Profile::new(3, 2).unwrap();
    let program = RankingProgram::for_profile(profile, 1).unwrap();
    let engine = Engine::new(profile, program.bytes()).unwrap();
    let width = engine.coefficient_bytes();
    let mut bytes = vec![0; DEGREE * width];
    let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
    for coefficient in bytes.chunks_exact_mut(width) {
        seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let magnitude = (seed >> 11).to_le_bytes();
        coefficient[1..9].copy_from_slice(&magnitude);
        coefficient[0] = u8::from(seed & 1 == 1 && seed >> 11 != 0);
    }
    let whole = engine.decode_polynomial(&bytes).unwrap();
    for piece in [1, 7, width - 1, width, width + 1, 4099, 1 << 20] {
        let mut decoder = engine.polynomial_decoder();
        for bytes in bytes.chunks(piece) {
            engine.decode_into(&mut decoder, bytes).unwrap();
        }
        assert_eq!(engine.finish_polynomial(decoder).unwrap(), whole);
    }
    let refuses = |bytes: &[u8]| engine.decode_polynomial(bytes).is_err();
    let mut changed = bytes.clone();
    changed[5 * width] = 2;
    assert!(refuses(&changed));
    let mut changed = bytes.clone();
    changed[7 * width..8 * width].fill(0);
    changed[7 * width] = 1;
    assert!(refuses(&changed));
    let mut changed = bytes.clone();
    changed[9 * width + 1..10 * width].fill(0xff);
    assert!(refuses(&changed));
    assert!(refuses(&bytes[..bytes.len() - 1]));
    assert!(refuses(&[&bytes[..], &bytes[..width]].concat()));
    // Half the modulus rounded down, several words long, decodes with
    // either sign and one more refuses with either; a negative
    // coefficient decodes to the modulus minus its magnitude, here from
    // the modulus's own odd factor and exponent.
    let modulus = profile.ciphertext_modulus();
    let q = (BigUint::from(modulus.odd_factor()) << modulus.exponent()) + 1u32;
    let half = (&q - 1u32) >> 1u32;
    let words = whole.len() / DEGREE;
    assert!(words > 1 && half.bits() > 64);
    let encoded = |negative: bool, magnitude: &BigUint| {
        let mut coefficient = vec![0; width];
        coefficient[0] = u8::from(negative);
        let digits = magnitude.to_bytes_le();
        coefficient[1..1 + digits.len()].copy_from_slice(&digits);
        coefficient
    };
    let word_values = |value: BigUint| {
        let mut values = value.to_u64_digits();
        values.resize(words, 0);
        values
    };
    let above_word = BigUint::from(1u32) << 64u32;
    let cases = [
        (false, half.clone(), half.clone()),
        (true, half.clone(), &q - &half),
        (true, BigUint::from(1u32), &q - 1u32),
        (false, above_word.clone(), above_word.clone()),
        (true, above_word.clone(), &q - &above_word),
    ];
    let mut boundary = bytes.clone();
    for (index, (negative, magnitude, _)) in cases.iter().enumerate() {
        boundary[index * width..(index + 1) * width]
            .copy_from_slice(&encoded(*negative, magnitude));
    }
    let decoded = engine.decode_polynomial(&boundary).unwrap();
    for (index, (_, _, expected)) in cases.into_iter().enumerate() {
        assert_eq!(
            decoded[index * words..(index + 1) * words],
            word_values(expected)[..]
        );
    }
    for negative in [false, true] {
        let mut beyond = bytes.clone();
        beyond[..width].copy_from_slice(&encoded(negative, &(&half + 1u32)));
        assert!(refuses(&beyond));
    }
    let mut decoder = engine.polynomial_decoder();
    engine
        .decode_into(&mut decoder, &bytes[..bytes.len() - 1])
        .unwrap();
    assert!(engine.finish_polynomial(decoder).is_err());
    let value_bytes = encrypted_ranking::ranking::stored_value_bytes(profile);
    let mut read = engine.begin_reload(0).unwrap();
    assert!(engine.push_read(&mut read, &[0; 7]).is_err());
    assert!(
        engine
            .push_read(&mut read, &vec![0; value_bytes + 8])
            .is_err()
    );
    engine
        .push_read(&mut read, &vec![0; value_bytes - 8])
        .unwrap();
    assert!(engine.push_read(&mut read, &[0; 16]).is_err());
}

#[test]
fn mixed_or_noncanonical_rank_parameters_refuse_after_rehashing() {
    let program = RankingProgram::for_profile(completion(), 3).unwrap();
    let weighted = program.bytes()[16..]
        .chunks_exact(16)
        .position(|bytes| u32::from_le_bytes(bytes[..4].try_into().unwrap()) == 4)
        .unwrap();
    let parameter_offset = 16 + 16 * weighted + 12;
    let original = u32::from_le_bytes(
        program.bytes()[parameter_offset..parameter_offset + 4]
            .try_into()
            .unwrap(),
    );
    for parameter in [original + 10, 0, 100, u32::MAX] {
        let mut changed = program.bytes().to_vec();
        changed[parameter_offset..parameter_offset + 4].copy_from_slice(&parameter.to_le_bytes());
        assert!(Engine::new(completion(), &changed).is_err());
    }
    for constant in [2u32, 12, u32::MAX] {
        let mut changed = program.bytes().to_vec();
        let offset = changed.len() - 4;
        changed[offset..].copy_from_slice(&constant.to_le_bytes());
        assert!(Engine::new(completion(), &changed).is_err());
    }
}
