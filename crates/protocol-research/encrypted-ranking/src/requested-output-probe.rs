use super::{Ciphertext, DEGREE, Engine, Refusal, plaintext, stored_bytes};
use num_bigint::BigInt;
use num_traits::Zero;
use protocol_foundations::identity::identity;
use supported_profile::plaintext::{ACTIVE_SLOTS, ENCODING_DEGREE};
use supported_profile::{FHE_SECRET_SUPPORT, PLAINTEXT_MODULUS, Profile};

/// The diagnostic identity of every loaded input and its position.
const PROBE_INPUT_DOMAIN: &str = "sealed-lattice/requested-output-probe-input";

const PRIME: u64 = PLAINTEXT_MODULUS as u64;

fn power(mut value: u64, mut exponent: usize, modulus: u64) -> u64 {
    let mut result = 1;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = result * value % modulus;
        }
        value = value * value % modulus;
        exponent >>= 1;
    }
    result
}

/// The fixed rank order of the options that the synthetic inputs encrypt.
fn order(options: usize) -> Vec<usize> {
    let mut state = 0x9e37_79b9_7f4a_7c15 ^ options as u64;
    let mut order: Vec<_> = (0..options).collect();
    for index in (1..options).rev() {
        let other = (super::super::next(&mut state) % (index as u64 + 1)) as usize;
        order.swap(index, other);
    }
    order
}

// Direct evaluation-basis interpolation is independent of the coefficient
// encoder and of the encrypted arithmetic being exercised.
fn expected_coefficients(profile: Profile, order: &[usize], top_count: usize) -> Vec<u64> {
    let mut expected = vec![0; DEGREE];
    for (rank, option) in order.iter().take(top_count).enumerate() {
        let slot = (option * profile.rank_window() + ACTIVE_SLOTS - rank) % ACTIVE_SLOTS;
        let exponent = power(5, slot, ENCODING_DEGREE as u64);
        let root = power(
            11,
            (PRIME as usize - 1) / ENCODING_DEGREE * exponent as usize,
            PRIME,
        );
        let inverse = power(root, (PRIME - 2) as usize, PRIME);
        let mut term = power((ENCODING_DEGREE / 2) as u64, (PRIME - 2) as usize, PRIME);
        for coefficient in expected.iter_mut().step_by(2 * DEGREE / ENCODING_DEGREE) {
            *coefficient = (*coefficient + term) % PRIME;
            term = term * inverse % PRIME;
        }
    }
    expected
}

/// Input p below the option count less one encrypts the rank powers of
/// exponent p + 1; every other input encrypts zero and only enters the sum.
/// Each input loads just before its use, so the program holds at most three
/// values at once and never spills.
fn program(profile: Profile, top_count: usize) -> Vec<u8> {
    let (participants, options) = (profile.participants(), profile.options());
    let mut instructions = vec![[0, u32::MAX, u32::MAX, (participants - 1) as u32]];
    let family = if top_count == options { 0 } else { top_count };
    let mut sum = 0;
    for position in options - 1..participants - 1 {
        instructions.push([0, u32::MAX, u32::MAX, position as u32]);
        instructions.push([1, sum, instructions.len() as u32 - 1, 0]);
        sum = instructions.len() as u32 - 1;
    }
    for exponent in 1..options {
        instructions.push([0, u32::MAX, u32::MAX, (exponent - 1) as u32]);
        instructions.push([
            4,
            instructions.len() as u32 - 1,
            u32::MAX,
            (options * family + exponent) as u32,
        ]);
        instructions.push([1, sum, instructions.len() as u32 - 1, 0]);
        sum = instructions.len() as u32 - 1;
    }
    instructions.push([5, sum, u32::MAX, 2 + family as u32]);
    instructions.push([
        5,
        instructions.len() as u32 - 1,
        u32::MAX,
        3 + options as u32,
    ]);
    let mut bytes = (DEGREE as u32).to_le_bytes().to_vec();
    bytes.extend((instructions.len() as u32).to_le_bytes());
    bytes.extend(((instructions.len() - 1) as u32).to_le_bytes());
    for instruction in instructions {
        for word in instruction {
            bytes.extend(word.to_le_bytes());
        }
    }
    bytes
}

/// Numerical coefficient-selection gates under a deterministic synthetic BFV
/// key. The inputs encrypt known rank powers, not participant ballots, so
/// the profile needs an input for every rank power. The test-only secret
/// decoder cannot receive an external key or ciphertext.
pub fn probe(profile: Profile, top_count: usize) -> Result<String, Refusal> {
    let (participants, options) = (profile.participants(), profile.options());
    if !(1..=options).contains(&top_count) || participants < options {
        return Err(Refusal::Program);
    }
    let bytes = program(profile, top_count);
    let mut engine = Engine::new(profile, &bytes)?;
    let secret = engine.arithmetic.small(&super::super::secret(
        DEGREE,
        profile.setup_contributors(),
        FHE_SECRET_SUPPORT,
        0x1234_5678_9abc_def1,
    ));
    let common = engine.arithmetic.uniform(0x6a09_e667_f3bc_c909);
    let zeros = vec![0; DEGREE];
    let public = engine.arithmetic.affine(
        &engine.arithmetic.multiply(&secret, &common, false),
        true,
        &zeros,
        &BigInt::zero(),
        -640,
    );
    let order = order(options);
    let mut ranks = vec![0; options];
    for (rank, option) in order.iter().enumerate() {
        ranks[*option] = rank as u32;
    }
    let mut slots = vec![0; ACTIVE_SLOTS];
    for (option, rank) in ranks.iter().enumerate() {
        for requested in 0..options {
            slots[(option * profile.rank_window() + ACTIVE_SLOTS - requested) % ACTIVE_SLOTS] =
                *rank;
        }
    }
    let mut inputs = Vec::new();
    while !engine.finished() {
        let requirements = engine.requirements()?;
        if requirements.cache.is_some()
            || !requirements.spills.is_empty()
            || !requirements.reloads.is_empty()
        {
            return Err(Refusal::Allocation);
        }
        if let Some(position) = requirements.input_position {
            let input: Ciphertext = if position + 1 >= options {
                engine.zero_value()
            } else {
                let ephemeral = engine.arithmetic.small(&super::super::ephemeral(
                    DEGREE,
                    FHE_SECRET_SUPPORT,
                    0x12ab_cdef_1234_5679 ^ position as u64,
                ));
                let encrypted_zero = [
                    engine.arithmetic.affine(
                        &engine.arithmetic.multiply(&ephemeral, &public, false),
                        false,
                        &zeros,
                        &BigInt::zero(),
                        63,
                    ),
                    engine.arithmetic.affine(
                        &engine.arithmetic.multiply(&ephemeral, &common, false),
                        false,
                        &zeros,
                        &BigInt::zero(),
                        -64,
                    ),
                ];
                let powered: Vec<_> = slots
                    .iter()
                    .map(|value| power(u64::from(*value), position + 1, PRIME) as u32)
                    .collect();
                engine.add_plaintext(&encrypted_zero, &plaintext::encode(&powered))
            };
            inputs.extend((position as u32).to_le_bytes());
            inputs.extend(stored_bytes(&input));
            engine.load_input(position, input)?;
        }
        engine.execute()?;
    }
    let decoded = engine
        .arithmetic
        .decode(engine.value(engine.step() - 1)?, &secret);
    if decoded != expected_coefficients(profile, &order, top_count) {
        return Err(Refusal::Coefficient);
    }
    let to_hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let output = engine.step() - 1;
    let mut ciphertext_identity = engine.value_hasher(output)?;
    ciphertext_identity
        .absorb(&stored_bytes(engine.value(output)?))
        .map_err(|_| Refusal::Identity)?;
    Ok(format!(
        "{{\"participants\":{participants},\"options\":{options},\"topCount\":{top_count},\"degree\":{DEGREE},\"optionPositions\":{:?},\"inputIdentity\":\"{}\",\"programIdentity\":\"{}\",\"ciphertextIdentity\":\"{}\"}}",
        &order[..top_count],
        to_hex(&identity(PROBE_INPUT_DOMAIN, &inputs).map_err(|_| Refusal::Identity)?),
        to_hex(&super::program_identity(&bytes)?),
        to_hex(
            &ciphertext_identity
                .finish()
                .map_err(|_| Refusal::Identity)?
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_scalar_output_preserves_full_and_short_requested_orders() {
        let profile = Profile::new(3, 2).unwrap();
        assert!(probe(profile, 2).is_ok());
        assert!(probe(profile, 1).is_ok());
        assert_eq!(probe(profile, 0), Err(Refusal::Program));
        assert_eq!(probe(profile, 3), Err(Refusal::Program));
    }

    #[test]
    fn compact_scalar_mask_removes_the_literal_orbit_and_nonbase_positions() {
        let profile = Profile::new(3, 2).unwrap();
        let mut instructions = vec![
            [0, u32::MAX, u32::MAX, 0],
            [0, u32::MAX, u32::MAX, 1],
            [1, 0, 1, 0],
            [0, u32::MAX, u32::MAX, 2],
            [1, 2, 3, 0],
            [4, 4, u32::MAX, 0],
        ];
        let bytes: Vec<_> = [
            DEGREE as u32,
            instructions.len() as u32,
            instructions.len() as u32 - 1,
        ]
        .into_iter()
        .chain(instructions.drain(..).flatten())
        .flat_map(u32::to_le_bytes)
        .collect();
        let mut engine = Engine::new(profile, &bytes).unwrap();
        let secret = engine.arithmetic.small(&super::super::super::secret(
            DEGREE,
            2,
            FHE_SECRET_SUPPORT,
            0x4123_5678_9abc_def1,
        ));
        let primary: Vec<_> = (0..ACTIVE_SLOTS)
            .map(|position| (position % 10 + 1) as u32)
            .collect();
        let complementary: Vec<_> = (0..ACTIVE_SLOTS)
            .map(|position| (position % 10 + 1) as u32)
            .collect();
        let message = supported_profile::plaintext::encode_orbits(&primary, &complementary, DEGREE);
        let input = engine.add_plaintext(&engine.zero_value(), &message);
        while !engine.finished() {
            if let Some(position) = engine.requirements().unwrap().input_position {
                engine
                    .load_input(
                        position,
                        if position == 0 {
                            input.clone()
                        } else {
                            engine.zero_value()
                        },
                    )
                    .unwrap();
            }
            engine.execute().unwrap();
        }
        let actual = engine
            .arithmetic
            .decode(engine.value(engine.step() - 1).unwrap(), &secret);
        let kept: Vec<_> = primary
            .iter()
            .enumerate()
            .map(|(position, value)| {
                if position % profile.rank_window() == 0 {
                    *value
                } else {
                    0
                }
            })
            .collect();
        let expected: Vec<_> = supported_profile::plaintext::encode_slots(&kept, DEGREE)
            .iter()
            .map(|value| value.rem_euclid(PLAINTEXT_MODULUS as i32) as u64)
            .collect();
        assert_eq!(actual, expected);
    }
}
