use super::{Ciphertext, DEGREE, Engine, Refusal, plaintext, stored_bytes};
use num_bigint::BigInt;
use num_traits::Zero;
use registration_credentials::identity::identity;
use supported_profile::{FHE_SECRET_SUPPORT, PLAINTEXT_MODULUS, Profile};

/// The diagnostic identity of every loaded input and its position.
const PROBE_INPUT_DOMAIN: &str = "sealed-lattice/requested-output-probe-input/v2";

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
        let slot = (option * profile.options() + rank) * profile.rank_window();
        let exponent = power(5, slot, DEGREE as u64);
        let root = power(3, exponent as usize, PRIME);
        let inverse = power(root, (PRIME - 2) as usize, PRIME);
        let mut term = power((DEGREE / 2) as u64, (PRIME - 2) as usize, PRIME);
        for coefficient in expected.iter_mut().step_by(2) {
            *coefficient = (*coefficient + term) % PRIME;
            term = term * inverse % PRIME;
        }
    }
    expected
}

/// Input p below the option count less one encrypts the rank powers of
/// exponent p + 1; every other input encrypts zero and only enters the sum.
fn program(profile: Profile, top_count: usize) -> Vec<u8> {
    let (participants, options) = (profile.participants(), profile.options());
    let mut instructions = Vec::<[u32; 4]>::new();
    for position in 0..participants {
        instructions.push([0, u32::MAX, u32::MAX, position as u32]);
    }
    let family = if top_count == options { 0 } else { top_count };
    let mut sum = (participants - 1) as u32;
    for position in options - 1..participants - 1 {
        let next = instructions.len() as u32;
        instructions.push([1, sum, position as u32, 0]);
        sum = next;
    }
    for exponent in 1..options {
        let weighted = instructions.len() as u32;
        instructions.push([
            4,
            (exponent - 1) as u32,
            u32::MAX,
            (options * family + exponent) as u32,
        ]);
        let next = instructions.len() as u32;
        instructions.push([1, sum, weighted, 0]);
        sum = next;
    }
    instructions.push([5, sum, u32::MAX, 2 + family as u32]);
    let mut bytes = b"BRK1".to_vec();
    bytes.extend((DEGREE as u32).to_le_bytes());
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
    let program = super::program_identity(&bytes)?;
    let mut engine = Engine::new(profile, &bytes, program)?;
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
    let mut slots: Vec<_> = (0..DEGREE / 4)
        .map(|index| ((index * 73 + 19) % PRIME as usize) as u32)
        .collect();
    for (option, rank) in ranks.iter().enumerate() {
        for requested in 0..options {
            slots[(option * options + requested) * profile.rank_window()] = *rank;
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
        to_hex(&program),
        to_hex(
            &ciphertext_identity
                .finish()
                .map_err(|_| Refusal::Identity)?
        ),
    ))
}
