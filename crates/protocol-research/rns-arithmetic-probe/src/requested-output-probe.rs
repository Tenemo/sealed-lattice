use super::{Ciphertext, DEGREE, Engine, OPTION_COUNT, Refusal, plaintext};
use num_bigint::BigInt;
use num_traits::Zero;
use sha2::{Digest, Sha512};

const PRIME: u64 = 65_537;
const ORDER: [usize; OPTION_COUNT] = [4, 1, 8, 0, 7, 2, 9, 5, 3, 6];

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

// Direct evaluation-basis interpolation is independent of the coefficient
// encoder and of the encrypted arithmetic being exercised.
fn expected_coefficients(top_count: usize) -> Vec<u64> {
    let mut expected = vec![0; DEGREE];
    for (rank, option) in ORDER.iter().take(top_count).enumerate() {
        let slot = (option * OPTION_COUNT + rank) * 16;
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

fn program(top_count: usize) -> Vec<u8> {
    let mut instructions = Vec::<[u32; 4]>::new();
    for position in 0..OPTION_COUNT {
        instructions.push([0, u32::MAX, u32::MAX, position as u32]);
    }
    let family = if top_count == OPTION_COUNT {
        0
    } else {
        top_count
    };
    let mut sum = (OPTION_COUNT - 1) as u32;
    for exponent in 1..OPTION_COUNT {
        let weighted = instructions.len() as u32;
        instructions.push([
            4,
            (exponent - 1) as u32,
            u32::MAX,
            (OPTION_COUNT * family + exponent) as u32,
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
/// key. The inputs encrypt known rank powers, not participant ballots. The
/// test-only secret decoder cannot receive an external key or ciphertext.
pub fn probe(top_count: usize) -> Result<String, Refusal> {
    if !(1..=OPTION_COUNT).contains(&top_count) {
        return Err(Refusal::Program);
    }
    crate::benchmark_phase(0);
    let bytes = program(top_count);
    let identity: [u8; 64] = Sha512::digest(&bytes).into();
    let mut engine = Engine::new(&bytes, identity)?;
    let secret =
        engine
            .arithmetic
            .small(&super::super::secret(DEGREE, 1024, 0x1234_5678_9abc_def1));
    let common = engine.arithmetic.uniform(0x6a09_e667_f3bc_c909);
    let zeros = vec![0; DEGREE];
    let public = engine.arithmetic.affine(
        &engine.arithmetic.multiply(&secret, &common, false),
        true,
        &zeros,
        &BigInt::zero(),
        -640,
    );
    let mut ranks = [0; OPTION_COUNT];
    for (rank, option) in ORDER.iter().enumerate() {
        ranks[*option] = rank as u32;
    }
    let mut slots: Vec<_> = (0..DEGREE / 4)
        .map(|index| ((index * 73 + 19) % PRIME as usize) as u32)
        .collect();
    for (option, rank) in ranks.iter().enumerate() {
        for requested in 0..OPTION_COUNT {
            slots[(option * OPTION_COUNT + requested) * 16] = *rank;
        }
    }
    let mut input_hash = Sha512::new();
    input_hash.update(b"sealed-lattice/requested-output-probe-input/v1");
    crate::benchmark_phase(1);
    while !engine.finished() {
        let requirements = engine.requirements()?;
        if requirements.cache.is_some()
            || !requirements.spills.is_empty()
            || !requirements.reloads.is_empty()
        {
            return Err(Refusal::Allocation);
        }
        if let Some(position) = requirements.input_position {
            let input: Ciphertext = if position == OPTION_COUNT - 1 {
                std::array::from_fn(|_| vec![[0; 14]; DEGREE])
            } else {
                let ephemeral = engine.arithmetic.small(&super::super::ephemeral(
                    DEGREE,
                    1024,
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
            input_hash.update((position as u32).to_le_bytes());
            for polynomial in &input {
                for coefficient in polynomial {
                    for word in coefficient {
                        input_hash.update(word.to_le_bytes());
                    }
                }
            }
            engine.load_input(position, input)?;
        }
        engine.execute()?;
    }
    crate::benchmark_phase(2);
    let decoded = engine
        .arithmetic
        .decode(engine.value(engine.step() - 1)?, &secret);
    let expected = expected_coefficients(top_count);
    if decoded != expected {
        return Err(Refusal::Coefficient);
    }
    crate::benchmark_phase(3);
    let to_hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    Ok(format!(
        "{{\"topCount\":{top_count},\"degree\":{DEGREE},\"optionPositions\":{:?},\"inputIdentity\":\"{}\",\"programIdentity\":\"{}\",\"ciphertextIdentity\":\"{}\"}}",
        &ORDER[..top_count],
        to_hex(&input_hash.finalize()),
        to_hex(&identity),
        to_hex(&engine.value_identity(engine.step() - 1, engine.value(engine.step() - 1)?)),
    ))
}
