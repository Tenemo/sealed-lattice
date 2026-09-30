use rns_arithmetic_probe::ranking::program_identity;
use supported_profile::{DEGREE, Profile};

/// The comparison polynomial is evaluated in blocks of this many powers.
const COMPARISON_BLOCK_WIDTH: usize = 16;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    UnsupportedTopCount,
    Encoding,
}

struct Instruction {
    operation: u32,
    inputs: Vec<usize>,
    parameter: u32,
}

struct Builder {
    instructions: Vec<Instruction>,
}
impl Builder {
    fn append(&mut self, operation: u32, inputs: &[usize], parameter: u32) -> usize {
        let index = self.instructions.len();
        assert!(inputs.iter().all(|input| *input < index));
        self.instructions.push(Instruction {
            operation,
            inputs: inputs.to_vec(),
            parameter,
        });
        index
    }
    fn sum(&mut self, values: &[usize]) -> usize {
        assert!(!values.is_empty());
        values[1..]
            .iter()
            .fold(values[0], |left, right| self.append(1, &[left, *right], 0))
    }
    fn power(&mut self, cache: &mut [Option<usize>], exponent: usize) -> usize {
        assert!(exponent > 0 && exponent < cache.len());
        if let Some(value) = cache[exponent] {
            return value;
        }
        let left = self.power(cache, exponent / 2);
        let right = self.power(cache, exponent.div_ceil(2));
        let value = self.append(2, &[left, right], 0);
        cache[exponent] = Some(value);
        value
    }
    fn combine_blocks(
        &mut self,
        offset: usize,
        length: usize,
        blocks: &[usize],
        powers: &mut [Option<usize>],
    ) -> Option<usize> {
        if offset >= blocks.len() {
            return None;
        }
        if length == 1 {
            return Some(blocks[offset]);
        }
        let lower = self
            .combine_blocks(offset, length / 2, blocks, powers)
            .expect("nonempty lower block");
        match self.combine_blocks(offset + length / 2, length / 2, blocks, powers) {
            None => Some(lower),
            Some(upper) => {
                let power = self.power(powers, COMPARISON_BLOCK_WIDTH * length / 2);
                let weighted = self.append(2, &[power, upper], 0);
                Some(self.append(1, &[lower, weighted], 0))
            }
        }
    }
    /// The odd comparison polynomial of the given degree: each block's
    /// weighted odd powers, combined by powers of the block width.
    fn comparison(&mut self, input: usize, degree: usize) -> usize {
        let mut powers = vec![None; degree + 1];
        powers[1] = Some(input);
        let mut blocks = Vec::new();
        for block in 0..(degree + 1).div_ceil(COMPARISON_BLOCK_WIDTH) {
            let last = (COMPARISON_BLOCK_WIDTH - 1).min(degree - COMPARISON_BLOCK_WIDTH * block);
            let terms: Vec<_> = (0..last.div_ceil(2))
                .map(|index| {
                    let power = self.power(&mut powers, 2 * index + 1);
                    self.append(
                        3,
                        &[power],
                        (COMPARISON_BLOCK_WIDTH * block + 2 * index + 1) as u32,
                    )
                })
                .collect();
            blocks.push(self.sum(&terms));
        }
        self.combine_blocks(0, blocks.len().next_power_of_two(), &blocks, &mut powers)
            .expect("complete comparison polynomial")
    }
    fn encode(self, result: usize) -> Vec<u8> {
        fn visit(
            index: usize,
            instructions: &[Instruction],
            seen: &mut [bool],
            ordered: &mut Vec<usize>,
        ) {
            if seen[index] {
                return;
            }
            seen[index] = true;
            for input in &instructions[index].inputs {
                visit(*input, instructions, seen, ordered);
            }
            ordered.push(index);
        }
        let mut ordered = Vec::new();
        let mut seen = vec![false; self.instructions.len()];
        visit(result, &self.instructions, &mut seen, &mut ordered);
        assert_eq!(ordered.len(), self.instructions.len());
        let mut renamed = vec![0; ordered.len()];
        for (index, original) in ordered.iter().enumerate() {
            renamed[*original] = index;
        }
        let mut bytes = Vec::from(b"BRK1".as_slice());
        bytes.extend((DEGREE as u32).to_le_bytes());
        bytes.extend((ordered.len() as u32).to_le_bytes());
        bytes.extend((renamed[result] as u32).to_le_bytes());
        for original in ordered {
            let instruction = &self.instructions[original];
            bytes.extend(instruction.operation.to_le_bytes());
            for position in 0..2 {
                bytes.extend(
                    instruction
                        .inputs
                        .get(position)
                        .map_or(u32::MAX, |input| renamed[*input] as u32)
                        .to_le_bytes(),
                );
            }
            bytes.extend(instruction.parameter.to_le_bytes());
        }
        bytes
    }
}

/// Public computation description only. The target verifier must separately
/// own the complete source classifications, setup and ciphertext bindings.
pub struct RankingProgram {
    bytes: Vec<u8>,
    identity: [u8; 64],
}
impl RankingProgram {
    /// The encrypted ranking of the profile's accepted ballots: their sum,
    /// every pairwise comparison, each option's rank over the comparison
    /// window and the rank-equality weights of the requested result length.
    pub fn for_profile(profile: Profile, top_count: usize) -> Result<Self, Error> {
        let options = profile.options();
        if !(1..=options).contains(&top_count) {
            return Err(Error::UnsupportedTopCount);
        }
        let mut builder = Builder {
            instructions: Vec::new(),
        };
        let inputs: Vec<_> = (0..profile.participants() as u32)
            .map(|position| builder.append(0, &[], position))
            .collect();
        let sum = builder.sum(&inputs);
        let input = builder.append(5, &[sum], 0);
        let polynomial = builder.comparison(input, profile.comparison_degree());
        let comparison = builder.append(5, &[polynomial], 1);
        let mut shifted = comparison;
        let mut rank = comparison;
        for _ in 1..profile.rank_window() {
            shifted = builder.append(6, &[shifted], 0);
            rank = builder.append(1, &[rank, shifted], 0);
        }
        let mut powers = vec![None; options];
        powers[1] = Some(rank);
        // Family zero retains the complete-ordering encoding. Other families
        // contain rank-equality coefficients only for the requested prefix.
        let coefficient_base = if top_count == options {
            0
        } else {
            (options * top_count) as u32
        };
        let terms: Vec<_> = (1..options)
            .map(|exponent| {
                let power = builder.power(&mut powers, exponent);
                builder.append(4, &[power], coefficient_base + exponent as u32)
            })
            .collect();
        let sum = builder.sum(&terms);
        let constant = if top_count == options {
            2
        } else {
            2 + top_count as u32
        };
        let result = builder.append(5, &[sum], constant);
        let bytes = builder.encode(result);
        let identity = program_identity(&bytes).map_err(|_| Error::Encoding)?;
        Ok(Self { bytes, identity })
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn identity(&self) -> &[u8; 64] {
        &self.identity
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;
    use rns_arithmetic_probe::ranking::{Engine, MAXIMUM_INSTRUCTIONS};

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
                assert!(Engine::new(profile, program.bytes(), *program.identity()).is_ok());
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
                assert!(Engine::new(other, program.bytes(), *program.identity()).is_err());
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
        let engine = Engine::new(profile, program.bytes(), *program.identity()).unwrap();
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
        let value_bytes = rns_arithmetic_probe::ranking::stored_value_bytes(profile);
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
            changed[parameter_offset..parameter_offset + 4]
                .copy_from_slice(&parameter.to_le_bytes());
            assert!(
                Engine::new(completion(), &changed, program_identity(&changed).unwrap()).is_err()
            );
        }
        for constant in [2u32, 12, u32::MAX] {
            let mut changed = program.bytes().to_vec();
            let offset = changed.len() - 4;
            changed[offset..].copy_from_slice(&constant.to_le_bytes());
            assert!(
                Engine::new(completion(), &changed, program_identity(&changed).unwrap()).is_err()
            );
        }
    }
}
