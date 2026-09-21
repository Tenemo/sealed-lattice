use sha2::{Digest, Sha512};

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    UnsupportedProfile,
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
                let power = self.power(powers, 16 * length / 2);
                let weighted = self.append(2, &[power, upper], 0);
                Some(self.append(1, &[lower, weighted], 0))
            }
        }
    }
    fn comparison(&mut self, input: usize) -> usize {
        let mut powers = vec![None; 182];
        powers[1] = Some(input);
        let mut blocks = Vec::new();
        for block in 0usize..12 {
            let last = 15.min(181 - 16 * block);
            let terms: Vec<_> = (0..last.div_ceil(2))
                .map(|index| {
                    let power = self.power(&mut powers, 2 * index + 1);
                    self.append(3, &[power], (16 * block + 2 * index + 1) as u32)
                })
                .collect();
            blocks.push(self.sum(&terms));
        }
        self.combine_blocks(0, 16, &blocks, &mut powers)
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
        bytes.extend(65_536u32.to_le_bytes());
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
    pub fn for_profile(
        participants: usize,
        options: usize,
        top_count: usize,
    ) -> Result<Self, Error> {
        if (participants, options) != (10, 10) || !(1..=options).contains(&top_count) {
            return Err(Error::UnsupportedProfile);
        }
        let mut builder = Builder {
            instructions: Vec::new(),
        };
        let inputs: Vec<_> = (0..10)
            .map(|position| builder.append(0, &[], position))
            .collect();
        let sum = builder.sum(&inputs);
        let input = builder.append(5, &[sum], 0);
        let polynomial = builder.comparison(input);
        let comparison = builder.append(5, &[polynomial], 1);
        let mut shifted = comparison;
        let mut rank = comparison;
        for _ in 1..16 {
            shifted = builder.append(6, &[shifted], 0);
            rank = builder.append(1, &[rank, shifted], 0);
        }
        let mut powers = vec![None; 10];
        powers[1] = Some(rank);
        // Family zero retains the complete-ordering encoding. Other families
        // contain rank-equality coefficients only for the requested prefix.
        let coefficient_base = if top_count == options {
            0
        } else {
            (options * top_count) as u32
        };
        let terms: Vec<_> = (1..10)
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
        let identity = Sha512::digest(&bytes).into();
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

    #[test]
    fn requested_prefixes_preserve_the_reference_schedule_and_complete_ordering() {
        let complete = RankingProgram::for_profile(10, 10, 10).unwrap();
        // Pinned identity of the independently emitted pre-extension schedule.
        assert_eq!(
            complete
                .identity()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            "c3872177b99208361bc96dd4127b169a0985dffa819fd648aa8f1d65f7fa93e14230168efbcae815b970d5993edb00587b70a14dc46d5aaf85af0585f0eb3042"
        );
        for top_count in 1..10 {
            let selected = RankingProgram::for_profile(10, 10, top_count).unwrap();
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

    #[test]
    fn every_requested_result_length_has_an_executable_program() {
        for top_count in 1..=10 {
            let program = RankingProgram::for_profile(10, 10, top_count)
                .expect("A supported requested result length needs its own encrypted program");
            assert!(
                rns_arithmetic_probe::ranking::Engine::new(program.bytes(), *program.identity())
                    .is_ok()
            );
        }
        for (participants, options, top_count) in
            [(10, 10, 0), (10, 10, 11), (9, 10, 1), (10, 9, 1)]
        {
            assert!(matches!(
                RankingProgram::for_profile(participants, options, top_count),
                Err(Error::UnsupportedProfile)
            ));
        }
    }

    #[test]
    fn mixed_or_noncanonical_rank_parameters_refuse_after_rehashing() {
        let program = RankingProgram::for_profile(10, 10, 3).unwrap();
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
                rns_arithmetic_probe::ranking::Engine::new(
                    &changed,
                    Sha512::digest(&changed).into()
                )
                .is_err()
            );
        }
        for constant in [2u32, 12, u32::MAX] {
            let mut changed = program.bytes().to_vec();
            let offset = changed.len() - 4;
            changed[offset..].copy_from_slice(&constant.to_le_bytes());
            assert!(
                rns_arithmetic_probe::ranking::Engine::new(
                    &changed,
                    Sha512::digest(&changed).into()
                )
                .is_err()
            );
        }
    }
}
