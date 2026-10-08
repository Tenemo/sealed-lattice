use encrypted_ranking::ranking::program_identity;
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
#[path = "program-tests.rs"]
mod tests;
