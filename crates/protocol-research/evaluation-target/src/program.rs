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
        if (participants, options, top_count) != (10, 10, 10) {
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
        let terms: Vec<_> = (1..10)
            .map(|exponent| {
                let power = builder.power(&mut powers, exponent);
                builder.append(4, &[power], exponent as u32)
            })
            .collect();
        let sum = builder.sum(&terms);
        let result = builder.append(5, &[sum], 2);
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
