use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult, append_varuint};

pub struct DeterministicFixtureRng {
    seed: Vec<u8>,
    counter: u64,
    buffer: [u8; 64],
    offset: usize,
}

impl DeterministicFixtureRng {
    pub fn new(seed: &str) -> Self {
        Self {
            seed: seed.as_bytes().to_vec(),
            counter: 0,
            buffer: [0_u8; 64],
            offset: 64,
        }
    }

    pub fn next_bytes(&mut self, length: usize) -> Vec<u8> {
        let mut output = Vec::with_capacity(length);
        while output.len() < length {
            if self.offset == self.buffer.len() {
                self.refill();
            }
            let available = self.buffer.len() - self.offset;
            let needed = length - output.len();
            let copied = available.min(needed);
            output.extend_from_slice(&self.buffer[self.offset..self.offset + copied]);
            self.offset += copied;
        }

        output
    }

    pub fn next_u64_below(&mut self, exclusive_upper_bound: u64) -> CanonicalResult<u64> {
        if exclusive_upper_bound == 0 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "deterministic fixture RNG bound must be greater than zero",
            ));
        }

        let bytes = self.next_bytes(8);
        let mut value = 0_u64;
        for byte in bytes {
            value = (value << 8) | u64::from(byte);
        }

        Ok(value % exclusive_upper_bound)
    }

    fn refill(&mut self) {
        let mut counter_bytes = Vec::new();
        append_varuint(&mut counter_bytes, self.counter);
        self.buffer = crate::hashing::hash512(
            "transcript-core/deterministic-fixture-rng-block",
            &[&self.seed, &counter_bytes],
        );
        self.counter += 1;
        self.offset = 0;
    }
}
