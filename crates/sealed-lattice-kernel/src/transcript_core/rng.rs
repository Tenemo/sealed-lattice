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

        loop {
            let value = decode_u64_be(&self.next_bytes(8));
            if let Some(reduced_value) =
                reduce_u64_below_without_modulo_bias(value, exclusive_upper_bound)
            {
                return Ok(reduced_value);
            }
        }
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

fn decode_u64_be(bytes: &[u8]) -> u64 {
    let mut value = 0_u64;
    for byte in bytes {
        value = (value << 8) | u64::from(*byte);
    }

    value
}

fn reduce_u64_below_without_modulo_bias(value: u64, exclusive_upper_bound: u64) -> Option<u64> {
    let bound = u128::from(exclusive_upper_bound);
    let sample_space_size = u128::from(u64::MAX) + 1;
    let rejection_threshold = sample_space_size - (sample_space_size % bound);
    let candidate = u128::from(value);

    if candidate >= rejection_threshold {
        return None;
    }

    Some((candidate % bound) as u64)
}

#[cfg(test)]
mod tests {
    use super::reduce_u64_below_without_modulo_bias;

    #[test]
    fn unbiased_reduction_rejects_only_the_partial_top_bucket() {
        assert_eq!(reduce_u64_below_without_modulo_bias(u64::MAX, 3), None);
        assert_eq!(
            reduce_u64_below_without_modulo_bias(u64::MAX - 1, 3),
            Some(2),
        );
        assert_eq!(reduce_u64_below_without_modulo_bias(u64::MAX, 2), Some(1),);
        assert_eq!(reduce_u64_below_without_modulo_bias(42, 1), Some(0));
    }
}
