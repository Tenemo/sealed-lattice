use sha3::digest::XofReader;
use zeroize::Zeroizing;

/// A witness's private randomness, drawn in blocks of this many bytes, so an
/// operation's seed serves the same bytes however the sampler divides its
/// reads.
const BLOCK_BYTES: usize = 65_520;

pub struct Reader {
    bytes: Zeroizing<Vec<u8>>,
    position: usize,
}
impl Reader {
    pub fn new() -> Self {
        Self {
            bytes: Zeroizing::new(vec![0; BLOCK_BYTES]),
            position: BLOCK_BYTES,
        }
    }
}
impl XofReader for Reader {
    fn read(&mut self, mut output: &mut [u8]) {
        while !output.is_empty() {
            if self.position == self.bytes.len() {
                parallel_work::random::witness(&mut self.bytes);
                self.position = 0;
            }
            let count = output.len().min(self.bytes.len() - self.position);
            output[..count].copy_from_slice(&self.bytes[self.position..self.position + count]);
            self.position += count;
            output = &mut output[count..];
        }
    }
}
