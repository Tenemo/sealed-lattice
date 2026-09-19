use sha3::digest::XofReader;
use zeroize::Zeroizing;

pub struct Reader {
    bytes: Zeroizing<Vec<u8>>,
    position: usize,
}
impl Reader {
    pub fn new() -> Self {
        Self {
            bytes: Zeroizing::new(vec![0; 65520]),
            position: 65520,
        }
    }
}
impl XofReader for Reader {
    fn read(&mut self, mut output: &mut [u8]) {
        #[link(wasm_import_module = "setup_witness")]
        unsafe extern "C" {
            fn fill_random(pointer: *mut u8, length: usize) -> u32;
        }
        while !output.is_empty() {
            if self.position == self.bytes.len() {
                // The browser writes exactly this live, exclusively owned buffer.
                assert_eq!(
                    unsafe { fill_random(self.bytes.as_mut_ptr(), self.bytes.len()) },
                    0
                );
                self.position = 0;
            }
            let count = output.len().min(self.bytes.len() - self.position);
            output[..count].copy_from_slice(&self.bytes[self.position..self.position + count]);
            self.position += count;
            output = &mut output[count..];
        }
    }
}
