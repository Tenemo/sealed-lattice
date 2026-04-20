pub const MODULE_MARKER: &str = "encoding";
pub const BYTE_BUFFER_CONTRACT_VERSION: &str = "sealed-lattice-m01-byte-buffer-roundtrip-v1";

pub fn roundtrip_bytes(input: &[u8]) -> Vec<u8> {
    input.to_vec()
}

#[cfg(test)]
mod tests {
    use super::roundtrip_bytes;

    #[test]
    fn returns_the_input_bytes_unchanged() {
        assert_eq!(roundtrip_bytes(&[5, 4, 3, 2, 1]), vec![5, 4, 3, 2, 1]);
    }
}
