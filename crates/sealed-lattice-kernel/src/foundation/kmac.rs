use sha3::{
    CShake256, CShake256Core,
    digest::{ExtendableOutput, Update, XofReader},
};
use zeroize::Zeroize;

const KMAC256_RATE_BYTE_LENGTH: usize = 136;

fn left_encode(value: usize) -> Vec<u8> {
    let value = value as u64;
    let byte_length = (64 - value.leading_zeros() as usize).max(1).div_ceil(8);
    let mut encoded = Vec::with_capacity(byte_length + 1);
    encoded.push(byte_length as u8);
    encoded.extend_from_slice(&value.to_be_bytes()[8 - byte_length..]);
    encoded
}

fn right_encode(value: usize) -> Vec<u8> {
    let value = value as u64;
    let byte_length = (64 - value.leading_zeros() as usize).max(1).div_ceil(8);
    let mut encoded = Vec::with_capacity(byte_length + 1);
    encoded.extend_from_slice(&value.to_be_bytes()[8 - byte_length..]);
    encoded.push(byte_length as u8);
    encoded
}

fn encode_string(value: &[u8]) -> Vec<u8> {
    let mut encoded = left_encode(value.len() * 8);
    encoded.extend_from_slice(value);
    encoded
}

fn bytepad(value: &[u8], width: usize) -> Vec<u8> {
    let mut encoded = left_encode(width);
    encoded.extend_from_slice(value);
    let padding = (width - encoded.len() % width) % width;
    encoded.resize(encoded.len() + padding, 0);
    encoded
}

pub(crate) fn kmac256<const LENGTH: usize>(
    key: &[u8],
    message: &[u8],
    customization: &[u8],
) -> [u8; LENGTH] {
    let mut encoded_key = encode_string(key);
    let mut input = bytepad(&encoded_key, KMAC256_RATE_BYTE_LENGTH);
    encoded_key.zeroize();
    input.extend_from_slice(message);
    input.extend_from_slice(&right_encode(LENGTH * 8));
    let core = CShake256Core::new_with_function_name(b"KMAC", customization);
    let mut hasher = CShake256::from_core(core);
    hasher.update(&input);
    let mut reader = hasher.finalize_xof();
    let mut output = [0_u8; LENGTH];
    reader.read(&mut output);
    input.zeroize();
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex<const BYTE_LENGTH: usize>(hex: &str) -> [u8; BYTE_LENGTH] {
        assert_eq!(hex.len(), 2 * BYTE_LENGTH);
        core::array::from_fn(|index| {
            u8::from_str_radix(&hex[2 * index..2 * index + 2], 16).expect("valid hex")
        })
    }

    #[test]
    fn matches_nist_sp_800_185_sample_six() {
        let key =
            decode_hex::<32>("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
        let message = decode_hex::<200>(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
             404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f\
             606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
             808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
             a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf\
             c0c1c2c3c4c5c6c7",
        );
        let expected = decode_hex::<64>(
            "b58618f71f92e1d56c1b8c55ddd7cd188b97b4ca4d99831eb2699a837da2e4d9\
             70fbacfde50033aea585f1a2708510c32d07880801bd182898fe476876fc8965",
        );
        assert_eq!(kmac256(&key, &message, b"My Tagged Application"), expected);
    }
}
