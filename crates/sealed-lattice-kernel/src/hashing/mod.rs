use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::encoding::{append_bytes, append_varuint};

const HASH512_PREIMAGE_PREFIX: &[u8] = b"sealed.vote/hash512";

pub(crate) fn hash_framed_parts_512(domain: &str, parts: &[&[u8]]) -> [u8; 64] {
    let mut preimage = Vec::new();
    preimage.extend(HASH512_PREIMAGE_PREFIX);
    append_bytes(&mut preimage, domain.as_bytes());
    append_varuint(&mut preimage, parts.len() as u64);
    for part in parts {
        append_bytes(&mut preimage, part);
    }

    let mut hasher = Shake256::default();
    hasher.update(&preimage);
    let mut reader = hasher.finalize_xof();
    let mut output = [0_u8; 64];
    reader.read(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::hash_framed_parts_512;

    #[test]
    fn framing_separates_domains_and_parts() {
        assert_ne!(
            hash_framed_parts_512("first", &[b"same"]),
            hash_framed_parts_512("second", &[b"same"]),
        );
        assert_ne!(
            hash_framed_parts_512("first", &[b"a", b"b"]),
            hash_framed_parts_512("first", &[b"ab"]),
        );
    }
}
