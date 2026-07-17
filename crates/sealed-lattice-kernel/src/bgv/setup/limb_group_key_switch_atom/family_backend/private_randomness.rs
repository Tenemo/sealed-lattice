#[cfg(test)]
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

#[cfg(test)]
use crate::{
    bgv::setup::limb_group_key_switch_atom::proof_field::ProofFieldParameters,
    encoding::{append_bytes, append_varuint},
    hashing::HASH512_PREIMAGE_PREFIX,
};

pub(super) const PROOF_SALT_BYTE_LENGTH: usize = 16;
// Fifteen 64-bit words reduced modulo the largest proof field leave less than
// 2^-180 statistical bias while avoiding a variable-time rejection loop.
#[cfg(test)]
const FIELD_ELEMENT_WORD_COUNT: usize = 15;

#[cfg(test)]
#[derive(Clone)]
pub(super) struct PrivateProofRandomness {
    reader: <Shake256 as ExtendableOutput>::Reader,
    consumed_byte_length: u64,
}

#[cfg(test)]
impl PrivateProofRandomness {
    pub(super) fn new(domain: &str, parts: &[&[u8]]) -> Self {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(HASH512_PREIMAGE_PREFIX);
        append_bytes(&mut preimage, domain.as_bytes());
        append_varuint(&mut preimage, parts.len() as u64);
        for part in parts {
            append_bytes(&mut preimage, part);
        }
        let mut hasher = Shake256::default();
        hasher.update(&preimage);

        Self {
            reader: hasher.finalize_xof(),
            consumed_byte_length: 0,
        }
    }

    pub(super) fn next_field_element<const LIMB_COUNT: usize>(
        &mut self,
        parameters: &ProofFieldParameters<LIMB_COUNT>,
    ) -> [u64; LIMB_COUNT] {
        debug_assert!(LIMB_COUNT > 1);
        parameters.wide_words_to_element((0..FIELD_ELEMENT_WORD_COUNT).map(|_| {
            let mut word_bytes = [0_u8; 8];
            self.read(&mut word_bytes);
            u64::from_le_bytes(word_bytes)
        }))
    }

    pub(super) fn next_salt(&mut self) -> [u8; PROOF_SALT_BYTE_LENGTH] {
        let mut salt = [0_u8; PROOF_SALT_BYTE_LENGTH];
        self.read(&mut salt);
        salt
    }

    pub(super) fn discard_field_elements(&mut self, count: usize) {
        let mut remaining_byte_length = count
            .checked_mul(FIELD_ELEMENT_WORD_COUNT * 8)
            .expect("proof-randomness discard length must fit usize");
        let mut scratch = [0_u8; 1024];
        while remaining_byte_length > 0 {
            let byte_length = remaining_byte_length.min(scratch.len());
            self.read(&mut scratch[..byte_length]);
            remaining_byte_length -= byte_length;
        }
    }

    fn read(&mut self, output: &mut [u8]) {
        self.reader.read(output);
        self.consumed_byte_length = self
            .consumed_byte_length
            .checked_add(output.len() as u64)
            .expect("proof-randomness stream position must fit u64");
    }

    #[cfg(test)]
    pub(super) fn for_test(seed: u64) -> Self {
        Self::new(
            "sealed-lattice/test/key-switch-atom/private-proof-randomness",
            &[&seed.to_le_bytes()],
        )
    }

    #[cfg(test)]
    pub(super) fn consumed_byte_length(&self) -> u64 {
        self.consumed_byte_length
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::setup::limb_group_key_switch_atom::proof_field::sixteen_limb_group_field_parameters;

    #[test]
    fn field_masks_use_the_full_proof_field() {
        let parameters = sixteen_limb_group_field_parameters();
        let mut private_randomness = PrivateProofRandomness::for_test(7);
        let element = private_randomness.next_field_element(&parameters);
        let raw = parameters.to_raw_value(&element);

        assert!(raw[1..].iter().any(|word| *word != 0));
        assert_eq!(
            private_randomness.consumed_byte_length(),
            (FIELD_ELEMENT_WORD_COUNT * 8) as u64
        );
    }
}
