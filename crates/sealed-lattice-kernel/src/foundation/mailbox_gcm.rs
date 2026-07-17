use aes::{
    Aes256,
    cipher::{BlockEncrypt, KeyInit as AesKeyInit, KeyIvInit, StreamCipher},
};
use ctr::Ctr32BE;
use ghash::{
    GHash,
    universal_hash::{KeyInit as UniversalHashKeyInit, UniversalHash},
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use super::authenticated_mailbox::MAILBOX_GCM_TAG_BYTE_LENGTH;
use super::schemas::SchemaResult;
use super::{FoundationSchemaError, MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH, RefusalReason};

pub(crate) const MAILBOX_GCM_KEY_BYTE_LENGTH: usize = 32;
pub(crate) const MAILBOX_GCM_NONCE_BYTE_LENGTH: usize = 12;

const GCM_BLOCK_BYTE_LENGTH: usize = 16;

type Aes256Counter = Ctr32BE<Aes256>;

struct MailboxGcmAuthentication {
    associated_data_byte_length: u64,
    authenticated_ciphertext_byte_length: u64,
    expected_ciphertext_byte_length: u64,
    ghash: GHash,
    partial_ciphertext_block: Zeroizing<[u8; GCM_BLOCK_BYTE_LENGTH]>,
    partial_ciphertext_byte_length: usize,
    tag_mask: Zeroizing<[u8; GCM_BLOCK_BYTE_LENGTH]>,
}

impl MailboxGcmAuthentication {
    fn new(
        key: &[u8; MAILBOX_GCM_KEY_BYTE_LENGTH],
        nonce: &[u8; MAILBOX_GCM_NONCE_BYTE_LENGTH],
        associated_data: &[u8],
        expected_ciphertext_byte_length: u64,
    ) -> SchemaResult<(Self, Aes256Counter)> {
        require_safe_length(expected_ciphertext_byte_length)?;

        let cipher = Aes256::new_from_slice(key).map_err(|_| {
            schema_error(
                RefusalReason::WrongTypeOrLength,
                "mailbox AES-GCM key has the wrong length",
            )
        })?;
        let mut hash_subkey = aes::cipher::Block::<Aes256>::default();
        cipher.encrypt_block(&mut hash_subkey);
        let mut ghash =
            <GHash as UniversalHashKeyInit>::new_from_slice(&hash_subkey).map_err(|_| {
                schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "mailbox GHASH key has the wrong length",
                )
            })?;
        hash_subkey.as_mut_slice().zeroize();
        ghash.update_padded(associated_data);

        let mut initial_counter_block = Zeroizing::new([0_u8; GCM_BLOCK_BYTE_LENGTH]);
        initial_counter_block[..MAILBOX_GCM_NONCE_BYTE_LENGTH].copy_from_slice(nonce);
        initial_counter_block[GCM_BLOCK_BYTE_LENGTH - 1] = 1;
        let mut counter = Aes256Counter::new_from_slices(key, initial_counter_block.as_slice())
            .map_err(|_| {
                schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "mailbox AES-GCM counter input has the wrong length",
                )
            })?;
        let mut tag_mask = Zeroizing::new([0_u8; GCM_BLOCK_BYTE_LENGTH]);
        counter
            .try_apply_keystream(tag_mask.as_mut_slice())
            .map_err(|_| {
                schema_error(
                    RefusalReason::OutsideSupportedProfile,
                    "mailbox AES-GCM counter space is exhausted",
                )
            })?;

        let associated_data_byte_length = u64::try_from(associated_data.len()).map_err(|_| {
            schema_error(
                RefusalReason::OutsideSupportedProfile,
                "mailbox associated data exceeds the supported length",
            )
        })?;
        associated_data_byte_length.checked_mul(8).ok_or_else(|| {
            schema_error(
                RefusalReason::OutsideSupportedProfile,
                "mailbox associated-data bit length overflows",
            )
        })?;

        Ok((
            Self {
                associated_data_byte_length,
                authenticated_ciphertext_byte_length: 0,
                expected_ciphertext_byte_length,
                ghash,
                partial_ciphertext_block: Zeroizing::new([0_u8; GCM_BLOCK_BYTE_LENGTH]),
                partial_ciphertext_byte_length: 0,
                tag_mask,
            },
            counter,
        ))
    }

    fn absorb_ciphertext(&mut self, ciphertext: &[u8]) -> SchemaResult<()> {
        let ciphertext_byte_length = u64::try_from(ciphertext.len()).map_err(|_| {
            schema_error(
                RefusalReason::OutsideSupportedProfile,
                "mailbox ciphertext chunk exceeds the supported length",
            )
        })?;
        let next_authenticated_byte_length = self
            .authenticated_ciphertext_byte_length
            .checked_add(ciphertext_byte_length)
            .ok_or_else(|| {
                schema_error(
                    RefusalReason::OutsideSupportedProfile,
                    "mailbox ciphertext length overflows",
                )
            })?;
        if next_authenticated_byte_length > self.expected_ciphertext_byte_length {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "mailbox ciphertext exceeds its authenticated length",
            ));
        }

        let mut remaining = ciphertext;
        if self.partial_ciphertext_byte_length != 0 {
            let required_byte_length = GCM_BLOCK_BYTE_LENGTH - self.partial_ciphertext_byte_length;
            let copied_byte_length = required_byte_length.min(remaining.len());
            self.partial_ciphertext_block[self.partial_ciphertext_byte_length
                ..self.partial_ciphertext_byte_length + copied_byte_length]
                .copy_from_slice(&remaining[..copied_byte_length]);
            self.partial_ciphertext_byte_length += copied_byte_length;
            remaining = &remaining[copied_byte_length..];
            if self.partial_ciphertext_byte_length == GCM_BLOCK_BYTE_LENGTH {
                self.ghash.update(&[ghash::Block::clone_from_slice(
                    self.partial_ciphertext_block.as_slice(),
                )]);
                self.partial_ciphertext_block.fill(0);
                self.partial_ciphertext_byte_length = 0;
            }
        }

        let complete_byte_length = remaining.len() - (remaining.len() % GCM_BLOCK_BYTE_LENGTH);
        if complete_byte_length != 0 {
            self.ghash.update_padded(&remaining[..complete_byte_length]);
            remaining = &remaining[complete_byte_length..];
        }
        if !remaining.is_empty() {
            self.partial_ciphertext_block[..remaining.len()].copy_from_slice(remaining);
            self.partial_ciphertext_byte_length = remaining.len();
        }

        self.authenticated_ciphertext_byte_length = next_authenticated_byte_length;
        Ok(())
    }

    fn finish(mut self) -> SchemaResult<[u8; MAILBOX_GCM_TAG_BYTE_LENGTH]> {
        if self.authenticated_ciphertext_byte_length != self.expected_ciphertext_byte_length {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "mailbox ciphertext is shorter than its authenticated length",
            ));
        }
        if self.partial_ciphertext_byte_length != 0 {
            self.ghash.update(&[ghash::Block::clone_from_slice(
                self.partial_ciphertext_block.as_slice(),
            )]);
        }

        let associated_data_bit_length = self
            .associated_data_byte_length
            .checked_mul(8)
            .ok_or_else(|| {
                schema_error(
                    RefusalReason::OutsideSupportedProfile,
                    "mailbox associated-data bit length overflows",
                )
            })?;
        let ciphertext_bit_length = self
            .authenticated_ciphertext_byte_length
            .checked_mul(8)
            .ok_or_else(|| {
                schema_error(
                    RefusalReason::OutsideSupportedProfile,
                    "mailbox ciphertext bit length overflows",
                )
            })?;
        let mut length_block = Zeroizing::new([0_u8; GCM_BLOCK_BYTE_LENGTH]);
        length_block[..8].copy_from_slice(&associated_data_bit_length.to_be_bytes());
        length_block[8..].copy_from_slice(&ciphertext_bit_length.to_be_bytes());
        self.ghash
            .update(&[ghash::Block::clone_from_slice(length_block.as_slice())]);

        let mut tag = self.ghash.finalize();
        for (tag_byte, mask_byte) in tag.iter_mut().zip(self.tag_mask.iter()) {
            *tag_byte ^= *mask_byte;
        }
        let mut output = [0_u8; MAILBOX_GCM_TAG_BYTE_LENGTH];
        output.copy_from_slice(tag.as_slice());
        tag.as_mut_slice().zeroize();
        Ok(output)
    }
}

pub(crate) struct MailboxGcmEncryptor {
    authentication: MailboxGcmAuthentication,
    counter: Aes256Counter,
}

impl MailboxGcmEncryptor {
    pub(crate) fn new(
        key: [u8; MAILBOX_GCM_KEY_BYTE_LENGTH],
        nonce: [u8; MAILBOX_GCM_NONCE_BYTE_LENGTH],
        associated_data: &[u8],
        expected_plaintext_byte_length: u64,
    ) -> SchemaResult<Self> {
        let key = Zeroizing::new(key);
        let (authentication, counter) = MailboxGcmAuthentication::new(
            &key,
            &nonce,
            associated_data,
            expected_plaintext_byte_length,
        )?;
        Ok(Self {
            authentication,
            counter,
        })
    }

    pub(crate) fn encrypt_chunk(&mut self, plaintext: &mut [u8]) -> SchemaResult<()> {
        self.counter.try_apply_keystream(plaintext).map_err(|_| {
            plaintext.zeroize();
            schema_error(
                RefusalReason::OutsideSupportedProfile,
                "mailbox AES-GCM counter space is exhausted",
            )
        })?;
        self.authentication.absorb_ciphertext(plaintext)
    }

    pub(crate) fn finish(self) -> SchemaResult<[u8; MAILBOX_GCM_TAG_BYTE_LENGTH]> {
        self.authentication.finish()
    }
}

pub(crate) struct MailboxGcmVerifier {
    authentication: MailboxGcmAuthentication,
    key: Zeroizing<[u8; MAILBOX_GCM_KEY_BYTE_LENGTH]>,
    nonce: [u8; MAILBOX_GCM_NONCE_BYTE_LENGTH],
}

impl MailboxGcmVerifier {
    pub(crate) fn new(
        key: [u8; MAILBOX_GCM_KEY_BYTE_LENGTH],
        nonce: [u8; MAILBOX_GCM_NONCE_BYTE_LENGTH],
        associated_data: &[u8],
        expected_ciphertext_byte_length: u64,
    ) -> SchemaResult<Self> {
        let key = Zeroizing::new(key);
        let (authentication, unused_counter) = MailboxGcmAuthentication::new(
            &key,
            &nonce,
            associated_data,
            expected_ciphertext_byte_length,
        )?;
        drop(unused_counter);
        Ok(Self {
            authentication,
            key,
            nonce,
        })
    }

    pub(crate) fn absorb_ciphertext(&mut self, ciphertext: &[u8]) -> SchemaResult<()> {
        self.authentication.absorb_ciphertext(ciphertext)
    }

    pub(crate) fn finish(
        self,
        expected_tag: &[u8; MAILBOX_GCM_TAG_BYTE_LENGTH],
    ) -> SchemaResult<VerifiedMailboxGcmOpening> {
        let Self {
            authentication,
            key,
            nonce,
        } = self;
        let expected_ciphertext_byte_length = authentication.expected_ciphertext_byte_length;
        let computed_tag = Zeroizing::new(authentication.finish()?);
        if !bool::from(computed_tag.as_slice().ct_eq(expected_tag.as_slice())) {
            return Err(schema_error(
                RefusalReason::InvalidArithmeticRelation,
                "mailbox AES-GCM authentication failed",
            ));
        }
        Ok(VerifiedMailboxGcmOpening {
            expected_ciphertext_byte_length,
            key,
            nonce,
        })
    }
}

pub(crate) struct VerifiedMailboxGcmOpening {
    expected_ciphertext_byte_length: u64,
    key: Zeroizing<[u8; MAILBOX_GCM_KEY_BYTE_LENGTH]>,
    nonce: [u8; MAILBOX_GCM_NONCE_BYTE_LENGTH],
}

impl VerifiedMailboxGcmOpening {
    pub(crate) fn begin_decryption(self) -> SchemaResult<MailboxGcmDecryptor> {
        let mut initial_counter_block = Zeroizing::new([0_u8; GCM_BLOCK_BYTE_LENGTH]);
        initial_counter_block[..MAILBOX_GCM_NONCE_BYTE_LENGTH].copy_from_slice(&self.nonce);
        initial_counter_block[GCM_BLOCK_BYTE_LENGTH - 1] = 1;
        let mut counter =
            Aes256Counter::new_from_slices(self.key.as_slice(), initial_counter_block.as_slice())
                .map_err(|_| {
                schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "mailbox AES-GCM counter input has the wrong length",
                )
            })?;
        let mut discarded_tag_mask = Zeroizing::new([0_u8; GCM_BLOCK_BYTE_LENGTH]);
        counter
            .try_apply_keystream(discarded_tag_mask.as_mut_slice())
            .map_err(|_| {
                schema_error(
                    RefusalReason::OutsideSupportedProfile,
                    "mailbox AES-GCM counter space is exhausted",
                )
            })?;
        Ok(MailboxGcmDecryptor {
            counter,
            decrypted_ciphertext_byte_length: 0,
            expected_ciphertext_byte_length: self.expected_ciphertext_byte_length,
        })
    }
}

pub(crate) struct MailboxGcmDecryptor {
    counter: Aes256Counter,
    decrypted_ciphertext_byte_length: u64,
    expected_ciphertext_byte_length: u64,
}

impl MailboxGcmDecryptor {
    pub(crate) fn decrypt_chunk(&mut self, ciphertext: &mut [u8]) -> SchemaResult<()> {
        let ciphertext_byte_length = u64::try_from(ciphertext.len()).map_err(|_| {
            schema_error(
                RefusalReason::OutsideSupportedProfile,
                "mailbox ciphertext chunk exceeds the supported length",
            )
        })?;
        let next_decrypted_byte_length = self
            .decrypted_ciphertext_byte_length
            .checked_add(ciphertext_byte_length)
            .ok_or_else(|| {
                schema_error(
                    RefusalReason::OutsideSupportedProfile,
                    "mailbox ciphertext length overflows",
                )
            })?;
        if next_decrypted_byte_length > self.expected_ciphertext_byte_length {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "mailbox ciphertext exceeds its authenticated length",
            ));
        }
        self.counter.try_apply_keystream(ciphertext).map_err(|_| {
            ciphertext.zeroize();
            schema_error(
                RefusalReason::OutsideSupportedProfile,
                "mailbox AES-GCM counter space is exhausted",
            )
        })?;
        self.decrypted_ciphertext_byte_length = next_decrypted_byte_length;
        Ok(())
    }

    pub(crate) fn finish(self) -> SchemaResult<()> {
        if self.decrypted_ciphertext_byte_length != self.expected_ciphertext_byte_length {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "mailbox ciphertext is shorter than its authenticated length",
            ));
        }
        Ok(())
    }
}

fn require_safe_length(byte_length: u64) -> SchemaResult<()> {
    if byte_length == 0 || byte_length > MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH {
        return Err(schema_error(
            RefusalReason::OutsideSupportedProfile,
            "mailbox ciphertext length exceeds the canonical stream safety bound",
        ));
    }
    byte_length.checked_mul(8).ok_or_else(|| {
        schema_error(
            RefusalReason::OutsideSupportedProfile,
            "mailbox ciphertext bit length overflows",
        )
    })?;
    Ok(())
}

fn schema_error(refusal_reason: RefusalReason, message: &'static str) -> FoundationSchemaError {
    FoundationSchemaError::new(refusal_reason, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex<const BYTE_LENGTH: usize>(hex: &str) -> [u8; BYTE_LENGTH] {
        assert_eq!(hex.len(), BYTE_LENGTH * 2);
        let mut bytes = [0_u8; BYTE_LENGTH];
        for (byte, pair) in bytes.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
            *byte = u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII hex"), 16)
                .expect("valid hex");
        }
        bytes
    }

    fn encrypt_with_fragments(
        key: [u8; MAILBOX_GCM_KEY_BYTE_LENGTH],
        nonce: [u8; MAILBOX_GCM_NONCE_BYTE_LENGTH],
        associated_data: &[u8],
        plaintext: &[u8],
        fragment_byte_length: usize,
    ) -> (Vec<u8>, [u8; MAILBOX_GCM_TAG_BYTE_LENGTH]) {
        let mut ciphertext = plaintext.to_vec();
        let mut encryptor = MailboxGcmEncryptor::new(
            key,
            nonce,
            associated_data,
            u64::try_from(plaintext.len()).expect("test length"),
        )
        .expect("encryptor starts");
        for fragment in ciphertext.chunks_mut(fragment_byte_length) {
            encryptor
                .encrypt_chunk(fragment)
                .expect("fragment encrypts");
        }
        let tag = encryptor.finish().expect("encryption finishes");
        (ciphertext, tag)
    }

    #[test]
    fn matches_nist_aes_256_gcm_single_block_vector_for_every_fragmentation() {
        let expected_ciphertext = decode_hex::<16>("cea7403d4d606b6e074ec5d3baf39d18");
        let expected_tag = decode_hex::<16>("d0d1c8a799996bf0265b98b5d48ab919");
        for fragment_byte_length in 1..=16 {
            let (ciphertext, tag) = encrypt_with_fragments(
                [0_u8; 32],
                [0_u8; 12],
                &[],
                &[0_u8; 16],
                fragment_byte_length,
            );
            assert_eq!(ciphertext, expected_ciphertext);
            assert_eq!(tag, expected_tag);
        }
    }

    #[test]
    fn matches_nist_gcm_aes_256_example_five_for_every_fragmentation() {
        // NIST's published GCM-AES256 Example 5: 160 AAD bits, 480 plaintext
        // bits, and a 128-bit tag.
        let key =
            decode_hex::<32>("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        let nonce = decode_hex::<12>("cafebabefacedbaddecaf888");
        let associated_data = decode_hex::<20>("3ad77bb40d7a3660a89ecaf32466ef97f5d3d585");
        let plaintext = decode_hex::<60>(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        );
        let expected_ciphertext = decode_hex::<60>(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
             8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        );
        let expected_tag = decode_hex::<16>("e097195f4532da895fb917a5a55c6aa0");

        for fragment_byte_length in [1, 2, 15, 16, 17, 31, 60] {
            let (ciphertext, tag) = encrypt_with_fragments(
                key,
                nonce,
                &associated_data,
                &plaintext,
                fragment_byte_length,
            );
            assert_eq!(ciphertext, expected_ciphertext);
            assert_eq!(tag, expected_tag);
        }
    }

    #[test]
    fn authenticates_before_issuing_a_decryptor_and_preserves_fragment_positions() {
        let key = [0x29_u8; 32];
        let nonce = [0x71_u8; 12];
        let associated_data = b"canonical mailbox associated data";
        let plaintext = (0_u16..=1024)
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let (ciphertext, tag) = encrypt_with_fragments(key, nonce, associated_data, &plaintext, 17);

        for authentication_fragment_byte_length in [1, 7, 16, 31, 257] {
            let mut verifier = MailboxGcmVerifier::new(
                key,
                nonce,
                associated_data,
                u64::try_from(ciphertext.len()).expect("test length"),
            )
            .expect("verifier starts");
            for fragment in ciphertext.chunks(authentication_fragment_byte_length) {
                verifier
                    .absorb_ciphertext(fragment)
                    .expect("ciphertext authenticates incrementally");
            }
            let opening = verifier.finish(&tag).expect("tag authenticates");
            let mut opened = ciphertext.clone();
            let mut decryptor = opening.begin_decryption().expect("decryptor starts");
            for fragment in opened.chunks_mut(13) {
                decryptor
                    .decrypt_chunk(fragment)
                    .expect("ciphertext decrypts incrementally");
            }
            decryptor.finish().expect("decryption finishes");
            assert_eq!(opened, plaintext);
        }

        let mut verifier = MailboxGcmVerifier::new(
            key,
            nonce,
            associated_data,
            u64::try_from(ciphertext.len()).expect("test length"),
        )
        .expect("verifier starts");
        verifier
            .absorb_ciphertext(&ciphertext)
            .expect("ciphertext authenticates");
        let mut tampered_tag = tag;
        tampered_tag[9] ^= 0x80;
        let error = verifier
            .finish(&tampered_tag)
            .err()
            .expect("tampered tag refuses before decryptor issuance");
        assert_eq!(
            error.refusal_reason,
            RefusalReason::InvalidArithmeticRelation
        );
    }

    #[test]
    fn rejects_short_overlong_and_empty_streams_at_the_exact_boundary() {
        assert_eq!(
            MailboxGcmEncryptor::new([0_u8; 32], [0_u8; 12], &[], 0)
                .err()
                .expect("empty stream refuses")
                .refusal_reason,
            RefusalReason::OutsideSupportedProfile
        );

        let mut short =
            MailboxGcmEncryptor::new([0_u8; 32], [0_u8; 12], &[], 17).expect("encryptor starts");
        short
            .encrypt_chunk(&mut [0_u8; 16])
            .expect("prefix encrypts");
        assert_eq!(
            short
                .finish()
                .expect_err("short stream refuses")
                .refusal_reason,
            RefusalReason::WrongTypeOrLength
        );

        let mut overlong =
            MailboxGcmVerifier::new([0_u8; 32], [0_u8; 12], &[], 16).expect("verifier starts");
        assert_eq!(
            overlong
                .absorb_ciphertext(&[0_u8; 17])
                .expect_err("overlong stream refuses")
                .refusal_reason,
            RefusalReason::WrongTypeOrLength
        );
    }
}
