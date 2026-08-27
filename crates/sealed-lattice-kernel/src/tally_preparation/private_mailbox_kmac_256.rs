use sha3::{
    CShake256, CShake256Core,
    digest::{ExtendableOutput, Update, XofReader},
};
use zeroize::Zeroizing;

const CSHAKE256_RATE_BYTE_LENGTH: usize = 136;
const ENCODED_CSHAKE256_RATE: [u8; 2] = [1, 136];
const ENCODED_256_BIT_KEY_LENGTH: [u8; 3] = [2, 1, 0];
const RIGHT_ENCODED_256_BIT_OUTPUT_LENGTH: [u8; 3] = [1, 0, 2];
const RIGHT_ENCODED_96_BIT_OUTPUT_LENGTH: [u8; 2] = [96, 1];

/// Exact fixed-output KMAC256 operation used for private-mailbox AEAD keys.
///
/// The 32-byte key and 32-byte output are deliberately fixed here. This is
/// SP 800-108 fixed-output KMAC framing, not a variable-output stream.
pub(crate) fn derive_private_mailbox_key_256(
    key: &[u8; 32],
    customization: &[u8],
    context: &[u8],
) -> Zeroizing<[u8; 32]> {
    let mut output = Zeroizing::new([0_u8; 32]);
    derive_private_mailbox_kmac_256(
        key,
        customization,
        context,
        &RIGHT_ENCODED_256_BIT_OUTPUT_LENGTH,
        output.as_mut(),
    );
    output
}

/// Exact fixed-output KMAC256 operation used for private-mailbox AEAD nonces.
pub(crate) fn derive_private_mailbox_nonce_96(
    key: &[u8; 32],
    customization: &[u8],
    context: &[u8],
) -> Zeroizing<[u8; 12]> {
    let mut output = Zeroizing::new([0_u8; 12]);
    derive_private_mailbox_kmac_256(
        key,
        customization,
        context,
        &RIGHT_ENCODED_96_BIT_OUTPUT_LENGTH,
        output.as_mut(),
    );
    output
}

fn derive_private_mailbox_kmac_256(
    key: &[u8; 32],
    customization: &[u8],
    context: &[u8],
    right_encoded_output_bit_length: &[u8],
    output: &mut [u8],
) {
    let mut padded_key = Zeroizing::new([0_u8; CSHAKE256_RATE_BYTE_LENGTH]);
    let encoded_key_start = ENCODED_CSHAKE256_RATE.len();
    let key_start = encoded_key_start + ENCODED_256_BIT_KEY_LENGTH.len();
    let key_end = key_start + key.len();
    padded_key[..encoded_key_start].copy_from_slice(&ENCODED_CSHAKE256_RATE);
    padded_key[encoded_key_start..key_start].copy_from_slice(&ENCODED_256_BIT_KEY_LENGTH);
    padded_key[key_start..key_end].copy_from_slice(key);

    let mut derivation = CShake256::from_core(CShake256Core::new_with_function_name(
        b"KMAC",
        customization,
    ));
    derivation.update(padded_key.as_ref());
    derivation.update(context);
    derivation.update(right_encoded_output_bit_length);
    derivation.finalize_xof().read(output);
}
