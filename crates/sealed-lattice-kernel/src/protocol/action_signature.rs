use core::fmt;

use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use zeroize::Zeroize;

pub const CHAIN_VALUE_BYTE_LENGTH: usize = 48;
pub const MESSAGE_BYTE_LENGTH: usize = 64;
pub const MESSAGE_CHAIN_COUNT: usize = 128;
pub const CHECKSUM_CHAIN_COUNT: usize = 3;
pub const CHAIN_COUNT: usize = MESSAGE_CHAIN_COUNT + CHECKSUM_CHAIN_COUNT;
pub const KEY_BYTE_LENGTH: usize = CHAIN_COUNT * CHAIN_VALUE_BYTE_LENGTH;
pub const MAXIMUM_FRAGMENT_CHAIN_COUNT: usize = 17;

const WINTERNITZ_BASE: u16 = 16;
const MAXIMUM_CHAIN_STEP_COUNT: u8 = 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionSignatureError {
    EmptyFragment,
    FragmentTooLarge,
    InvalidFragmentLength,
    InvalidFragmentRange,
}

impl fmt::Display for ActionSignatureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyFragment => "action-signature fragment must be nonempty",
            Self::FragmentTooLarge => "action-signature fragment exceeds the scalar-work bound",
            Self::InvalidFragmentLength => {
                "action-signature fragment length is not a whole chain vector"
            }
            Self::InvalidFragmentRange => "action-signature fragment is outside the key range",
        })
    }
}

impl std::error::Error for ActionSignatureError {}

fn fragment_chain_count(
    first_chain: usize,
    fragment_byte_length: usize,
) -> Result<usize, ActionSignatureError> {
    if fragment_byte_length == 0 {
        return Err(ActionSignatureError::EmptyFragment);
    }
    if !fragment_byte_length.is_multiple_of(CHAIN_VALUE_BYTE_LENGTH) {
        return Err(ActionSignatureError::InvalidFragmentLength);
    }
    let chain_count = fragment_byte_length / CHAIN_VALUE_BYTE_LENGTH;
    if chain_count > MAXIMUM_FRAGMENT_CHAIN_COUNT {
        return Err(ActionSignatureError::FragmentTooLarge);
    }
    if first_chain
        .checked_add(chain_count)
        .is_none_or(|end| end > CHAIN_COUNT)
    {
        return Err(ActionSignatureError::InvalidFragmentRange);
    }
    Ok(chain_count)
}

fn chain(mut value: [u8; CHAIN_VALUE_BYTE_LENGTH], step_count: u8) -> [u8; 48] {
    for _ in 0..step_count {
        let mut hasher = Shake256::default();
        hasher.update(&value);
        let mut reader = hasher.finalize_xof();
        reader.read(&mut value);
    }
    value
}

fn message_digits(message: &[u8; MESSAGE_BYTE_LENGTH]) -> [u8; CHAIN_COUNT] {
    let mut digits = [0_u8; CHAIN_COUNT];
    for (byte_index, byte) in message.iter().copied().enumerate() {
        digits[2 * byte_index] = byte >> 4;
        digits[2 * byte_index + 1] = byte & 0x0f;
    }

    let checksum = digits[..MESSAGE_CHAIN_COUNT]
        .iter()
        .fold(0_u16, |sum, digit| {
            sum + (WINTERNITZ_BASE - 1 - u16::from(*digit))
        });
    digits[MESSAGE_CHAIN_COUNT] = ((checksum >> 8) & 0x0f) as u8;
    digits[MESSAGE_CHAIN_COUNT + 1] = ((checksum >> 4) & 0x0f) as u8;
    digits[MESSAGE_CHAIN_COUNT + 2] = (checksum & 0x0f) as u8;
    digits
}

fn transform_fragment(
    first_chain: usize,
    input_fragment: &[u8],
    step_count: impl Fn(usize) -> u8,
) -> Result<Vec<u8>, ActionSignatureError> {
    let chain_count = fragment_chain_count(first_chain, input_fragment.len())?;
    let mut output = Vec::with_capacity(input_fragment.len());
    for local_chain in 0..chain_count {
        let offset = local_chain * CHAIN_VALUE_BYTE_LENGTH;
        let mut value: [u8; CHAIN_VALUE_BYTE_LENGTH] = input_fragment
            [offset..offset + CHAIN_VALUE_BYTE_LENGTH]
            .try_into()
            .map_err(|_| ActionSignatureError::InvalidFragmentLength)?;
        let transformed = chain(value, step_count(first_chain + local_chain));
        value.zeroize();
        output.extend_from_slice(&transformed);
    }
    Ok(output)
}

pub fn derive_verification_key_fragment(
    first_chain: usize,
    secret_fragment: &[u8],
) -> Result<Vec<u8>, ActionSignatureError> {
    transform_fragment(first_chain, secret_fragment, |_| MAXIMUM_CHAIN_STEP_COUNT)
}

pub fn sign_fragment(
    first_chain: usize,
    secret_fragment: &[u8],
    message: &[u8; MESSAGE_BYTE_LENGTH],
) -> Result<Vec<u8>, ActionSignatureError> {
    let digits = message_digits(message);
    transform_fragment(first_chain, secret_fragment, |chain_index| {
        digits[chain_index]
    })
}

pub fn verify_fragment(
    first_chain: usize,
    signature_fragment: &[u8],
    verification_key_fragment: &[u8],
    message: &[u8; MESSAGE_BYTE_LENGTH],
) -> Result<bool, ActionSignatureError> {
    let chain_count = fragment_chain_count(first_chain, signature_fragment.len())?;
    if verification_key_fragment.len() != chain_count * CHAIN_VALUE_BYTE_LENGTH {
        return Err(ActionSignatureError::InvalidFragmentLength);
    }
    let digits = message_digits(message);
    let candidate = transform_fragment(first_chain, signature_fragment, |chain_index| {
        MAXIMUM_CHAIN_STEP_COUNT - digits[chain_index]
    })?;
    let mut difference = 0_u8;
    for (left, right) in candidate.iter().zip(verification_key_fragment) {
        difference |= left ^ right;
    }
    Ok(difference == 0)
}

pub fn verify_complete(
    signature: &[u8],
    verification_key: &[u8],
    message: &[u8; MESSAGE_BYTE_LENGTH],
) -> Result<bool, ActionSignatureError> {
    if signature.len() != KEY_BYTE_LENGTH || verification_key.len() != KEY_BYTE_LENGTH {
        return Err(ActionSignatureError::InvalidFragmentLength);
    }
    for first_chain in (0..CHAIN_COUNT).step_by(MAXIMUM_FRAGMENT_CHAIN_COUNT) {
        let chain_count = MAXIMUM_FRAGMENT_CHAIN_COUNT.min(CHAIN_COUNT - first_chain);
        let start = first_chain * CHAIN_VALUE_BYTE_LENGTH;
        let end = start + chain_count * CHAIN_VALUE_BYTE_LENGTH;
        if !verify_fragment(
            first_chain,
            &signature[start..end],
            &verification_key[start..end],
            message,
        )? {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deterministic_secret_key() -> Vec<u8> {
        (0..KEY_BYTE_LENGTH)
            .map(|index| ((index * 29 + 17) % 251) as u8)
            .collect()
    }

    fn transform_complete(
        input: &[u8],
        operation: impl Fn(usize, &[u8]) -> Result<Vec<u8>, ActionSignatureError>,
    ) -> Vec<u8> {
        let mut output = Vec::with_capacity(KEY_BYTE_LENGTH);
        for first_chain in (0..CHAIN_COUNT).step_by(MAXIMUM_FRAGMENT_CHAIN_COUNT) {
            let chain_count = MAXIMUM_FRAGMENT_CHAIN_COUNT.min(CHAIN_COUNT - first_chain);
            let start = first_chain * CHAIN_VALUE_BYTE_LENGTH;
            let end = start + chain_count * CHAIN_VALUE_BYTE_LENGTH;
            output.extend_from_slice(
                &operation(first_chain, &input[start..end]).expect("fragment transforms"),
            );
        }
        output
    }

    #[test]
    fn complete_signature_round_trip_and_mutations() {
        let secret_key = deterministic_secret_key();
        let message = [0x5a_u8; MESSAGE_BYTE_LENGTH];
        let verification_key = transform_complete(&secret_key, |first_chain, fragment| {
            derive_verification_key_fragment(first_chain, fragment)
        });
        let mut signature = transform_complete(&secret_key, |first_chain, fragment| {
            sign_fragment(first_chain, fragment, &message)
        });

        for first_chain in (0..CHAIN_COUNT).step_by(MAXIMUM_FRAGMENT_CHAIN_COUNT) {
            let chain_count = MAXIMUM_FRAGMENT_CHAIN_COUNT.min(CHAIN_COUNT - first_chain);
            let start = first_chain * CHAIN_VALUE_BYTE_LENGTH;
            let end = start + chain_count * CHAIN_VALUE_BYTE_LENGTH;
            assert!(
                verify_fragment(
                    first_chain,
                    &signature[start..end],
                    &verification_key[start..end],
                    &message,
                )
                .expect("valid fragment")
            );
        }

        signature[47] ^= 1;
        assert!(
            !verify_fragment(
                0,
                &signature[..MAXIMUM_FRAGMENT_CHAIN_COUNT * CHAIN_VALUE_BYTE_LENGTH],
                &verification_key[..MAXIMUM_FRAGMENT_CHAIN_COUNT * CHAIN_VALUE_BYTE_LENGTH],
                &message,
            )
            .expect("mutated fragment is structurally valid")
        );

        let different_message = [0xa5_u8; MESSAGE_BYTE_LENGTH];
        assert!(
            !verify_fragment(
                0,
                &signature[..MAXIMUM_FRAGMENT_CHAIN_COUNT * CHAIN_VALUE_BYTE_LENGTH],
                &verification_key[..MAXIMUM_FRAGMENT_CHAIN_COUNT * CHAIN_VALUE_BYTE_LENGTH],
                &different_message,
            )
            .expect("different-message fragment is structurally valid")
        );
    }

    #[test]
    fn fragment_bounds_fail_before_hashing() {
        assert_eq!(
            derive_verification_key_fragment(0, &[]),
            Err(ActionSignatureError::EmptyFragment)
        );
        assert_eq!(
            derive_verification_key_fragment(0, &[0_u8; CHAIN_VALUE_BYTE_LENGTH + 1]),
            Err(ActionSignatureError::InvalidFragmentLength)
        );
        assert_eq!(
            derive_verification_key_fragment(
                0,
                &[0_u8; (MAXIMUM_FRAGMENT_CHAIN_COUNT + 1) * CHAIN_VALUE_BYTE_LENGTH],
            ),
            Err(ActionSignatureError::FragmentTooLarge)
        );
        assert_eq!(
            derive_verification_key_fragment(CHAIN_COUNT, &[0_u8; CHAIN_VALUE_BYTE_LENGTH],),
            Err(ActionSignatureError::InvalidFragmentRange)
        );
    }
}
