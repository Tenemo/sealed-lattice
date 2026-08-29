use sha3::{
    CShake256, CShake256Core,
    digest::{ExtendableOutput, Update, XofReader},
};
use zeroize::Zeroizing;

use crate::foundation::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalCodecError, CanonicalItem,
    CanonicalTuple, Hash512,
};

pub(crate) const LPSY15_BMR_PRF_KEY_BYTE_LENGTH: usize = 40;
pub(crate) const LPSY15_BMR_PRF_OUTPUT_BYTE_LENGTH: usize = 40;
pub(crate) const LPSY15_BMR_PRF_RIGHT_ENCODE_BYTE_LENGTH: usize = 3;
pub(crate) const LPSY15_BMR_PRF_CUSTOMIZATION: &[u8] = b"sealed-lattice/v1/lpsy15/bmr-prf";
pub(crate) const LPSY15_BMR_PRF_MESSAGE_DOMAIN: &str =
    "sealed-lattice/v1/preparation/lpsy15-bmr-prf-input";

const CSHAKE256_RATE_BYTE_LENGTH: usize = 136;
const ENCODED_CSHAKE256_RATE: [u8; 2] = [1, 136];
const ENCODED_320_BIT_KEY_LENGTH: [u8; 3] = [2, 1, 64];

/// Canonical public coordinate absorbed by one published LPSY15 BMR PRF call.
///
/// Key owner and semantic alternative are bound by the selected 40-byte key,
/// while every public predecessor and table coordinate is bound here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Lpsy15BmrPrfInput {
    pub(crate) candidate_identity: Hash512,
    pub(crate) roster_root: Hash512,
    pub(crate) circuit_identity: Hash512,
    pub(crate) preparation_attempt_root: Hash512,
    pub(crate) complete_predecessor_root: Hash512,
    pub(crate) gate_index: u32,
    pub(crate) input_side: u16,
    pub(crate) output_component: u16,
    pub(crate) branch: u16,
}

impl Lpsy15BmrPrfInput {
    pub(crate) fn canonical_message_bytes(self) -> Result<Vec<u8>, CanonicalCodecError> {
        CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(LPSY15_BMR_PRF_MESSAGE_DOMAIN)?,
                CanonicalItem::hash512(self.candidate_identity.into_bytes()),
                CanonicalItem::hash512(self.roster_root.into_bytes()),
                CanonicalItem::hash512(self.circuit_identity.into_bytes()),
                CanonicalItem::hash512(self.preparation_attempt_root.into_bytes()),
                CanonicalItem::hash512(self.complete_predecessor_root.into_bytes()),
                CanonicalItem::unsigned32(self.gate_index),
                CanonicalItem::unsigned16(self.input_side),
                CanonicalItem::unsigned16(self.output_component),
                CanonicalItem::unsigned16(self.branch),
            ],
        )
        .encode()
    }
}

pub(crate) fn evaluate_lpsy15_bmr_prf(
    key: &[u8; LPSY15_BMR_PRF_KEY_BYTE_LENGTH],
    input: Lpsy15BmrPrfInput,
) -> Result<Zeroizing<[u8; LPSY15_BMR_PRF_OUTPUT_BYTE_LENGTH]>, CanonicalCodecError> {
    let message = Zeroizing::new(input.canonical_message_bytes()?);
    Ok(fixed_output_kmac256(
        key,
        LPSY15_BMR_PRF_CUSTOMIZATION,
        &message,
    ))
}

pub(crate) fn fixed_output_kmac256<const OUTPUT_BYTE_LENGTH: usize>(
    key: &[u8; LPSY15_BMR_PRF_KEY_BYTE_LENGTH],
    customization: &[u8],
    message: &[u8],
) -> Zeroizing<[u8; OUTPUT_BYTE_LENGTH]> {
    let mut padded_key = Zeroizing::new([0_u8; CSHAKE256_RATE_BYTE_LENGTH]);
    let encoded_key_start = ENCODED_CSHAKE256_RATE.len();
    let key_start = encoded_key_start + ENCODED_320_BIT_KEY_LENGTH.len();
    let key_end = key_start + key.len();
    padded_key[..encoded_key_start].copy_from_slice(&ENCODED_CSHAKE256_RATE);
    padded_key[encoded_key_start..key_start].copy_from_slice(&ENCODED_320_BIT_KEY_LENGTH);
    padded_key[key_start..key_end].copy_from_slice(key);

    let output_bit_length = OUTPUT_BYTE_LENGTH
        .checked_mul(8)
        .and_then(|value| u64::try_from(value).ok())
        .expect("candidate fixed-output KMAC width fits u64");
    let encoded_integer_byte_length =
        usize::try_from((u64::BITS - output_bit_length.leading_zeros()).div_ceil(u8::BITS))
            .expect("right-encoded integer width fits usize")
            .max(1);
    let mut right_encoded_output_bit_length = [0_u8; 9];
    let integer_start = 8 - encoded_integer_byte_length;
    right_encoded_output_bit_length[integer_start..8]
        .copy_from_slice(&output_bit_length.to_be_bytes()[integer_start..]);
    right_encoded_output_bit_length[8] =
        u8::try_from(encoded_integer_byte_length).expect("u64 uses at most eight bytes");

    let mut kmac = CShake256::from_core(CShake256Core::new_with_function_name(
        b"KMAC",
        customization,
    ));
    kmac.update(padded_key.as_ref());
    kmac.update(message);
    kmac.update(&right_encoded_output_bit_length[integer_start..]);
    let mut output = Zeroizing::new([0_u8; OUTPUT_BYTE_LENGTH]);
    kmac.finalize_xof().read(output.as_mut());
    output
}
