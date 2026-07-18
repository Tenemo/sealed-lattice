//! Bounded browser/WASM encoding for the exact selected foundation roster.

use core::{mem::size_of, slice};

use super::runtime_input::refusal_status;
use super::{
    FOUNDATION_PROFILE, ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH,
    ML_KEM_768_ENCAPSULATION_KEY_BYTE_LENGTH, RefusalReason, Roster, RosterEntry,
};

const ROSTER_POSITION_BYTE_LENGTH: usize = size_of::<u16>();
const ROSTER_ENTRY_INPUT_BYTE_LENGTH: usize = ROSTER_POSITION_BYTE_LENGTH
    + ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH
    + ML_KEM_768_ENCAPSULATION_KEY_BYTE_LENGTH;

fn encode_selected_roster(input_bytes: &[u8]) -> Result<Vec<u8>, u32> {
    let expected_byte_length = usize::from(FOUNDATION_PROFILE.participant_count)
        .checked_mul(ROSTER_ENTRY_INPUT_BYTE_LENGTH)
        .ok_or_else(|| refusal_status(RefusalReason::OutsideSupportedProfile))?;
    if input_bytes.len() != expected_byte_length {
        return Err(refusal_status(RefusalReason::WrongTypeOrLength));
    }

    let mut entries = Vec::with_capacity(usize::from(FOUNDATION_PROFILE.participant_count));
    for input_entry in input_bytes.chunks_exact(ROSTER_ENTRY_INPUT_BYTE_LENGTH) {
        let roster_position = u16::from_le_bytes(
            input_entry[..ROSTER_POSITION_BYTE_LENGTH]
                .try_into()
                .map_err(|_| refusal_status(RefusalReason::WrongTypeOrLength))?,
        );
        let signing_key_start = ROSTER_POSITION_BYTE_LENGTH;
        let signing_key_end = signing_key_start + ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH;
        let signing_verification_key =
            input_entry[signing_key_start..signing_key_end]
                .try_into()
                .map_err(|_| refusal_status(RefusalReason::WrongTypeOrLength))?;
        let mailbox_encapsulation_key = input_entry[signing_key_end..]
            .try_into()
            .map_err(|_| refusal_status(RefusalReason::WrongTypeOrLength))?;
        entries.push(
            RosterEntry::new(
                roster_position,
                signing_verification_key,
                mailbox_encapsulation_key,
            )
            .map_err(|error| refusal_status(error.refusal_reason))?,
        );
    }

    let roster = Roster::new(entries).map_err(|error| refusal_status(error.refusal_reason))?;
    roster
        .require_selected_profile_size()
        .map_err(|error| refusal_status(error.refusal_reason))?;
    roster
        .encode()
        .map_err(|error| refusal_status(error.refusal_reason))
}

unsafe fn input_bytes<'input>(pointer: *const u8, byte_length: usize) -> &'input [u8] {
    if pointer.is_null() || byte_length == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(pointer, byte_length) }
    }
}

unsafe fn write_status(status_pointer: *mut u32, status: u32) {
    if !status_pointer.is_null() {
        unsafe {
            status_pointer.write(status);
        }
    }
}

/// Returns the exact canonical output length after fully validating and
/// encoding the selected roster input.
///
/// # Safety
///
/// The input pointer must name its declared readable range. A non-null status
/// pointer must name one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_foundation_roster_encoded_byte_length(
    input_pointer: *const u8,
    input_byte_length: usize,
    status_pointer: *mut u32,
) -> usize {
    let result = encode_selected_roster(unsafe { input_bytes(input_pointer, input_byte_length) });
    match result {
        Ok(encoded_roster) => {
            unsafe {
                write_status(status_pointer, 0);
            }
            encoded_roster.len()
        }
        Err(status) => {
            unsafe {
                write_status(status_pointer, status);
            }
            0
        }
    }
}

/// Writes the exact Rust-canonical roster encoding into an equally sized
/// caller-owned output range.
///
/// # Safety
///
/// The input pointer must name its declared readable range. The output pointer
/// must name its declared writable range and must not overlap the input range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_foundation_roster_encode(
    input_pointer: *const u8,
    input_byte_length: usize,
    output_pointer: *mut u8,
    output_byte_length: usize,
) -> u32 {
    let result = encode_selected_roster(unsafe { input_bytes(input_pointer, input_byte_length) });
    let encoded_roster = match result {
        Ok(encoded_roster) => encoded_roster,
        Err(status) => return status,
    };
    if output_pointer.is_null() || output_byte_length != encoded_roster.len() {
        return refusal_status(RefusalReason::WrongTypeOrLength);
    }
    let output = unsafe { slice::from_raw_parts_mut(output_pointer, output_byte_length) };
    output.copy_from_slice(&encoded_roster);
    0
}

#[cfg(test)]
mod tests {
    use fips203::{
        ml_kem_768,
        traits::{KeyGen as KemKeyGen, SerDes as KemSerDes},
    };
    use fips204::{
        ml_dsa_65,
        traits::{KeyGen as SignatureKeyGen, SerDes as SignatureSerDes},
    };

    use super::*;
    use crate::foundation::CanonicalDecodeLimits;

    fn selected_roster_input() -> Vec<u8> {
        let mut input = Vec::with_capacity(
            usize::from(FOUNDATION_PROFILE.participant_count) * ROSTER_ENTRY_INPUT_BYTE_LENGTH,
        );
        for roster_position in 0..FOUNDATION_PROFILE.participant_count {
            let mut signing_seed = [0x31_u8; 32];
            signing_seed[0] =
                u8::try_from(roster_position + 1).expect("test roster position fits u8");
            signing_seed[31] = u8::try_from(FOUNDATION_PROFILE.participant_count - roster_position)
                .expect("reverse test roster position fits u8");
            let (signing_key, _) = ml_dsa_65::KG::keygen_from_seed(&signing_seed);

            let mut mailbox_seed = [0x62_u8; 32];
            mailbox_seed[0] =
                u8::try_from(roster_position + 1).expect("test roster position fits u8");
            let mut mailbox_fallback_seed = [0x93_u8; 32];
            mailbox_fallback_seed[31] =
                u8::try_from(FOUNDATION_PROFILE.participant_count - roster_position)
                    .expect("reverse test roster position fits u8");
            let (mailbox_key, _) =
                ml_kem_768::KG::keygen_from_seed(mailbox_seed, mailbox_fallback_seed);

            input.extend_from_slice(&roster_position.to_le_bytes());
            input.extend_from_slice(&signing_key.into_bytes());
            input.extend_from_slice(&mailbox_key.into_bytes());
        }
        input
    }

    fn entry_offset(roster_position: usize) -> usize {
        roster_position * ROSTER_ENTRY_INPUT_BYTE_LENGTH
    }

    #[test]
    fn exact_selected_roster_input_round_trips_through_the_canonical_schema() {
        let input = selected_roster_input();
        let encoded = encode_selected_roster(&input).expect("selected roster encodes");
        let decoded = Roster::decode(&encoded, &CanonicalDecodeLimits::default())
            .expect("Rust-produced roster decodes");

        assert_eq!(
            decoded.entries.len(),
            usize::from(FOUNDATION_PROFILE.participant_count)
        );
        assert_eq!(
            decoded.encode().expect("decoded roster re-encodes"),
            encoded
        );
        for (entry_index, entry) in decoded.entries.iter().enumerate() {
            assert_eq!(usize::from(entry.roster_position), entry_index);
            let input_offset = entry_offset(entry_index) + ROSTER_POSITION_BYTE_LENGTH;
            assert_eq!(
                entry.signing_verification_key.as_slice(),
                &input[input_offset..input_offset + ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH]
            );
        }
    }

    #[test]
    fn malformed_keys_duplicate_identities_and_noncanonical_order_refuse() {
        let input = selected_roster_input();

        let mut malformed_mailbox_key = input.clone();
        let mailbox_offset =
            entry_offset(0) + ROSTER_POSITION_BYTE_LENGTH + ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH;
        malformed_mailbox_key
            [mailbox_offset..mailbox_offset + ML_KEM_768_ENCAPSULATION_KEY_BYTE_LENGTH]
            .fill(0xff);
        assert_eq!(
            encode_selected_roster(&malformed_mailbox_key),
            Err(refusal_status(RefusalReason::MalformedEncoding))
        );

        let mut duplicate_identity = input.clone();
        let first_signing_key_offset = entry_offset(0) + ROSTER_POSITION_BYTE_LENGTH;
        let second_signing_key_offset = entry_offset(1) + ROSTER_POSITION_BYTE_LENGTH;
        duplicate_identity.copy_within(
            first_signing_key_offset
                ..first_signing_key_offset + ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH,
            second_signing_key_offset,
        );
        assert_eq!(
            encode_selected_roster(&duplicate_identity),
            Err(refusal_status(RefusalReason::DuplicateIdentity))
        );

        let mut noncanonical_order = input.clone();
        noncanonical_order[..ROSTER_ENTRY_INPUT_BYTE_LENGTH * 2]
            .rotate_left(ROSTER_ENTRY_INPUT_BYTE_LENGTH);
        assert_eq!(
            encode_selected_roster(&noncanonical_order),
            Err(refusal_status(RefusalReason::WrongTypeOrLength))
        );

        assert_eq!(
            encode_selected_roster(&input[..input.len() - 1]),
            Err(refusal_status(RefusalReason::WrongTypeOrLength))
        );
        let mut extra_entry = input;
        extra_entry.resize(extra_entry.len() + ROSTER_ENTRY_INPUT_BYTE_LENGTH, 0);
        assert_eq!(
            encode_selected_roster(&extra_entry),
            Err(refusal_status(RefusalReason::WrongTypeOrLength))
        );
    }

    #[test]
    fn raw_copy_requires_the_exact_rust_reported_output_bound() {
        let input = selected_roster_input();
        let encoded = encode_selected_roster(&input).expect("selected roster encodes");
        let mut short_output = vec![0_u8; encoded.len() - 1];
        let short_status = unsafe {
            sealed_lattice_foundation_roster_encode(
                input.as_ptr(),
                input.len(),
                short_output.as_mut_ptr(),
                short_output.len(),
            )
        };
        assert_eq!(
            short_status,
            refusal_status(RefusalReason::WrongTypeOrLength)
        );

        let mut exact_output = vec![0_u8; encoded.len()];
        let exact_status = unsafe {
            sealed_lattice_foundation_roster_encode(
                input.as_ptr(),
                input.len(),
                exact_output.as_mut_ptr(),
                exact_output.len(),
            )
        };
        assert_eq!(exact_status, 0);
        assert_eq!(exact_output, encoded);
    }
}
