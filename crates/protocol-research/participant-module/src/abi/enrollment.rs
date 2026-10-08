//! Enrollment: the organizer's poll, each role's credential and the restore
//! of a retained credential.
use super::SESSION;
use crate::Enrollment;
use protocol_foundations::SIGNATURE_BYTES;
use protocol_foundations::foundation::{
    MAXIMUM_USERNAME_INGRESS_BYTES, RegistrationHeader, normalize_username,
};
use zeroize::{Zeroize, Zeroizing};
/// The bytes after a four-byte length at an offset, as their range, when the
/// input holds them and they fit a poll definition.
fn framed(input: &[u8], offset: usize) -> Option<(usize, usize)> {
    let start = offset.checked_add(4)?;
    let length = u32::from_le_bytes(input.get(offset..start)?.try_into().ok()?) as usize;
    if length > protocol_foundations::poll::MAXIMUM_POLL_BYTES {
        return None;
    }
    let end = start.checked_add(length)?;
    (end <= input.len()).then_some((start, end))
}
/// The organizer input is the runtime, the result length, the participant
/// maximum, the question, the option count, each option's label in order and
/// the username, each text after its four-byte length. The question and
/// labels become the poll's manifest under the module's own normalization,
/// option `i` named `option-i`, and the poll definition bounds them all.
fn organizer_context(
    input: &[u8],
) -> Option<(
    protocol_foundations::poll::PollDraft,
    [u8; 64],
    usize,
    usize,
)> {
    use protocol_foundations::foundation::{
        StabilizedDisplayText,
        manifest::{Manifest, OptionDefinition},
    };
    let runtime = input.get(..64)?.try_into().ok()?;
    let top_count = u16::from_le_bytes(input.get(64..66)?.try_into().ok()?);
    let maximum_participants = u16::from_le_bytes(input.get(66..68)?.try_into().ok()?);
    let (start, end) = framed(input, 68)?;
    let question = StabilizedDisplayText::from_ingress_utf8(&input[start..end]).ok()?;
    let option_count = u16::from_le_bytes(input.get(end..end + 2)?.try_into().ok()?);
    let mut offset = end + 2;
    // An option index past the supported count is refused, which bounds
    // this loop.
    let mut options = Vec::new();
    for index in 0..option_count {
        let (start, end) = framed(input, offset)?;
        offset = end;
        options.push(
            OptionDefinition::new(
                index,
                format!("option-{index}"),
                StabilizedDisplayText::from_ingress_utf8(&input[start..end]).ok()?,
            )
            .ok()?,
        );
    }
    let manifest = Manifest::new(question, options).ok()?;
    let draft =
        protocol_foundations::poll::PollDraft::new(manifest, top_count, maximum_participants)
            .ok()?;
    let (name_start, name_end) = framed(input, offset)?;
    if name_end - name_start > MAXIMUM_USERNAME_INGRESS_BYTES {
        return None;
    }
    normalize_username(&input[name_start..name_end]).ok()?;
    Some((draft, runtime, name_start, name_end))
}
fn joiner_context(
    input: &[u8],
) -> Option<(protocol_foundations::poll::VerifiedPoll, usize, usize)> {
    if input.len() < 132 {
        return None;
    }
    let length = u32::from_le_bytes(input[128..132].try_into().ok()?) as usize;
    if length > protocol_foundations::poll::MAXIMUM_POLL_BYTES
        || input.len() < 132 + length + SIGNATURE_BYTES + 4
    {
        return None;
    }
    let poll = protocol_foundations::poll::verify_poll(
        input[..64].try_into().ok()?,
        input[64..128].try_into().ok()?,
        &input[132..132 + length],
        &input[132 + length..132 + length + SIGNATURE_BYTES],
    )
    .ok()?;
    let name_start = 132 + length + SIGNATURE_BYTES + 4;
    let name_length =
        u32::from_le_bytes(input[name_start - 4..name_start].try_into().ok()?) as usize;
    if name_length > MAXIMUM_USERNAME_INGRESS_BYTES || input.len() < name_start + name_length {
        return None;
    }
    normalize_username(&input[name_start..name_start + name_length]).ok()?;
    Some((poll, name_start, name_start + name_length))
}

#[unsafe(no_mangle)]
pub extern "C" fn validate_organizer(length: usize) -> u32 {
    SESSION.with(|state| {
        let state = state.borrow();
        if length > state.input.len() {
            return 1;
        }
        u32::from(
            organizer_context(&state.input[..length]).is_none_or(|(_, _, _, end)| end != length),
        )
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn validate_joiner(length: usize) -> u32 {
    SESSION.with(|state| {
        let state = state.borrow();
        if length > state.input.len() {
            return 1;
        }
        u32::from(joiner_context(&state.input[..length]).is_none_or(|(_, _, end)| end != length))
    })
}

/// The staged output that carries the enrollment's three capsule keys, which
/// the worker retains in its root rather than as a record.
const DATA_KEYS: u32 = 12;
fn staged_output(kind: u32, offset: usize, bytes: &[u8]) {
    #[link(wasm_import_module = "enrollment")]
    unsafe extern "C" {
        fn staged_chunk(kind: u32, offset: usize, pointer: *const u8, length: usize) -> u32;
    }
    for (index, chunk) in bytes.chunks(1 << 20).enumerate() {
        assert_eq!(
            unsafe {
                staged_chunk(
                    kind,
                    offset + index * (1 << 20),
                    chunk.as_ptr(),
                    chunk.len(),
                )
            },
            0
        );
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn prepare_organizer(length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        if state.started || length > state.input.len() {
            return 1;
        }
        let Some((draft, runtime, start, end)) = organizer_context(&state.input[..length]) else {
            return 1;
        };
        if length != end {
            return 1;
        }
        state.started = true;
        let input = Zeroizing::new(state.input[..length].to_vec());
        state.input[..length].zeroize();
        let Ok((poll, enrollment, data_keys)) =
            Enrollment::create_organizer(draft, runtime, &input[start..end], staged_output)
        else {
            return 1;
        };
        staged_output(5, 0, &poll.body);
        staged_output(6, 0, &poll.signature);
        staged_output(DATA_KEYS, 0, &*data_keys);
        state.poll_identity = poll.identity;
        state.enrollment = Some(enrollment);
        0
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn prepare_joiner(length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        if state.started || length > state.input.len() {
            return 1;
        }
        let Some((poll, start, end)) = joiner_context(&state.input[..length]) else {
            return 1;
        };
        if length != end {
            return 1;
        }
        state.started = true;
        let input = Zeroizing::new(state.input[..length].to_vec());
        state.input[..length].zeroize();
        let Ok((enrollment, data_keys)) =
            Enrollment::create_for_poll(&poll, &input[start..end], staged_output)
        else {
            return 1;
        };
        staged_output(DATA_KEYS, 0, &*data_keys);
        state.poll_identity = poll.identity();
        state.enrollment = Some(enrollment);
        0
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn restore(length: usize) -> u32 {
    restore_enrollment(length, false)
}
/// The prepared path authenticates a retained setup result and accepts no
/// source capsule or source wrapping key.
#[unsafe(no_mangle)]
pub extern "C" fn restore_prepared(length: usize) -> u32 {
    restore_enrollment(length, true)
}
fn restore_enrollment(length: usize, prepared: bool) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        if state.restored
            || (state.started && state.enrollment.is_none())
            || !(132..=state.input.len()).contains(&length)
        {
            return 1;
        }
        state.restored = true;
        state.started = true;
        let input = Zeroizing::new(state.input[..length].to_vec());
        state.input[..length].zeroize();
        let header_length = u32::from_le_bytes(input[128..132].try_into().unwrap()) as usize;
        if header_length > RegistrationHeader::maximum_bytes() {
            return 1;
        }
        let key_bytes = if prepared { 64 } else { 96 };
        let key_polynomial_bytes = protocol_foundations::registration::KEY_BYTES;
        let recipient_bytes = setup_witness::registration::SEALED_KEY_BYTES;
        let signing_bytes = protocol_foundations::SEALED_SIGNING_SEED_BYTES;
        let base_length = 132
            + header_length
            + 64
            + key_bytes
            + key_polynomial_bytes
            + recipient_bytes
            + signing_bytes;
        if length < base_length + 2 {
            return 1;
        }
        let Ok((header, consumed)) =
            RegistrationHeader::decode_prefix(&input[132..132 + header_length])
        else {
            return 1;
        };
        if consumed != header_length
            || header.poll.as_slice() != &input[..64]
            || header.runtime.as_slice() != &input[64..128]
        {
            return 1;
        }
        let start = 132 + header_length;
        let body_digest = input[start..start + 64].try_into().unwrap();
        let data_keys = &input[start + 64..start + 64 + key_bytes];
        let public_start = start + 64 + key_bytes;
        let capsule_start = public_start + key_polynomial_bytes;
        let recipient_capsule = &input[capsule_start..capsule_start + recipient_bytes];
        let signing_capsule = &input[capsule_start + recipient_bytes..base_length];
        // The authenticated participant root names the purposes its records
        // show unused. Every other purpose of the restored credential stays
        // locked; completed messages are restored from their own records.
        let unused = u16::from_le_bytes(input[length - 2..].try_into().unwrap());
        let Some(Ok(mut enrollment)) = super::own_verification::with_poll(|poll| {
            if prepared {
                let framed = input
                    .get(base_length..length - 2)
                    .ok_or(crate::Error::Shape)?;
                let frame_length = usize::try_from(u32::from_le_bytes(
                    framed
                        .get(..4)
                        .ok_or(crate::Error::Shape)?
                        .try_into()
                        .unwrap(),
                ))
                .map_err(|_| crate::Error::Shape)?;
                if frame_length != framed.len() - 4 {
                    return Err(crate::Error::Shape);
                }
                Enrollment::restore_prepared(
                    poll,
                    &header,
                    &input[public_start..capsule_start],
                    body_digest,
                    data_keys.try_into().unwrap(),
                    [recipient_capsule, signing_capsule, &framed[4..]],
                )
            } else {
                if length != base_length + crate::fhe_sources::capsule_bytes(poll) + 2 {
                    return Err(crate::Error::Shape);
                }
                Enrollment::restore(
                    poll,
                    &header,
                    &input[public_start..capsule_start],
                    body_digest,
                    data_keys.try_into().unwrap(),
                    [
                        recipient_capsule,
                        signing_capsule,
                        &input[base_length..length - 2],
                    ],
                )
            }
        }) else {
            return 1;
        };
        // The registration this instance verified. The keys stay only if it
        // names the root's exact inputs.
        let Some(verified) = super::own_verification::verified() else {
            return 1;
        };
        if verified.header().encode().ok().as_deref() != Some(&input[132..132 + header_length])
            || verified.body_digest() != body_digest
            || verified.public_key() != &input[public_start..capsule_start]
        {
            return 1;
        }
        if let Some(original) = state.enrollment.as_ref() {
            // A newly created instance retains its actual consumed authority.
            // Reopening validates the saved capsules without replacing it.
            if unused != 0
                || state.poll_identity != header.poll
                || original.credential.signing_public() != enrollment.credential.signing_public()
                || original.key.public_key() != enrollment.key.public_key()
                || original.sources_retired() != enrollment.sources_retired()
            {
                return 1;
            }
        } else {
            if enrollment
                .credential
                .unlock_unused_purposes(unused)
                .is_err()
            {
                return 1;
            }
            state.enrollment = Some(enrollment);
        }
        state.poll_identity = header.poll;
        if prepared {
            super::contribution::retire();
        }
        0
    })
}
