//! Enrollment: the organizer's poll, each role's credential and the restore
//! of a retained credential.
use super::SESSION;
use crate::enrollment_input::{joiner_input, organizer_input, restore_input};
use crate::{Enrollment, data_kind};
use zeroize::{Zeroize, Zeroizing};

#[unsafe(no_mangle)]
pub extern "C" fn validate_organizer(length: usize) -> u32 {
    SESSION.with(|state| {
        let state = state.borrow();
        if length > state.input.len() {
            return 1;
        }
        u32::from(organizer_input(&state.input[..length]).is_none())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn validate_joiner(length: usize) -> u32 {
    SESSION.with(|state| {
        let state = state.borrow();
        if length > state.input.len() {
            return 1;
        }
        u32::from(joiner_input(&state.input[..length]).is_none())
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
        let Some(organizer) = organizer_input(&state.input[..length]) else {
            return 1;
        };
        state.started = true;
        let input = Zeroizing::new(state.input[..length].to_vec());
        state.input[..length].zeroize();
        let Ok((poll, enrollment, data_keys)) = Enrollment::create_organizer(
            organizer.draft,
            organizer.runtime,
            &input[organizer.username],
            staged_output,
        ) else {
            return 1;
        };
        staged_output(data_kind::POLL_DEFINITION, 0, &poll.body);
        staged_output(data_kind::POLL_SIGNATURE, 0, &poll.signature);
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
        let Some(joiner) = joiner_input(&state.input[..length]) else {
            return 1;
        };
        state.started = true;
        let input = Zeroizing::new(state.input[..length].to_vec());
        state.input[..length].zeroize();
        let Ok((enrollment, data_keys)) =
            Enrollment::create_for_poll(&joiner.poll, &input[joiner.username], staged_output)
        else {
            return 1;
        };
        staged_output(DATA_KEYS, 0, &*data_keys);
        state.poll_identity = joiner.poll.identity();
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
            || !(68..=state.input.len()).contains(&length)
        {
            return 1;
        }
        state.restored = true;
        state.started = true;
        let input = Zeroizing::new(state.input[..length].to_vec());
        state.input[..length].zeroize();
        let Some(retained) = restore_input(&input, prepared) else {
            return 1;
        };
        // Authenticate the exact public record before opening private state.
        let Some(verified) = super::own_registration::verified() else {
            return 1;
        };
        let Some(Ok(mut enrollment)) =
            super::own_registration::with_poll(|poll| retained.enrollment(poll, &verified))
        else {
            return 1;
        };
        // The authenticated participant root names the purposes its records
        // show unused. Every other purpose of the restored credential stays
        // locked; completed messages are restored from their own records.
        let unused = retained.unused;
        if let Some(original) = state.enrollment.as_ref() {
            // A newly created instance retains its actual consumed authority.
            // Reopening validates the saved capsules without replacing it.
            if unused != 0
                || state.poll_identity != retained.header.poll
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
        state.poll_identity = retained.header.poll;
        if prepared {
            super::contribution::retire();
        }
        0
    })
}
