//! The verification of the participant's own registration, which enrollment,
//! the roster and the contribution read.
use super::SESSION;
use crate::own_verification::{CONTROL_BYTES, State};
use protocol_foundations::{poll::VerifiedPoll, registration::VerifiedRegistration};
use std::{cell::RefCell, sync::Arc};

thread_local! {static STATE:RefCell<State>=RefCell::new(State::new());}

pub(super) fn verified() -> Option<Arc<VerifiedRegistration>> {
    STATE.with(|state| state.borrow().verified.clone())
}

/// The signed poll, which the registration verification checks first. It
/// fixes enrollment source families even during restoration.
pub(super) fn with_poll<T>(operation: impl FnOnce(&VerifiedPoll) -> T) -> Option<T> {
    STATE.with(|state| state.borrow().poll.as_ref().map(operation))
}

/// The result length, question and options of the poll this instance
/// verified the registration of, as `own_registration_poll` writes them.
pub(super) fn verified_poll() -> Option<Vec<u8>> {
    STATE.with(|state| {
        let state = state.borrow();
        let poll = state.verified.as_ref().and(state.poll.as_ref())?;
        let manifest = poll.manifest();
        let text = |bytes: &mut Vec<u8>, value: &str| {
            bytes.extend((value.len() as u32).to_le_bytes());
            bytes.extend(value.as_bytes());
        };
        let mut bytes = Vec::from(poll.top_count().to_le_bytes());
        text(&mut bytes, manifest.display_title().as_str());
        bytes.extend((manifest.option_count() as u16).to_le_bytes());
        for option in manifest.options() {
            text(&mut bytes, option.option_identifier());
            text(&mut bytes, option.display_label().as_str());
        }
        Some(bytes)
    })
}
/// The option count of the poll this instance verified the registration of.
pub(super) fn verified_option_count() -> Option<usize> {
    STATE.with(|state| {
        let state = state.borrow();
        state.verified.as_ref().map(|_| state.options)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn own_registration_input_pointer() -> usize {
    STATE.with(|state| state.borrow_mut().input.as_mut_ptr() as usize)
}
/// The input buffer's length; the host never writes more.
#[unsafe(no_mangle)]
pub extern "C" fn own_registration_input_capacity() -> usize {
    CONTROL_BYTES
}
#[unsafe(no_mangle)]
pub extern "C" fn own_registration_command(operation: u32, length: usize) -> u32 {
    STATE.with(|state| u32::from(state.borrow_mut().command(operation, length).is_err()))
}
/// The verified poll's option count, or zero before verification.
#[unsafe(no_mangle)]
pub extern "C" fn own_registration_option_count() -> usize {
    verified_option_count().unwrap_or(0)
}
/// The participant maximum of the poll this instance verified the
/// registration of, or zero before verification.
#[unsafe(no_mangle)]
pub extern "C" fn own_registration_maximum_participants() -> usize {
    STATE.with(|state| {
        let state = state.borrow();
        state
            .verified
            .as_ref()
            .and(state.poll.as_ref())
            .map_or(0, |poll| usize::from(poll.maximum_participants()))
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn own_registration_username_pointer() -> usize {
    STATE.with(|state| {
        state.borrow().verified.as_ref().map_or(0, |value| {
            value.header().username.as_str().as_ptr() as usize
        })
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn own_registration_username_length() -> usize {
    STATE.with(|state| {
        state
            .borrow()
            .verified
            .as_ref()
            .map_or(0, |value| value.header().username.as_str().len())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn own_registration_body_digest_pointer() -> usize {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        let Some(value) = state.verified.as_ref().map(|value| value.body_digest()) else {
            return 0;
        };
        state.input[..64].copy_from_slice(&value);
        state.input.as_ptr() as usize
    })
}

/// Writes the poll this instance verified the participant's own registration
/// against to the contribution output: the two-byte result length, the
/// question, the two-byte option count and each option's identifier and
/// label, each text after its four-byte length.
#[unsafe(no_mangle)]
pub extern "C" fn own_registration_poll() -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        state.contribution_output.clear();
        let Some(poll) = verified_poll() else {
            return 1;
        };
        state.contribution_output = poll;
        0
    })
}
