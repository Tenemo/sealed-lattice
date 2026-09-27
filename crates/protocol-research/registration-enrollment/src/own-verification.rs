use registration_credentials::{
    Credential, Error,
    poll::{MAXIMUM_POLL_BYTES, VerifiedPoll, verify_poll},
    registration::{RETAINED_REGISTRATION_BYTES, RegistrationVerifier, VerifiedRegistration},
};
use std::{cell::RefCell, sync::Arc};

const CHUNK_BYTES: usize = 1 << 20;
const SIGNATURE_BYTES: usize = 3309;
const MAXIMUM_HEADER_BYTES: usize = 4096;
const CONTROL_BYTES: usize =
    128 + 4 + MAXIMUM_POLL_BYTES + SIGNATURE_BYTES + 4 + MAXIMUM_HEADER_BYTES + SIGNATURE_BYTES;
struct State {
    input: Vec<u8>,
    pending: Option<RegistrationVerifier>,
    // The verified poll that the pending or verified registration names, and
    // its option count; no later input can replace them.
    poll: Option<VerifiedPoll>,
    options: usize,
    // The retained copy of an earlier visit's verification, which replaces
    // the proof once the credential it is keyed to is open.
    retained: Option<Vec<u8>>,
    verified: Option<Arc<VerifiedRegistration>>,
    // Whether the verified registration is that retained copy's rather than
    // this instance's verification.
    restored: bool,
}
impl State {
    fn new() -> Self {
        Self {
            input: vec![0; CONTROL_BYTES],
            pending: None,
            poll: None,
            options: 0,
            retained: None,
            verified: None,
            restored: false,
        }
    }
    fn begin(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.verified.is_some() || bytes.len() < 132 {
            return Err(Error::Consumed);
        }
        let definition_bytes = u32::from_le_bytes(bytes[128..132].try_into().unwrap()) as usize;
        if definition_bytes > MAXIMUM_POLL_BYTES
            || bytes.len() < 132 + definition_bytes + SIGNATURE_BYTES + 4
        {
            return Err(Error::Shape);
        }
        let end = 132 + definition_bytes;
        let poll = verify_poll(
            bytes[..64].try_into().unwrap(),
            bytes[64..128].try_into().unwrap(),
            &bytes[132..end],
            &bytes[end..end + SIGNATURE_BYTES],
        )?;
        let header_start = end + SIGNATURE_BYTES + 4;
        let header_bytes =
            u32::from_le_bytes(bytes[header_start - 4..header_start].try_into().unwrap()) as usize;
        if header_bytes > MAXIMUM_HEADER_BYTES
            || bytes.len() != header_start + header_bytes + SIGNATURE_BYTES
        {
            return Err(Error::Shape);
        }
        self.pending = Some(RegistrationVerifier::new(
            &poll,
            &bytes[header_start..header_start + header_bytes],
            &bytes[header_start + header_bytes..],
        )?);
        self.options = poll.manifest().option_count();
        self.poll = Some(poll);
        self.retained = None;
        Ok(())
    }
    fn command(&mut self, operation: u32, length: usize) -> Result<(), Error> {
        if length > self.input.len() || (operation != 0 && length > CHUNK_BYTES) {
            return Err(Error::Shape);
        }
        if operation == 0 {
            let bytes = self.input[..length].to_vec();
            self.pending = None;
            return self.begin(&bytes);
        }
        if self.verified.is_some() {
            return Err(Error::Consumed);
        }
        match operation {
            1 => self
                .pending
                .as_mut()
                .ok_or(Error::Consumed)?
                .push_key(&self.input[..length]),
            2 if length == 0 => self.pending.as_mut().ok_or(Error::Consumed)?.finish_key(),
            3 => self
                .pending
                .as_mut()
                .ok_or(Error::Consumed)?
                .push_proof(&self.input[..length]),
            4 if length == 0 => {
                let verified = self.pending.take().ok_or(Error::Consumed)?.finish()?;
                self.verified = Some(Arc::new(verified));
                Ok(())
            }
            5 if length == RETAINED_REGISTRATION_BYTES => {
                if self.pending.is_none() || self.retained.is_some() {
                    return Err(Error::Consumed);
                }
                self.retained = Some(self.input[..length].to_vec());
                Ok(())
            }
            _ => Err(Error::Shape),
        }
    }
}
thread_local! {static STATE:RefCell<State>=RefCell::new(State::new());}

pub(super) fn verified() -> Option<Arc<VerifiedRegistration>> {
    STATE.with(|state| state.borrow().verified.clone())
}

/// Restores the participant's own registration from the retained copy the
/// host delivered in place of the proof, for the credential that the
/// registration's capsules opened.
pub(super) fn restore(credential: &Credential) -> Option<Arc<VerifiedRegistration>> {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        let state = &mut *state;
        if state.verified.is_some() {
            return None;
        }
        let retained = state.retained.take()?;
        let pending = state.pending.take()?;
        let verified = Arc::new(
            pending
                .restore(credential, state.poll.as_ref()?, &retained)
                .ok()?,
        );
        state.verified = Some(verified.clone());
        state.restored = true;
        Some(verified)
    })
}

/// Keys this instance's verification of the participant's own registration
/// to its credential. A registration restored from its retained copy is not
/// retained again.
pub(super) fn retain(credential: &Credential) -> Option<Vec<u8>> {
    STATE.with(|state| {
        let state = state.borrow();
        if state.restored {
            return None;
        }
        state
            .verified
            .as_ref()?
            .retain(credential, state.poll.as_ref()?)
            .ok()
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
pub extern "C" fn own_registration_proof_hash_pointer() -> usize {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        let Some(value) = state.verified.as_ref().map(|value| value.proof_hash()) else {
            return 0;
        };
        state.input[..64].copy_from_slice(&value);
        state.input.as_ptr() as usize
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
