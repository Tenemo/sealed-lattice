//! Identities the participant runtime binds into its retained state or
//! addresses public records by. The module computes them so that the host
//! carries no hash of its own, and computes them here, since the host waits
//! for each identity right after its last bytes.

use crate::Error;
use registration_credentials::{
    ballot_authentication::ENVELOPE_IDENTITY_DOMAIN, close_signing::ClosePurpose,
    identity::IdentityHasher, target_signing::TARGET_IDENTITY_DOMAIN,
};

/// The bytes one absorb call reads from the host.
pub const INPUT_BYTES: usize = 1 << 16;

/// The closed set of purposes the host may request, each under its own
/// domain. The target, envelope and close-response purposes yield the
/// certified target's, a ballot envelope's and a close response body's own
/// identities.
fn domain(purpose: u32) -> Option<&'static str> {
    Some(match purpose {
        0 => "sealed-lattice/participant-root/v1",
        1 => "sealed-lattice/participant-record/v1",
        2 => "sealed-lattice/enrollment-input/v1",
        3 => TARGET_IDENTITY_DOMAIN,
        4 => ENVELOPE_IDENTITY_DOMAIN,
        5 => ClosePurpose::Response.context(),
        _ => return None,
    })
}

pub struct State {
    input: Vec<u8>,
    output: [u8; 64],
    hash: Option<IdentityHasher>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            input: vec![0; INPUT_BYTES],
            output: [0; 64],
            hash: None,
        }
    }
}
impl State {
    /// Starts the identity of `length` bytes, discarding any unfinished one.
    pub fn begin(&mut self, purpose: u32, length: usize) -> Result<(), Error> {
        self.output = [0; 64];
        self.hash = None;
        let hash = IdentityHasher::local(domain(purpose).ok_or(Error::Shape)?, &[], length)
            .map_err(|_| Error::Shape)?;
        self.hash = Some(hash);
        Ok(())
    }
    /// Absorbs the first `length` input bytes, then clears them.
    pub fn absorb(&mut self, length: usize) -> Result<(), Error> {
        let result = match (self.input.get(..length), self.hash.as_mut()) {
            (Some(bytes), Some(hash)) => hash.absorb(bytes).map_err(|_| Error::Shape),
            (None, _) => Err(Error::Shape),
            (_, None) => Err(Error::State),
        };
        self.input[..length.min(INPUT_BYTES)].fill(0);
        if result.is_err() {
            self.hash = None;
        }
        result
    }
    /// Writes the identity once every committed byte is absorbed.
    pub fn finish(&mut self) -> Result<(), Error> {
        self.output = self
            .hash
            .take()
            .ok_or(Error::State)?
            .finish()
            .map_err(|_| Error::Shape)?;
        Ok(())
    }
}

#[cfg(target_arch = "wasm32")]
mod browser {
    use super::State;
    use std::cell::RefCell;

    thread_local! {static STATE: RefCell<State> = RefCell::new(State::default());}

    #[unsafe(no_mangle)]
    pub extern "C" fn custody_identity_input_pointer() -> usize {
        STATE.with(|state| state.borrow_mut().input.as_mut_ptr() as usize)
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn custody_identity_input_capacity() -> usize {
        super::INPUT_BYTES
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn custody_identity_output_pointer() -> usize {
        STATE.with(|state| state.borrow().output.as_ptr() as usize)
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn custody_identity_begin(purpose: u32, length: usize) -> u32 {
        STATE.with(|state| u32::from(state.borrow_mut().begin(purpose, length).is_err()))
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn custody_identity_absorb(length: usize) -> u32 {
        STATE.with(|state| u32::from(state.borrow_mut().absorb(length).is_err()))
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn custody_identity_finish() -> u32 {
        STATE.with(|state| u32::from(state.borrow_mut().finish().is_err()))
    }
}

#[cfg(test)]
#[path = "custody-identity-tests.rs"]
mod tests;
