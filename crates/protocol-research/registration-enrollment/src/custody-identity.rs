//! Identities the participant runtime binds into its retained state. The
//! module computes them so that the host carries no hash of its own.

use crate::Error;
use registration_credentials::{identity::IdentityHasher, target_signing::TARGET_IDENTITY_DOMAIN};

/// The bytes one absorb call reads from the host.
pub const INPUT_BYTES: usize = 1 << 16;

/// The closed set of purposes the host may request, each under its own
/// domain. The target purpose yields the certified target's own identity.
fn domain(purpose: u32) -> Option<&'static str> {
    Some(match purpose {
        0 => "sealed-lattice/participant-root/v1",
        1 => "sealed-lattice/participant-record/v1",
        2 => "sealed-lattice/enrollment-input/v1",
        3 => TARGET_IDENTITY_DOMAIN,
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
        let hash = IdentityHasher::new(domain(purpose).ok_or(Error::Shape)?, &[], length)
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
mod tests {
    use super::*;
    use registration_credentials::foundation::{CanonicalItem, hash_foundation_tuple_512};

    fn identity(state: &mut State, purpose: u32, bytes: &[u8], fragment: usize) -> [u8; 64] {
        state.begin(purpose, bytes.len()).unwrap();
        for part in bytes.chunks(fragment) {
            state.input[..part.len()].copy_from_slice(part);
            state.absorb(part.len()).unwrap();
            assert!(state.input.iter().all(|value| *value == 0));
        }
        state.finish().unwrap();
        state.output
    }

    #[test]
    fn separates_purposes_and_matches_the_target_identity() {
        let body: Vec<u8> = (0..INPUT_BYTES + 91)
            .map(|index| (index % 253) as u8)
            .collect();
        let mut state = State::default();
        let target = hash_foundation_tuple_512(
            TARGET_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(&body[..2048]).unwrap()],
        )
        .unwrap()
        .into_bytes();
        assert_eq!(identity(&mut state, 3, &body[..2048], 100), target);
        let identities: Vec<_> = (0..4)
            .map(|purpose| identity(&mut state, purpose, &body, INPUT_BYTES))
            .collect();
        for purpose in 0..4 {
            assert_eq!(
                identity(&mut state, purpose as u32, &body, 7_000),
                identities[purpose]
            );
            for other in purpose + 1..4 {
                assert_ne!(identities[purpose], identities[other]);
            }
        }
    }

    #[test]
    fn refuses_unknown_purposes_and_wrong_lengths() {
        let mut state = State::default();
        assert!(state.begin(4, 1).is_err());
        assert!(state.absorb(1).is_err());
        assert!(state.finish().is_err());
        state.begin(1, 2).unwrap();
        assert!(state.absorb(INPUT_BYTES + 1).is_err());
        assert!(state.finish().is_err());
        state.begin(1, 2).unwrap();
        state.absorb(1).unwrap();
        assert!(state.finish().is_err());
        state.begin(1, 2).unwrap();
        assert!(state.absorb(3).is_err());
        // A new identity replaces an unfinished one.
        state.begin(1, 2).unwrap();
        state.absorb(1).unwrap();
        state.begin(1, 1).unwrap();
        state.absorb(1).unwrap();
        state.finish().unwrap();
        assert_ne!(state.output, [0; 64]);
    }
}
