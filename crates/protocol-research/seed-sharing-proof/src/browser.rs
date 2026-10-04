//! Bounded scalar verifier for the exact native research artifacts. Case
//! selection fixes a synthetic statement, never participant authority.
use crate::{
    fixture,
    verification::{ROLE, Verifier},
};
use word_verifier::{HEADER_LENGTH, Refusal, engine::CHUNK_LIMIT};

fn code(refusal: Refusal) -> u32 {
    match refusal {
        Refusal::Encoding => 1,
        Refusal::Length => 2,
        Refusal::Context => 3,
        Refusal::Authentication => 4,
        Refusal::Relation => 5,
        Refusal::Stage => 6,
    }
}
struct State {
    input: Vec<u8>,
    started: bool,
    failed: u32,
    verifier: Option<Verifier>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            input: vec![0; CHUNK_LIMIT],
            started: false,
            failed: 0,
            verifier: None,
        }
    }
}
impl State {
    fn refuse(&mut self, refusal: Refusal) -> u32 {
        if self.failed == 0 {
            self.failed = code(refusal);
        }
        self.verifier = None;
        self.failed
    }
    fn begin(&mut self, case: u32, length: usize) -> u32 {
        if self.failed != 0 {
            return self.failed;
        }
        if self.started {
            return self.refuse(Refusal::Stage);
        }
        self.started = true;
        if length != HEADER_LENGTH || length > self.input.len() {
            return self.refuse(Refusal::Length);
        }
        let expected = match case {
            0 | 1 => fixture::create().0,
            2 => fixture::impossible_share().0,
            3 => {
                let mut statement = fixture::create().0;
                statement.scope.poll[0] ^= 1;
                statement
            }
            _ => return self.refuse(Refusal::Context),
        };
        let supplied = match expected.encode() {
            Ok(bytes) => bytes,
            Err(_) => return self.refuse(Refusal::Encoding),
        };
        match Verifier::open(&expected, &supplied, ROLE, &self.input[..length]) {
            Ok(verifier) => {
                self.verifier = Some(verifier);
                0
            }
            Err(refusal) => self.refuse(refusal),
        }
    }
    fn push(&mut self, length: usize) -> u32 {
        if self.failed != 0 {
            return self.failed;
        }
        if length > self.input.len() {
            return self.refuse(Refusal::Length);
        }
        let Some(verifier) = &mut self.verifier else {
            return self.refuse(Refusal::Stage);
        };
        match verifier.push(&self.input[..length]) {
            Ok(()) => 0,
            Err(refusal) => self.refuse(refusal),
        }
    }
    fn finish(&mut self) -> u32 {
        if self.failed != 0 {
            return self.failed;
        }
        let Some(verifier) = self.verifier.take() else {
            return self.refuse(Refusal::Stage);
        };
        match verifier.finish() {
            Ok(()) => 0,
            Err(refusal) => self.refuse(refusal),
        }
    }
}

#[cfg(target_arch = "wasm32")]
mod exports {
    use super::*;
    use std::cell::RefCell;
    thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }
    #[unsafe(no_mangle)]
    pub extern "C" fn seed_verifier_input_pointer() -> usize {
        STATE.with(|state| state.borrow_mut().input.as_mut_ptr() as usize)
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn seed_verifier_input_capacity() -> usize {
        CHUNK_LIMIT
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn seed_verifier_header_length() -> usize {
        HEADER_LENGTH
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn seed_verifier_begin(case: u32, length: usize) -> u32 {
        STATE.with(|state| state.borrow_mut().begin(case, length))
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn seed_verifier_push(length: usize) -> u32 {
        STATE.with(|state| state.borrow_mut().push(length))
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn seed_verifier_finish() -> u32 {
        STATE.with(|state| state.borrow_mut().finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scalar_session_refuses_missing_start_and_keeps_its_first_failure() {
        let mut state = State::default();
        assert_eq!(state.finish(), 6);
        assert_eq!(state.begin(0, HEADER_LENGTH), 6);
        assert_eq!(state.push(1), 6);
        let mut state = State::default();
        assert_eq!(state.push(0), 6);
        assert_eq!(state.finish(), 6);
    }
    #[test]
    fn scalar_session_bounds_lengths_before_reading_or_deriving_fixture_inputs() {
        for length in [
            0,
            HEADER_LENGTH - 1,
            HEADER_LENGTH + 1,
            CHUNK_LIMIT + 1,
            usize::MAX,
        ] {
            let mut state = State::default();
            assert_eq!(state.begin(0, length), 2);
            assert_eq!(state.finish(), 2);
        }
        let mut state = State::default();
        assert_eq!(state.push(usize::MAX), 2);
        assert_eq!(state.finish(), 2);
        let mut state = State::default();
        assert_eq!(state.begin(99, HEADER_LENGTH), 3);
        assert_eq!(state.finish(), 3);
    }
}
