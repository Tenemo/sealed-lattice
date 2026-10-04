//! One bounded scalar session. Two actual predecessor proof streams must
//! finish before this module can verify or prove the fixed opening fixture.
use crate::{
    fixture,
    predecessor::{RecordVerifier, VerifiedSeedSharingRecord},
    statement::Statement,
    verification::Verifier,
};
#[cfg(any(test, feature = "scalar-prover-fixture"))]
use crate::{
    prover::{Error, POSITIVE_PROOF_RANDOMNESS_SEED, Prover},
    witness,
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
pub(crate) struct State {
    pub(crate) input: Vec<u8>,
    records: Vec<VerifiedSeedSharingRecord>,
    source: Option<RecordVerifier>,
    verifier: Option<Verifier>,
    #[cfg(any(test, feature = "scalar-prover-fixture"))]
    prover: Option<Prover>,
    consumed: bool,
    failed: u32,
}
impl Default for State {
    fn default() -> Self {
        Self {
            input: vec![0; CHUNK_LIMIT],
            records: Vec::new(),
            source: None,
            verifier: None,
            #[cfg(any(test, feature = "scalar-prover-fixture"))]
            prover: None,
            consumed: false,
            failed: 0,
        }
    }
}
impl State {
    fn refuse(&mut self, refusal: Refusal) -> u32 {
        if self.failed == 0 {
            self.failed = code(refusal);
        }
        self.source = None;
        self.verifier = None;
        self.records.clear();
        #[cfg(any(test, feature = "scalar-prover-fixture"))]
        {
            self.prover = None;
        }
        self.failed
    }
    pub(crate) fn source_begin(&mut self, slot: u32, length: usize) -> u32 {
        if self.failed != 0 {
            return self.failed;
        }
        if length != HEADER_LENGTH || length > self.input.len() {
            return self.refuse(Refusal::Length);
        }
        if self.consumed
            || self.source.is_some()
            || slot as usize != self.records.len()
            || slot as usize >= crate::SELECTED
        {
            return self.refuse(Refusal::Stage);
        }
        // These are fixed bounded expected operands, not host-supplied keys
        // or a claim that a browser has authenticated a roster or decision.
        let original = seed_sharing_proof::fixture::create().0;
        let expected = if slot == 0 {
            original
        } else {
            fixture::second_source(&original).0
        };
        let bytes = match expected.encode() {
            Ok(bytes) => bytes,
            Err(_) => return self.refuse(Refusal::Encoding),
        };
        match RecordVerifier::open(&expected, &bytes, &self.input[..length]) {
            Ok(source) => {
                self.source = Some(source);
                0
            }
            Err(refusal) => self.refuse(refusal),
        }
    }
    pub(crate) fn source_push(&mut self, length: usize) -> u32 {
        if self.failed != 0 {
            return self.failed;
        }
        if length > self.input.len() {
            return self.refuse(Refusal::Length);
        }
        let Some(source) = &mut self.source else {
            return self.refuse(Refusal::Stage);
        };
        match source.push(&self.input[..length]) {
            Ok(()) => 0,
            Err(refusal) => self.refuse(refusal),
        }
    }
    pub(crate) fn source_finish(&mut self) -> u32 {
        if self.failed != 0 {
            return self.failed;
        }
        let Some(source) = self.source.take() else {
            return self.refuse(Refusal::Stage);
        };
        match source.finish() {
            Ok(record) => {
                self.records.push(record);
                0
            }
            Err(refusal) => self.refuse(refusal),
        }
    }
    fn expected(&self, case: u32) -> Result<(Statement, &'static [u8]), Refusal> {
        if self.records.len() != crate::SELECTED {
            return Err(Refusal::Stage);
        }
        let first = &self.records[0];
        let second = &self.records[1];
        let mut selection =
            fixture::selection(first.statement(), [first.identity(), second.identity()]);
        let messages = fixture::messages([first.statement(), second.statement()], 2);
        let role = if case == 5 {
            seed_sharing_proof::verification::ROLE
        } else {
            crate::ROLE
        };
        if case == 2 {
            selection.runtime[0] ^= 1;
        }
        let statement = if case == 4 {
            selection.records.swap(0, 1);
            Statement::from_records(
                selection,
                2,
                [second, first],
                [messages[1].clone(), messages[0].clone()],
            )
        } else {
            Statement::from_records(
                selection,
                if case == 3 { 1 } else { 2 },
                [first, second],
                messages,
            )
        }
        .map_err(|_| Refusal::Context)?;
        Ok((
            if case == 1 {
                fixture::shifted_share(&statement).map_err(|_| Refusal::Encoding)?
            } else {
                statement
            },
            role,
        ))
    }
    pub(crate) fn verifier_begin(&mut self, case: u32, length: usize) -> u32 {
        if self.failed != 0 {
            return self.failed;
        }
        if length != HEADER_LENGTH || length > self.input.len() {
            return self.refuse(Refusal::Length);
        }
        if self.consumed || self.source.is_some() || self.records.len() != crate::SELECTED {
            return self.refuse(Refusal::Stage);
        }
        if case > 5 {
            return self.refuse(Refusal::Context);
        }
        self.consumed = true;
        let (expected, role) = match self.expected(case) {
            Ok(value) => value,
            Err(refusal) => return self.refuse(refusal),
        };
        let bytes = match expected.encode() {
            Ok(bytes) => bytes,
            Err(_) => return self.refuse(Refusal::Encoding),
        };
        match Verifier::open(&expected, &bytes, role, &self.input[..length]) {
            Ok(verifier) => {
                self.verifier = Some(verifier);
                0
            }
            Err(refusal) => self.refuse(refusal),
        }
    }
    pub(crate) fn verifier_push(&mut self, length: usize) -> u32 {
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
    pub(crate) fn verifier_finish(&mut self) -> u32 {
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

    #[cfg(any(test, feature = "scalar-prover-fixture"))]
    pub(crate) fn prover_begin(&mut self) -> u32 {
        if self.failed != 0 {
            return self.failed;
        }
        if self.prover.is_some() {
            return code(Refusal::Stage);
        }
        if self.consumed || self.source.is_some() || self.records.len() != crate::SELECTED {
            return self.refuse(Refusal::Stage);
        }
        self.consumed = true;
        let (statement, _) = match self.expected(0) {
            Ok(value) => value,
            Err(refusal) => return self.refuse(refusal),
        };
        let secret = zeroize::Zeroizing::new(fixture::recipient_secret(2));
        let witness = match witness::create(&statement, &secret) {
            Ok(value) => value,
            Err(_) => return self.refuse(Refusal::Relation),
        };
        match Prover::new(statement, witness, POSITIVE_PROOF_RANDOMNESS_SEED, false) {
            Ok(prover) => {
                self.prover = Some(prover);
                0
            }
            Err(Error::Context) => self.refuse(Refusal::Context),
            Err(Error::Stage) => self.refuse(Refusal::Stage),
        }
    }
    #[cfg(any(test, feature = "scalar-prover-fixture"))]
    pub(crate) fn prover_phase(&self) -> u32 {
        self.prover.as_ref().map_or(0, Prover::phase)
    }
    #[cfg(any(test, feature = "scalar-prover-fixture"))]
    fn advance(&mut self, action: fn(&mut Prover) -> Result<(), Error>) -> u32 {
        if self.failed != 0 {
            return self.failed;
        }
        let Some(prover) = &mut self.prover else {
            return self.refuse(Refusal::Stage);
        };
        match action(prover) {
            Ok(()) => 0,
            Err(Error::Context) => self.refuse(Refusal::Context),
            Err(Error::Stage) => code(Refusal::Stage),
        }
    }
    #[cfg(any(test, feature = "scalar-prover-fixture"))]
    pub(crate) fn prover_step(&mut self) -> u32 {
        self.advance(Prover::step)
    }
    #[cfg(any(test, feature = "scalar-prover-fixture"))]
    pub(crate) fn prover_next_output(&mut self) -> u32 {
        self.advance(Prover::next_output)
    }
    #[cfg(any(test, feature = "scalar-prover-fixture"))]
    pub(crate) fn prover_acknowledge_output(&mut self) -> u32 {
        self.advance(Prover::acknowledge_output)
    }
}

#[cfg(target_arch = "wasm32")]
mod exports {
    use super::*;
    use std::cell::RefCell;
    thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }
    #[unsafe(no_mangle)]
    pub extern "C" fn opening_input_pointer() -> usize {
        STATE.with(|state| state.borrow_mut().input.as_mut_ptr() as usize)
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn opening_input_capacity() -> usize {
        CHUNK_LIMIT
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn opening_header_length() -> usize {
        HEADER_LENGTH
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn opening_source_begin(slot: u32, length: usize) -> u32 {
        STATE.with(|state| state.borrow_mut().source_begin(slot, length))
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn opening_source_push(length: usize) -> u32 {
        STATE.with(|state| state.borrow_mut().source_push(length))
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn opening_source_finish() -> u32 {
        STATE.with(|state| state.borrow_mut().source_finish())
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn opening_verifier_begin(case: u32, length: usize) -> u32 {
        STATE.with(|state| state.borrow_mut().verifier_begin(case, length))
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn opening_verifier_push(length: usize) -> u32 {
        STATE.with(|state| state.borrow_mut().verifier_push(length))
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn opening_verifier_finish() -> u32 {
        STATE.with(|state| state.borrow_mut().verifier_finish())
    }

    #[cfg(feature = "scalar-prover-fixture")]
    mod proving {
        use super::*;
        #[unsafe(no_mangle)]
        pub extern "C" fn opening_prover_begin() -> u32 {
            STATE.with(|state| state.borrow_mut().prover_begin())
        }
        #[unsafe(no_mangle)]
        pub extern "C" fn opening_prover_phase() -> u32 {
            STATE.with(|state| state.borrow().prover_phase())
        }
        #[unsafe(no_mangle)]
        pub extern "C" fn opening_prover_step() -> u32 {
            STATE.with(|state| state.borrow_mut().prover_step())
        }
        #[unsafe(no_mangle)]
        pub extern "C" fn opening_prover_next_output() -> u32 {
            STATE.with(|state| state.borrow_mut().prover_next_output())
        }
        #[unsafe(no_mangle)]
        pub extern "C" fn opening_prover_ack_output() -> u32 {
            STATE.with(|state| state.borrow_mut().prover_acknowledge_output())
        }
        #[unsafe(no_mangle)]
        pub extern "C" fn opening_prover_output_pointer() -> usize {
            STATE.with(|state| {
                state
                    .borrow()
                    .prover
                    .as_ref()
                    .map_or(0, |prover| prover.output().as_ptr() as usize)
            })
        }
        #[unsafe(no_mangle)]
        pub extern "C" fn opening_prover_output_length() -> usize {
            STATE.with(|state| {
                state
                    .borrow()
                    .prover
                    .as_ref()
                    .map_or(0, |prover| prover.output().len())
            })
        }
        #[unsafe(no_mangle)]
        pub extern "C" fn opening_prover_output_capacity() -> usize {
            crate::prover::OUTPUT_BYTES
        }
    }
}
