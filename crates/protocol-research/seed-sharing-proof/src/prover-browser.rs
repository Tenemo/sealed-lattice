//! One fixed synthetic positive prover in a dedicated scalar worker. The
//! output stays immutable until its host acknowledges a completed transfer.
use crate::{
    fixture,
    prover::{Error, POSITIVE_PROOF_RANDOMNESS_SEED, Prover},
};

#[derive(Default)]
struct State {
    prover: Option<Prover>,
}
impl State {
    fn begin(&mut self) -> u32 {
        if self.prover.is_some() {
            return 6;
        }
        let (statement, witness) = fixture::create();
        match Prover::new(statement, witness, POSITIVE_PROOF_RANDOMNESS_SEED, false) {
            Ok(prover) => {
                self.prover = Some(prover);
                0
            }
            Err(Error::Context) => 1,
            Err(Error::Stage) => 6,
        }
    }
    fn phase(&self) -> u32 {
        self.prover.as_ref().map_or(0, Prover::phase)
    }
    fn advance(&mut self, action: fn(&mut Prover) -> Result<(), Error>) -> u32 {
        let Some(prover) = &mut self.prover else {
            return 6;
        };
        match action(prover) {
            Ok(()) => 0,
            Err(Error::Context) => 1,
            Err(Error::Stage) => 6,
        }
    }
}

#[cfg(target_arch = "wasm32")]
mod exports {
    use super::*;
    use crate::prover::OUTPUT_BYTES;
    use std::cell::RefCell;
    thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }
    #[unsafe(no_mangle)]
    pub extern "C" fn seed_prover_begin() -> u32 {
        STATE.with(|state| state.borrow_mut().begin())
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn seed_prover_phase() -> u32 {
        STATE.with(|state| state.borrow().phase())
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn seed_prover_step() -> u32 {
        STATE.with(|state| state.borrow_mut().advance(Prover::step))
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn seed_prover_next_output() -> u32 {
        STATE.with(|state| state.borrow_mut().advance(Prover::next_output))
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn seed_prover_ack_output() -> u32 {
        STATE.with(|state| state.borrow_mut().advance(Prover::acknowledge_output))
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn seed_prover_output_pointer() -> usize {
        STATE.with(|state| {
            state
                .borrow()
                .prover
                .as_ref()
                .map_or(0, |prover| prover.output().as_ptr() as usize)
        })
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn seed_prover_output_length() -> usize {
        STATE.with(|state| {
            state
                .borrow()
                .prover
                .as_ref()
                .map_or(0, |prover| prover.output().len())
        })
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn seed_prover_output_capacity() -> usize {
        OUTPUT_BYTES
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stage_refusals_do_not_start_or_replace_the_fixed_prover() {
        let mut state = State::default();
        for operation in [
            Prover::step,
            Prover::next_output,
            Prover::acknowledge_output,
        ] {
            assert_eq!(state.advance(operation), 6);
            assert_eq!(state.phase(), 0);
        }
        assert_eq!(state.begin(), 0);
        assert_eq!(state.phase(), 1);
        assert_eq!(state.begin(), 6);
        assert_eq!(state.advance(Prover::next_output), 6);
        assert_eq!(state.advance(Prover::acknowledge_output), 6);
        assert_eq!(state.phase(), 1);
        assert!(state.prover.as_ref().unwrap().output().is_empty());
    }
}
