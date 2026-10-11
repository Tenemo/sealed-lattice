//! The operation randomness that a retained seed serves.
use crate::operation_random::{Purpose, State};
use parallel_work::random;
use std::cell::RefCell;
use zeroize::Zeroize;

thread_local! {static STATE:RefCell<State>=RefCell::new(State::default());}

fn serve(purpose: random::Purpose, bytes: &mut [u8]) -> bool {
    STATE.with(|state| state.borrow_mut().serve(purpose, bytes))
}

/// Whether the purpose's randomness is installed from its seed and
/// undrawn, so that the operation draws only from that seed.
pub(super) fn ready(purpose: Purpose) -> bool {
    STATE.with(|state| state.borrow().ready(purpose))
}

/// The completed setup retires the contribution's remaining private
/// stream state along with its persisted seed and witness records.
pub(super) fn retire_contribution() {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        if state
            .streams
            .as_ref()
            .is_some_and(|streams| streams.purpose == Purpose::Contribution)
        {
            state.streams = None;
            state.input.zeroize();
            random::release();
        }
    });
}

#[unsafe(no_mangle)]
pub extern "C" fn operation_random_input_pointer() -> usize {
    STATE.with(|state| state.borrow_mut().input.as_mut_ptr() as usize)
}
/// The bytes the first or the proof stream of the last installed seed
/// served.
#[unsafe(no_mangle)]
pub extern "C" fn operation_random_drawn(stream: u32) -> usize {
    STATE.with(|state| state.borrow().drawn[stream as usize])
}
/// While a seed's streams are installed, they serve the operation's
/// draws.
#[unsafe(no_mangle)]
pub extern "C" fn operation_random_command(operation: u32, length: usize) -> u32 {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        let installed = state.streams.is_some();
        let refused = state.command(operation, length).is_err();
        match (installed, state.streams.is_some()) {
            (false, true) => random::install(serve),
            (true, false) => random::release(),
            _ => {}
        }
        u32::from(refused)
    })
}
