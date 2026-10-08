//! The custody identity of a message the participant signs.
use crate::custody_identity::{INPUT_BYTES, State};
use std::cell::RefCell;

thread_local! {static STATE: RefCell<State> = RefCell::new(State::default());}

#[unsafe(no_mangle)]
pub extern "C" fn custody_identity_input_pointer() -> usize {
    STATE.with(|state| state.borrow_mut().input.as_mut_ptr() as usize)
}
#[unsafe(no_mangle)]
pub extern "C" fn custody_identity_input_capacity() -> usize {
    INPUT_BYTES
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
