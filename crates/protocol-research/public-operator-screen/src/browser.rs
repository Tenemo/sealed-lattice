//! Scalar ABI only. All mathematics and output ownership live in the same
//! source modules as the native screen.
use crate::{OUTPUT_BYTES, Screen, State};
use std::cell::RefCell;

thread_local! {static STATE:RefCell<State>=RefCell::new(State::default());}
#[unsafe(no_mangle)]
pub extern "C" fn operator_screen_begin(case: u32) -> u32 {
    STATE.with(|state| state.borrow_mut().begin(case))
}
#[unsafe(no_mangle)]
pub extern "C" fn operator_screen_phase() -> u32 {
    STATE.with(|state| state.borrow().phase())
}
#[unsafe(no_mangle)]
pub extern "C" fn operator_screen_step() -> u32 {
    STATE.with(|state| state.borrow_mut().advance(Screen::step))
}
#[unsafe(no_mangle)]
pub extern "C" fn operator_screen_next_output() -> u32 {
    STATE.with(|state| state.borrow_mut().advance(Screen::next_output))
}
#[unsafe(no_mangle)]
pub extern "C" fn operator_screen_ack_output() -> u32 {
    STATE.with(|state| state.borrow_mut().advance(Screen::acknowledge_output))
}
#[unsafe(no_mangle)]
pub extern "C" fn operator_screen_output_pointer() -> usize {
    STATE.with(|state| {
        state
            .borrow()
            .screen
            .as_ref()
            .map_or(0, |screen| screen.output().as_ptr() as usize)
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn operator_screen_output_length() -> usize {
    STATE.with(|state| {
        state
            .borrow()
            .screen
            .as_ref()
            .map_or(0, |screen| screen.output().len())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn operator_screen_output_capacity() -> usize {
    OUTPUT_BYTES
}
