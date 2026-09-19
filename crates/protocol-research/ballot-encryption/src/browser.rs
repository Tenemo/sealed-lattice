use crate::packing;
use std::cell::RefCell;
use zeroize::Zeroizing;

struct Session {
    input: [u8; 20],
    coefficients: Zeroizing<Vec<i32>>,
}
thread_local! { static SESSION: RefCell<Session> = RefCell::new(Session { input: [0;20], coefficients: Zeroizing::new(Vec::new()) }); }

#[unsafe(no_mangle)]
pub extern "C" fn ballot_input_pointer() -> usize {
    SESSION.with(|value| value.borrow_mut().input.as_mut_ptr() as usize)
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_pack(count: usize, top_count: usize) -> u32 {
    SESSION.with(|value| {
        let mut value = value.borrow_mut();
        value.coefficients = Zeroizing::new(Vec::new());
        if count > value.input.len() {
            value.input.fill(0);
            return 1;
        }
        let packed = packing::encode(&value.input[..count], top_count);
        value.input.fill(0);
        let Ok(coefficients) = packed else {
            return 1;
        };
        value.coefficients = Zeroizing::new(coefficients);
        0
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_coefficients_pointer() -> usize {
    SESSION.with(|value| {
        let value = value.borrow();
        if value.coefficients.is_empty() {
            0
        } else {
            value.coefficients.as_ptr() as usize
        }
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_coefficient_count() -> usize {
    SESSION.with(|value| value.borrow().coefficients.len())
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_clear() {
    SESSION.with(|value| {
        let mut value = value.borrow_mut();
        value.input.fill(0);
        value.coefficients = Zeroizing::new(Vec::new());
    });
}
