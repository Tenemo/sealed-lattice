//! The completion: the target's certificate, the verified release shares and
//! the terminal they reach.
use evaluation_target::{
    certification::VerifiedInventoryCertificate,
    completion_session::{COMPLETION_INPUT_BYTES, CompletionSession},
    release::ReleaseContext,
};
use std::{cell::RefCell, sync::Arc};

thread_local! {static COMPLETION: RefCell<CompletionSession> = RefCell::new(CompletionSession::new());}

pub(super) fn verified_release_context() -> Option<Arc<ReleaseContext>> {
    COMPLETION.with(|completion| completion.borrow().context())
}
pub(super) fn verified_certificate() -> Option<Arc<VerifiedInventoryCertificate>> {
    COMPLETION.with(|completion| completion.borrow().certificate())
}
#[unsafe(no_mangle)]
pub extern "C" fn completion_input_pointer() -> usize {
    COMPLETION.with(|completion| completion.borrow_mut().input().as_mut_ptr() as usize)
}
/// The input buffer's length; the host never writes more.
#[unsafe(no_mangle)]
pub extern "C" fn completion_input_capacity() -> usize {
    COMPLETION_INPUT_BYTES
}
#[unsafe(no_mangle)]
pub extern "C" fn completion_output_pointer() -> usize {
    COMPLETION.with(|completion| completion.borrow().output().as_ptr() as usize)
}
#[unsafe(no_mangle)]
pub extern "C" fn completion_output_length() -> usize {
    COMPLETION.with(|completion| completion.borrow().output().len())
}
#[unsafe(no_mangle)]
pub extern "C" fn completion_command(operation: u32, argument: usize, length: usize) -> u32 {
    COMPLETION.with(|completion| {
        u32::from(
            completion
                .borrow_mut()
                .command(
                    super::evaluation::verified_target,
                    operation,
                    argument,
                    length,
                )
                .is_err(),
        )
    })
}
