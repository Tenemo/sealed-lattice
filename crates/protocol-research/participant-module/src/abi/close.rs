//! The close: the participant's close messages and the public close
//! verification that yields the close barrier.
use super::{SESSION, Session};
use evaluation_target::{
    close::VerifiedCloseBarrier,
    close_session::{CLOSE_INPUT_BYTES, CloseSession},
};
use std::cell::RefCell;
use zeroize::{Zeroize, Zeroizing};
#[unsafe(no_mangle)]
pub extern "C" fn participant_close_command(operation: u32, argument: usize, length: usize) -> u32 {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        session.contribution_output.clear();
        if length > session.input.len() {
            return 1;
        }
        let input = Zeroizing::new(session.input[..length].to_vec());
        session.input[..length].zeroize();
        if operation == 0 {
            if argument != 0 || session.close.is_some() || session.ballot.is_some() {
                return 1;
            }
            let Some(enrollment) = session.enrollment.as_ref() else {
                return 1;
            };
            if !enrollment.sources_retired() {
                return 1;
            }
            let Some(context) = session.retained_context.as_ref() else {
                return 1;
            };
            let Some((poll, setup)) = setup_aggregate::setup_browser::context() else {
                return 1;
            };
            let Ok(ballot) =
                crate::ballot::BallotWork::new(&enrollment.credential, context, &input)
            else {
                return 1;
            };
            let Ok(close) = crate::close_work::CloseWork::new(ballot.into_owner(), poll, setup)
            else {
                return 1;
            };
            session.close = Some(close);
            return 0;
        }
        let Session {
            enrollment,
            close,
            contribution_output,
            ..
        } = &mut *session;
        let Some(enrollment) = enrollment.as_mut() else {
            return 1;
        };
        let Some(close) = close.as_mut() else {
            return 1;
        };
        match close.command(&mut enrollment.credential, operation, argument, &input) {
            Ok(bytes) => {
                *contribution_output = bytes;
                0
            }
            Err(_) => 1,
        }
    })
}

thread_local! {static CLOSE: RefCell<CloseSession> = RefCell::new(CloseSession::new());}

pub(super) fn take_barrier() -> Option<VerifiedCloseBarrier> {
    CLOSE.with(|close| close.borrow_mut().take_barrier())
}
#[unsafe(no_mangle)]
pub extern "C" fn close_input_pointer() -> usize {
    CLOSE.with(|close| close.borrow_mut().input().as_mut_ptr() as usize)
}
/// The input buffer's length; the host never writes more.
#[unsafe(no_mangle)]
pub extern "C" fn close_input_capacity() -> usize {
    CLOSE_INPUT_BYTES
}
#[unsafe(no_mangle)]
pub extern "C" fn close_command(operation: u32, length: usize) -> u32 {
    CLOSE.with(|close| {
        u32::from(
            close
                .borrow_mut()
                .command(setup_aggregate::setup_browser::context, operation, length)
                .is_err(),
        )
    })
}
/// Consecutive 64-byte envelope identities of the missing usable-slot bodies.
#[unsafe(no_mangle)]
pub extern "C" fn close_missing_pointer() -> usize {
    CLOSE.with(|close| close.borrow().missing().as_ptr() as usize)
}
#[unsafe(no_mangle)]
pub extern "C" fn close_missing_count() -> usize {
    CLOSE.with(|close| close.borrow().missing().len() / 64)
}
