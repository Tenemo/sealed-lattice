//! The completion session takes the verified evaluation target only in its
//! first operation and refuses each later operation before what it needs.
use super::{COMPLETION_INPUT_BYTES, CompletionSession};
use crate::{release::Error, target::VerifiedEvaluationTarget};
use std::sync::Arc;

type Target = Option<Arc<VerifiedEvaluationTarget>>;

fn absent() -> Target {
    None
}

fn unread() -> Target {
    panic!("Only the first operation reads the target.")
}

#[test]
fn refuses_malformed_commands_and_a_missing_target() {
    let mut session = CompletionSession::new();
    // Only the share operand operations take an argument, and no input
    // exceeds the buffer.
    assert!(matches!(
        session.command(unread, 0, 1, 0),
        Err(Error::Encoding)
    ));
    assert!(matches!(
        session.command(unread, 1, 0, COMPLETION_INPUT_BYTES + 1),
        Err(Error::Encoding)
    ));
    assert!(matches!(
        session.command(unread, 0, 0, 1),
        Err(Error::Context)
    ));
    assert!(matches!(
        session.command(absent, 0, 0, 0),
        Err(Error::Incomplete)
    ));
    assert!(session.output().is_empty());
}

#[test]
fn refuses_each_later_operation_before_what_it_needs() {
    let mut session = CompletionSession::new();
    for (operation, argument) in [
        (1, 0),
        (2, 0),
        (3, 1),
        (4, 1),
        (5, 0),
        (6, 0),
        (8, 0),
        (9, 0),
        (10, 0),
    ] {
        assert!(matches!(
            session.command(unread, operation, argument, 0),
            Err(Error::Incomplete)
        ));
    }
    // A release body begins only after its envelope is authenticated.
    assert!(matches!(
        session.command(unread, 7, 0, 0),
        Err(Error::Context)
    ));
    assert!(matches!(
        session.command(unread, 11, 0, 0),
        Err(Error::Encoding)
    ));
    assert!(session.context().is_none());
    assert!(session.certificate().is_none());
}
