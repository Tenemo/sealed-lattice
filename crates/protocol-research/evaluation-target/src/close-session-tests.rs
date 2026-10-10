//! The public close session takes the verified setup only in its first
//! operation and refuses every later operation before that context.
use super::{CLOSE_INPUT_BYTES, CloseSession};
use protocol_foundations::poll::VerifiedPoll;
use setup_aggregate::verified::VerifiedSetupAggregate;
use std::sync::Arc;

type Setup = Option<(Arc<VerifiedPoll>, Arc<VerifiedSetupAggregate>)>;

fn absent() -> Setup {
    None
}

fn unread() -> Setup {
    panic!("Only the first operation reads the setup.")
}

#[test]
fn refuses_to_begin_without_a_verified_setup() {
    let mut session = CloseSession::new();
    assert_eq!(session.input().len(), CLOSE_INPUT_BYTES);
    // The first operation takes no input.
    assert!(session.command(unread, 1, 1).is_err());
    assert!(session.command(absent, 1, 0).is_err());
    assert!(session.missing().is_empty());
    assert!(session.take_barrier().is_none());
}

#[test]
fn refuses_every_later_operation_before_its_context() {
    let mut session = CloseSession::new();
    for operation in [0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11] {
        assert!(session.command(unread, operation, 0).is_err());
    }
    assert!(session.command(unread, 3, CLOSE_INPUT_BYTES + 1).is_err());
    assert!(session.missing().is_empty());
    assert!(session.take_barrier().is_none());
}
