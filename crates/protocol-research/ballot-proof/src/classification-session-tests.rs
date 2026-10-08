//! The classification session reads the verified setup only to begin a
//! well-formed ballot and refuses each later step without a ballot.
use super::{ClassificationSession, Refused};
use protocol_foundations::{
    SIGNATURE_BYTES, ballot_authentication::ENVELOPE_BYTES, ballot_body::HEADER_BYTES,
    poll::VerifiedPoll,
};
use setup_aggregate::verified::VerifiedSetupAggregate;
use std::sync::Arc;

type Setup = Option<(Arc<VerifiedPoll>, Arc<VerifiedSetupAggregate>)>;

fn absent() -> Setup {
    None
}

fn unread() -> Setup {
    panic!("Only a well-formed begin reads the setup.")
}

#[test]
fn begins_only_a_well_formed_ballot_under_a_verified_setup() {
    let mut session = ClassificationSession::new();
    let begin = ENVELOPE_BYTES + SIGNATURE_BYTES + HEADER_BYTES;
    assert!(matches!(session.begin(unread, begin - 1), Err(Refused)));
    assert!(matches!(session.begin(unread, begin + 1), Err(Refused)));
    assert!(matches!(session.begin(absent, begin), Err(Refused)));
    assert!(!session.requires_key());
}

#[test]
fn refuses_each_step_without_a_ballot() {
    let mut session = ClassificationSession::new();
    assert!(matches!(session.begin_key(0), Err(Refused)));
    assert!(matches!(session.finish_key(), Err(Refused)));
    assert!(matches!(session.push(1, true), Err(Refused)));
    assert!(matches!(session.push(1, false), Err(Refused)));
    let capacity = session.input().len();
    assert!(matches!(session.push(capacity + 1, false), Err(Refused)));
    assert!(session.finish().is_none());
    assert!(session.take_classification().is_none());
}
