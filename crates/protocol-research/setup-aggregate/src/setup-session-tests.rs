//! The setup verification session holds nothing before its roster verifies
//! and refuses each step whose predecessor it does not hold.
use super::{Refusal, SETUP_INPUT_BYTES, SetupSession};
use crate::CHUNK_BYTES;
use protocol_foundations::{Credential, roster_input::RecordStep};

#[test]
fn holds_nothing_before_its_roster_verifies() {
    let mut session = SetupSession::new();
    assert_eq!(session.input().len(), SETUP_INPUT_BYTES);
    assert!(session.output().is_empty());
    assert!(session.verified_setup().is_none());
    assert!(session.roster_context().is_none());
    assert!(session.unsigned_selection().is_none());
    assert!(session.selection_inputs().is_none());
    assert_eq!(session.option_count(), 0);
    assert_eq!(session.accepted(), 0);
    assert!(matches!(session.output_selection(), Err(Refusal)));
    assert!(session.output().is_empty());
    for length in [0, 63, 64] {
        assert!(!session.offer_available(0, length));
    }
    let credential = Credential::from_seed([5; 64]);
    assert!(!session.restore_setup(&credential, &[]));
    assert!(!session.restore_inputs(&credential, &[]));
}

#[test]
fn refuses_each_step_without_its_predecessor() {
    let mut session = SetupSession::new();
    // A roster input that is empty, malformed or beyond the input buffer.
    for length in [0, 64, SETUP_INPUT_BYTES + 1] {
        assert!(matches!(session.begin_roster_input(length), Err(Refusal)));
    }
    for step in [
        RecordStep::Begin,
        RecordStep::Key,
        RecordStep::KeyFinish,
        RecordStep::Finish,
        RecordStep::Discard,
    ] {
        assert!(matches!(session.roster_record(step, 0, 0), Err(Refusal)));
    }
    assert!(matches!(session.finish_roster(0), Err(Refusal)));
    assert!(matches!(session.begin_offer(0), Err(Refusal)));
    assert!(matches!(session.offer_polynomial(0, 0, 0), Err(Refusal)));
    assert!(matches!(session.offer_proof(0, 0), Err(Refusal)));
    assert!(matches!(session.finish_offer(), Err(Refusal)));
    assert!(matches!(session.propose_selection(0), Err(Refusal)));
    assert!(matches!(session.begin_selection(0), Err(Refusal)));
    assert!(matches!(session.aggregate_selection(), Err(Refusal)));
    assert!(matches!(
        session.begin_selected_offer_verification(0),
        Err(Refusal)
    ));
    assert!(matches!(session.selected_offer_proof(0, 0), Err(Refusal)));
    assert!(matches!(session.begin_selected_offer(0), Err(Refusal)));
    for length in [0, CHUNK_BYTES, CHUNK_BYTES + 1] {
        assert!(matches!(
            session.aggregate_polynomial(0, 0, length),
            Err(Refusal)
        ));
    }
    assert!(matches!(session.finish_selected_offer(), Err(Refusal)));
    assert!(matches!(session.finish_selection(), Err(Refusal)));
    assert!(matches!(session.add_endorsement(0), Err(Refusal)));
    assert!(matches!(session.build_certificate(), Err(Refusal)));
    assert!(matches!(session.begin_certificate(0), Err(Refusal)));
    assert!(matches!(session.finish_certificate(), Err(Refusal)));
    // Every refusal leaves the session as empty as it began.
    assert!(session.output().is_empty());
    assert!(session.verified_setup().is_none());
    assert!(session.roster_context().is_none());
}
