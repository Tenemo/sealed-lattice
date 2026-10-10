//! The evaluation target session refuses every operation whose inputs it
//! lacks, reads each of the instance's other verifiers only in the
//! operation that takes from it, and leaves them untouched when it refuses
//! before that point.
use super::{EVALUATION_INPUT_BYTES, Error, EvaluationInputs, TargetSession};
use crate::close::VerifiedCloseBarrier;
use ballot_proof::body::BallotBodyClassification;
use protocol_foundations::poll::VerifiedPoll;
use setup_aggregate::verified::VerifiedSetupAggregate;
use std::sync::Arc;

// Other verifiers that hold nothing, counting what the session asks of them.
#[derive(Default)]
struct Absent {
    setups: usize,
    classifications: usize,
    releases: usize,
    barriers: usize,
}
impl EvaluationInputs for Absent {
    fn setup(&mut self) -> Option<(Arc<VerifiedPoll>, Arc<VerifiedSetupAggregate>)> {
        self.setups += 1;
        None
    }
    fn take_classification(&mut self) -> Option<BallotBodyClassification> {
        self.classifications += 1;
        None
    }
    fn release_ballot_inputs(&mut self) {
        self.releases += 1;
    }
    fn take_barrier(&mut self) -> Option<VerifiedCloseBarrier> {
        self.barriers += 1;
        None
    }
}

#[test]
fn takes_from_other_verifiers_only_in_the_operations_that_need_them() {
    let mut session = TargetSession::new();
    let mut inputs = Absent::default();
    // The begin takes no argument, and without a verified setup it releases
    // no ballot inputs.
    assert!(matches!(
        session.command(&mut inputs, 0, 1, 0),
        Err(Error::Context)
    ));
    assert_eq!(inputs.setups, 0);
    assert!(matches!(
        session.command(&mut inputs, 0, 0, 0),
        Err(Error::Context)
    ));
    assert_eq!((inputs.setups, inputs.releases), (1, 0));
    // A classification or the close barrier is never taken before the
    // setup is held.
    assert!(matches!(
        session.command(&mut inputs, 1, 0, 0),
        Err(Error::Context)
    ));
    assert!(matches!(
        session.command(&mut inputs, 2, 0, 0),
        Err(Error::Context)
    ));
    assert_eq!(
        (inputs.classifications, inputs.releases, inputs.barriers),
        (0, 0, 0)
    );
}

#[test]
fn refuses_every_operation_before_an_evaluation_runs() {
    let mut session = TargetSession::new();
    let mut inputs = Absent::default();
    for operation in [0, 1, 2, 10, 13, 15, 16, 19, 21, 22, 23] {
        assert!(matches!(
            session.command(&mut inputs, operation, 0, EVALUATION_INPUT_BYTES + 1),
            Err(Error::Encoding)
        ));
    }
    for (operation, argument, length) in [(10, 0, 0), (11, 0, 0), (14, 0, 0), (15, 0, 0)] {
        assert!(matches!(
            session.command(&mut inputs, operation, argument, length),
            Err(Error::Context)
        ));
    }
    // No stream is open to take a piece or to finish.
    assert!(matches!(
        session.command(&mut inputs, 12, 0, 1),
        Err(Error::Incomplete)
    ));
    assert!(matches!(
        session.command(&mut inputs, 13, 0, 0),
        Err(Error::Incomplete)
    ));
    for (operation, argument, length) in
        [(16, 0, 8), (17, 0, 0), (18, 0, 0), (19, 0, 0), (22, 0, 0)]
    {
        assert!(
            session
                .command(&mut inputs, operation, argument, length)
                .is_err()
        );
    }
    for operation in [3, 9, 20, 24] {
        assert!(matches!(
            session.command(&mut inputs, operation, 0, 0),
            Err(Error::Encoding)
        ));
    }
    assert!(session.target().is_none());
    assert!(!session.finished());
    assert!(session.output().is_empty());
    assert_eq!(
        (
            inputs.setups,
            inputs.classifications,
            inputs.releases,
            inputs.barriers
        ),
        (0, 0, 0, 0)
    );
}
