//! Ballots: the participant's own ballot and the classification of each
//! published ballot.
use super::{SESSION, Session};
use crate::ballot::BallotOperation;
use ballot_proof::{
    CHUNK_LIMIT, body::BallotBodyClassification, classification_session::ClassificationSession,
};
use std::cell::RefCell;
use zeroize::{Zeroize, Zeroizing};
#[unsafe(no_mangle)]
pub extern "C" fn participant_ballot_command(
    operation: u32,
    argument: usize,
    length: usize,
) -> u32 {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        session.contribution_output.clear();
        if length > session.input.len() {
            return 1;
        }
        let input = Zeroizing::new(session.input[..length].to_vec());
        session.input[..length].zeroize();
        let Some(operation) = BallotOperation::from_code(operation) else {
            return 1;
        };
        if operation == BallotOperation::Begin {
            if argument != 0 || session.ballot.is_some() {
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
            let Ok(ballot) =
                crate::ballot::BallotWork::new(&enrollment.credential, context, &input)
            else {
                return 1;
            };
            session.ballot = Some(ballot);
            return 0;
        }
        let Session {
            enrollment,
            ballot,
            contribution_output,
            ..
        } = &mut *session;
        let Some(enrollment) = enrollment.as_mut() else {
            return 1;
        };
        let Some(ballot) = ballot.as_mut() else {
            return 1;
        };
        // A ballot is created only from the undrawn randomness of the seed
        // its root retains.
        if operation == BallotOperation::Create
            && !super::operation_random::ready(crate::operation_random::Purpose::Ballot)
        {
            return 1;
        }
        match ballot.command(&mut enrollment.credential, operation, argument, &input) {
            Ok(bytes) => {
                *contribution_output = bytes;
                0
            }
            Err(_) => 1,
        }
    })
}

/// The aggregate polynomial a ballot of the retained poll encrypts under at
/// this ordinal, which ballot creation reads as its key; the maximum value
/// when no poll is retained or no such key exists.
#[unsafe(no_mangle)]
pub extern "C" fn participant_ballot_key_index() -> usize {
    SESSION.with(|session| {
        session
            .borrow()
            .retained_context
            .as_ref()
            .map(|context| ballot_proof::statement::setup_input(context.profile()).2)
            .unwrap_or(usize::MAX)
    })
}

thread_local! {static CLASSIFICATION: RefCell<ClassificationSession> = RefCell::new(ClassificationSession::new());}

pub(super) fn take_classification() -> Option<BallotBodyClassification> {
    CLASSIFICATION.with(|session| session.borrow_mut().take_classification())
}
pub(super) fn release_ballot_inputs() {
    CLASSIFICATION.with(|session| session.borrow_mut().release_inputs());
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_body_input_pointer() -> usize {
    CLASSIFICATION.with(|session| session.borrow_mut().input().as_mut_ptr() as usize)
}
/// The input buffer's length; the host never writes more.
#[unsafe(no_mangle)]
pub extern "C" fn ballot_body_input_capacity() -> usize {
    CHUNK_LIMIT
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_classification_begin(length: usize) -> u32 {
    CLASSIFICATION.with(|session| {
        u32::from(
            session
                .borrow_mut()
                .begin(super::setup_verification::verified_setup, length)
                .is_err(),
        )
    })
}
/// The aggregate polynomial that a ballot classified under the verified
/// setup reads as its FHE key; the maximum value when no setup is verified.
#[unsafe(no_mangle)]
pub extern "C" fn ballot_classification_key_index() -> usize {
    super::setup_verification::verified_setup()
        .map(|(_, setup)| ballot_proof::statement::setup_input(setup.profile()).2)
        .unwrap_or(usize::MAX)
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_classification_requires_key() -> u32 {
    CLASSIFICATION.with(|session| u32::from(session.borrow().requires_key()))
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_classification_key_begin(index: usize) -> u32 {
    CLASSIFICATION.with(|session| u32::from(session.borrow_mut().begin_key(index).is_err()))
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_classification_key_finish() -> u32 {
    CLASSIFICATION.with(|session| u32::from(session.borrow_mut().finish_key().is_err()))
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_classification_key_chunk(length: usize) -> u32 {
    CLASSIFICATION.with(|session| u32::from(session.borrow_mut().push(length, true).is_err()))
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_classification_chunk(length: usize) -> u32 {
    CLASSIFICATION.with(|session| u32::from(session.borrow_mut().push(length, false).is_err()))
}
/// One for a valid ballot, two for an invalid one and zero when the
/// classification failed.
#[unsafe(no_mangle)]
pub extern "C" fn ballot_classification_finish() -> u32 {
    CLASSIFICATION.with(|session| match session.borrow_mut().finish() {
        Some(BallotBodyClassification::Valid(_)) => 1,
        Some(BallotBodyClassification::Invalid(_)) => 2,
        None => 0,
    })
}
