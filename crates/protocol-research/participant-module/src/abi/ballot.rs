//! The participant's ballot.
use super::{SESSION, Session};
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
        if operation == 0 {
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
        if operation == 4
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
