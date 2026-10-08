//! The roster: its verification, the organizer's proposal signature and the
//! participant's confirmation.
use super::{SESSION, Session, original_context};
use protocol_foundations::{
    SIGNATURE_BYTES, roster_authentication::authenticate_roster_proposal,
    roster_input::RosterInputVerifier,
};
use std::sync::Arc;
use zeroize::Zeroize;
#[unsafe(no_mangle)]
pub extern "C" fn roster_begin(length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Some(input) = state.input.get(..length) else {
            return 1;
        };
        let Ok(roster) = RosterInputVerifier::new(input) else {
            return 1;
        };
        begin_roster(&mut state, roster);
        0
    })
}
fn begin_roster(state: &mut Session, roster: RosterInputVerifier) {
    state.roster = Some(roster);
    state.proposal = None;
    state.proposal_signature = None;
    state.signed_proposal = None;
}
// A roster verifier that restores the retained roster the restored
// credential keyed: the input is the verifier's begin input and then the
// retained roster.
pub(super) fn retained_roster(
    state: &Session,
    begin: usize,
    length: usize,
) -> Option<RosterInputVerifier> {
    let enrollment = state.enrollment.as_ref()?;
    let (begin, retained) = state.input.get(..length)?.split_at_checked(begin)?;
    RosterInputVerifier::retained(begin, &enrollment.credential, retained).ok()
}
/// Restores this participant's earlier roster verification: each record
/// then takes its header and key, and no proof.
#[unsafe(no_mangle)]
pub extern "C" fn roster_begin_retained(begin: usize, length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Some(roster) = retained_roster(&state, begin, length) else {
            return 1;
        };
        begin_roster(&mut state, roster);
        0
    })
}
/// Emits the retained roster from the proposal this instance's roster
/// verifier built by verifying every record, keyed to the restored
/// credential. A restored roster is not retained again.
#[unsafe(no_mangle)]
pub extern "C" fn retain_roster() -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        state.contribution_output.clear();
        let (Some(enrollment), Some(roster), Some(proposal)) = (
            state.enrollment.as_ref(),
            state.roster.as_ref(),
            state.proposal.as_ref(),
        ) else {
            return 1;
        };
        if roster.is_retained() {
            return 1;
        }
        let Ok(retained) = enrollment.credential.retain_roster(roster.poll(), proposal) else {
            return 1;
        };
        state.contribution_output = retained;
        0
    })
}
/// The registration records the host may keep open at once.
#[unsafe(no_mangle)]
pub extern "C" fn roster_open_records() -> u32 {
    protocol_foundations::roster_input::open_record_limit() as u32
}
/// Begins, feeds or finishes the record at a position; a record begins
/// with its position, header and signature.
#[unsafe(no_mangle)]
pub extern "C" fn roster_record(operation: u32, position: usize, length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Session {
            input,
            roster,
            proposal,
            ..
        } = &mut *state;
        if proposal.is_some() {
            return 1;
        }
        let Some(bytes) = input.get(..length) else {
            return 1;
        };
        let Some(roster) = roster.as_mut() else {
            return 1;
        };
        u32::from(
            match operation {
                0 => roster.begin_record(bytes),
                1 => roster.push_key(position, bytes),
                2 if length == 0 => roster.finish_key(position),
                4 if length == 0 => roster.finish_record(position),
                5 if length == 0 => roster.discard_record(position),
                _ => return 1,
            }
            .is_err(),
        )
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn roster_finish() -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Some(roster) = state.roster.as_mut() else {
            return 1;
        };
        let Ok(proposal) = roster.finish() else {
            return 1;
        };
        state.proposal = Some(proposal);
        0
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn roster_body_pointer() -> usize {
    SESSION.with(|state| {
        state
            .borrow()
            .proposal
            .as_ref()
            .map_or(0, |p| p.body().as_ptr() as usize)
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn roster_body_length() -> usize {
    SESSION.with(|state| {
        state
            .borrow()
            .proposal
            .as_ref()
            .map_or(0, |p| p.body().len())
    })
}
/// Emits the usernames of the proposal this instance's roster verifier
/// built, in roster order, each as its four-byte length and its bytes.
#[unsafe(no_mangle)]
pub extern "C" fn roster_usernames() -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Session {
            proposal,
            contribution_output,
            ..
        } = &mut *state;
        contribution_output.clear();
        let Some(proposal) = proposal.as_ref() else {
            return 1;
        };
        for record in proposal.records() {
            let username = record.header().username.as_str().as_bytes();
            contribution_output.extend((username.len() as u32).to_le_bytes());
            contribution_output.extend(username);
        }
        0
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn roster_identity_pointer() -> usize {
    SESSION.with(|state| {
        state
            .borrow()
            .proposal
            .as_ref()
            .map_or(0, |p| p.identity_bytes().as_ptr() as usize)
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn sign_roster_proposal(length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        if length != 64 {
            return 1;
        }
        let Session {
            input,
            enrollment,
            proposal,
            proposal_signature,
            ..
        } = &mut *state;
        let Some(enrollment) = enrollment.as_mut() else {
            return 1;
        };
        let Some(proposal) = proposal.as_ref() else {
            return 1;
        };
        if input[..64] != proposal.identity() {
            return 1;
        }
        input[..64].zeroize();
        let Ok(signature) = enrollment.credential.sign_roster_proposal(proposal) else {
            return 1;
        };
        *proposal_signature = Some(signature);
        0
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn validate_roster_signer() -> u32 {
    SESSION.with(|state| {
        let state = state.borrow();
        let Some(enrollment) = state.enrollment.as_ref() else {
            return 1;
        };
        let Some(proposal) = state.proposal.as_ref() else {
            return 1;
        };
        u32::from(
            enrollment
                .credential
                .validate_roster_proposal_target(proposal)
                .is_err(),
        )
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn roster_signature_pointer() -> usize {
    SESSION.with(|state| {
        state
            .borrow()
            .proposal_signature
            .as_ref()
            .map_or(0, |s| s.as_ptr() as usize)
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn verify_roster_signature(length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        if length != SIGNATURE_BYTES {
            return 1;
        }
        let Some(roster) = state.roster.as_mut() else {
            return 1;
        };
        let Ok(proposal) = roster.finish() else {
            return 1;
        };
        let Ok(verified) = authenticate_roster_proposal(proposal, &state.input[..length]) else {
            return 1;
        };
        state.proposal_signature = Some(*verified.signature());
        state.signed_proposal = Some(Arc::new(verified));
        0
    })
}

/// The parent authenticates and commits its original confirmed roster first.
#[unsafe(no_mangle)]
pub extern "C" fn confirm_roster() -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Ok(context) = original_context(&state) else {
            return 1;
        };
        let Some(enrollment) = state.enrollment.as_mut() else {
            return 1;
        };
        if enrollment.credential.confirm_roster(&context).is_err() {
            return 1;
        }
        state.retained_context = Some(context);
        0
    })
}
