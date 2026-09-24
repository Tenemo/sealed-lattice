use crate::{OpenedContributionVerifier, VerifiedOpenedContribution};
use registration_credentials::{
    contribution_authentication::{CommitmentInventory, VerifiedConfirmation, verify_confirmation},
    roster_authentication::{OrganizerSignedRoster, verify_roster_proposal},
    roster_input::RosterInputVerifier,
};
use std::{cell::RefCell, sync::Arc};

const INPUT_BYTES: usize = 1_572_864;
struct Session {
    input: Vec<u8>,
    roster: Option<RosterInputVerifier>,
    proposal: Option<Arc<OrganizerSignedRoster>>,
    confirmations: Vec<VerifiedConfirmation>,
    inventory: Option<Arc<CommitmentInventory>>,
    opening: Option<OpenedContributionVerifier>,
    verified: Option<VerifiedOpenedContribution>,
}
thread_local! { static SESSION: RefCell<Session> = RefCell::new(Session { input: vec![0;INPUT_BYTES], roster: None, proposal: None, confirmations: Vec::new(), inventory: None, opening: None, verified: None }); }

fn packet(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let length = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
    if length > 1024 || bytes.len() != 4 + length + 3309 {
        return None;
    }
    Some((&bytes[4..4 + length], &bytes[4 + length..]))
}

#[unsafe(no_mangle)]
pub extern "C" fn opening_input_pointer() -> usize {
    SESSION.with(|state| state.borrow_mut().input.as_mut_ptr() as usize)
}

#[unsafe(no_mangle)]
pub extern "C" fn opening_roster_begin(length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Some(bytes) = state.input.get(..length) else {
            return 1;
        };
        let Ok(roster) = RosterInputVerifier::new(bytes) else {
            return 1;
        };
        state.roster = Some(roster);
        state.proposal = None;
        state.confirmations.clear();
        state.inventory = None;
        state.opening = None;
        state.verified = None;
        0
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn opening_roster_record(operation: u32, length: usize) -> u32 {
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
        let result = match operation {
            0 => roster.begin_record(bytes),
            1 => roster.push_key(bytes),
            2 if length == 0 => roster.finish_key(),
            3 => roster.push_proof(bytes),
            4 if length == 0 => roster.finish_record(),
            _ => return 1,
        };
        u32::from(result.is_err())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn opening_roster_finish(length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        if state.proposal.is_some() || length != 3309 {
            return 0;
        }
        let Some(roster) = &state.roster else {
            return 0;
        };
        let Ok(proposal) = roster.finish() else {
            return 0;
        };
        let Ok(proposal) = verify_roster_proposal(proposal, &state.input[..length]) else {
            return 0;
        };
        state.proposal = Some(Arc::new(proposal));
        state.roster = None;
        1
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn opening_confirmation(length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        if state.inventory.is_some() {
            return 1;
        }
        let Some(bytes) = state.input.get(..length) else {
            return 1;
        };
        let Some((body, signature)) = packet(bytes) else {
            return 1;
        };
        let Some(proposal) = &state.proposal else {
            return 1;
        };
        let Ok(confirmation) = verify_confirmation(proposal, body, signature) else {
            return 1;
        };
        if state
            .confirmations
            .iter()
            .any(|old| old.position() == confirmation.position())
        {
            return 1;
        }
        state.confirmations.push(confirmation);
        0
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn opening_inventory_finish() -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        if state.inventory.is_some() {
            return 0;
        }
        let Some(proposal) = state.proposal.clone() else {
            return 0;
        };
        if state.confirmations.len() != proposal.proposal().records().len() {
            return 0;
        }
        let confirmations = std::mem::take(&mut state.confirmations);
        let Ok(inventory) = CommitmentInventory::new(proposal, confirmations) else {
            return 0;
        };
        state.inventory = Some(Arc::new(inventory));
        1
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn opening_begin(length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Some(bytes) = state.input.get(..length) else {
            return 1;
        };
        if bytes.len() < 4 {
            return 1;
        }
        let packet_length = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
        if packet_length > 4 + 1024 + 3309
            || bytes.len() != 4 + packet_length + 12 + word_verifier::HEADER_LENGTH
        {
            return 1;
        }
        let Some((body, signature)) = packet(&bytes[4..4 + packet_length]) else {
            return 1;
        };
        let Some(inventory) = state.inventory.clone() else {
            return 1;
        };
        let start = 4 + packet_length;
        let Ok(opening) = OpenedContributionVerifier::new(
            inventory,
            body,
            signature,
            &bytes[start..start + 12],
            &bytes[start + 12..],
        ) else {
            return 1;
        };
        state.opening = Some(opening);
        state.verified = None;
        0
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn opening_polynomial(index: usize, offset: usize, length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Session { input, opening, .. } = &mut *state;
        let Some(bytes) = input.get(..length) else {
            return 1;
        };
        let Some(opening) = opening.as_mut() else {
            return 1;
        };
        u32::from(opening.polynomial(index, offset, bytes).is_err())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn opening_proof(offset: usize, length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Session { input, opening, .. } = &mut *state;
        let Some(bytes) = input.get(..length) else {
            return 1;
        };
        let Some(opening) = opening.as_mut() else {
            return 1;
        };
        u32::from(opening.proof(offset, bytes).is_err())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn opening_finish() -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Some(opening) = state.opening.take() else {
            return 0;
        };
        let Ok(verified) = opening.finish() else {
            return 0;
        };
        state.verified = Some(verified);
        1
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn opened_position() -> u32 {
    SESSION.with(|state| {
        state
            .borrow()
            .verified
            .as_ref()
            .map_or(0, |value| value.position() as u32 + 1)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn opened_inventory_pointer() -> usize {
    SESSION.with(|state| {
        state
            .borrow()
            .verified
            .as_ref()
            .map_or(0, |value| value.inventory().as_ptr() as usize)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn opened_commitment_pointer() -> usize {
    SESSION.with(|state| {
        state
            .borrow()
            .verified
            .as_ref()
            .map_or(0, |value| value.commitment().as_ptr() as usize)
    })
}
