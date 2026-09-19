use crate::{
    contribution_authentication::{
        CommitmentInventory, VerifiedConfirmation, verify_confirmation, verify_opening,
    },
    contribution_commitment::ContributionCommitmentHasher,
    roster::RosterProposal,
    roster_authentication::{OrganizerSignedRoster, verify_roster_proposal},
    roster_input::RosterInputVerifier,
};
use std::{cell::RefCell, sync::Arc};

const INPUT_BYTES: usize = 1_572_864;
struct Work {
    verifier: RosterInputVerifier,
    proposal: Option<RosterProposal>,
    role: Vec<u8>,
    commitment_hash: Option<ContributionCommitmentHasher>,
    commitment: Option<[u8; 64]>,
    signed_proposal: Option<Arc<OrganizerSignedRoster>>,
    confirmations: Vec<VerifiedConfirmation>,
    inventory: Option<CommitmentInventory>,
}
struct Session {
    input: Vec<u8>,
    work: Option<Work>,
}
thread_local! {static SESSION:RefCell<Session>=RefCell::new(Session{input:vec![0;INPUT_BYTES],work:None});}
#[unsafe(no_mangle)]
pub extern "C" fn roster_input_pointer() -> usize {
    SESSION.with(|state| state.borrow_mut().input.as_mut_ptr() as usize)
}
#[unsafe(no_mangle)]
pub extern "C" fn roster_begin(length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Some(input) = state.input.get(..length) else {
            return 1;
        };
        let Ok(verifier) = RosterInputVerifier::new(input) else {
            return 1;
        };
        state.work = Some(Work {
            verifier,
            proposal: None,
            role: Vec::new(),
            commitment_hash: None,
            commitment: None,
            signed_proposal: None,
            confirmations: Vec::new(),
            inventory: None,
        });
        0
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn roster_record_begin(length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Session { input, work } = &mut *state;
        let Some(work) = work.as_mut() else {
            return 1;
        };
        if work.proposal.is_some() {
            return 1;
        }
        let Some(bytes) = input.get(..length) else {
            return 1;
        };
        u32::from(work.verifier.begin_record(bytes).is_err())
    })
}
fn advance(length: usize, proof: bool) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Session { input, work } = &mut *state;
        let Some(work) = work.as_mut() else {
            return 1;
        };
        let Some(bytes) = input.get(..length) else {
            return 1;
        };
        let result = if proof {
            work.verifier.push_proof(bytes)
        } else {
            work.verifier.push_key(bytes)
        };
        u32::from(result.is_err())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn roster_record_key(length: usize) -> u32 {
    advance(length, false)
}
#[unsafe(no_mangle)]
pub extern "C" fn roster_record_proof(length: usize) -> u32 {
    advance(length, true)
}
#[unsafe(no_mangle)]
pub extern "C" fn roster_record_key_finish() -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Some(work) = state.work.as_mut() else {
            return 1;
        };
        u32::from(work.verifier.finish_key().is_err())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn roster_record_finish() -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Some(work) = state.work.as_mut() else {
            return 1;
        };
        u32::from(work.verifier.finish_record().is_err())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn roster_finish() -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Some(work) = state.work.as_mut() else {
            return 0;
        };
        let Ok(proposal) = work.verifier.finish() else {
            return 0;
        };
        work.proposal = Some(proposal);
        1
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn roster_body_pointer() -> usize {
    SESSION.with(|state| {
        state
            .borrow()
            .work
            .as_ref()
            .and_then(|w| w.proposal.as_ref())
            .map_or(0, |value| value.body().as_ptr() as usize)
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn roster_body_length() -> usize {
    SESSION.with(|state| {
        state
            .borrow()
            .work
            .as_ref()
            .and_then(|w| w.proposal.as_ref())
            .map_or(0, |value| value.body().len())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn roster_identity_pointer() -> usize {
    SESSION.with(|state| {
        state
            .borrow()
            .work
            .as_ref()
            .and_then(|w| w.proposal.as_ref())
            .map_or(0, |value| value.identity_bytes().as_ptr() as usize)
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn roster_contribution_role(position: usize) -> usize {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Some(work) = state.work.as_mut() else {
            return 0;
        };
        let Some(proposal) = work.proposal.as_ref() else {
            return 0;
        };
        let Ok(role) = proposal.contribution_role(position) else {
            return 0;
        };
        work.role = role;
        work.role.len()
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn roster_role_pointer() -> usize {
    SESSION.with(|state| {
        state
            .borrow()
            .work
            .as_ref()
            .map_or(0, |value| value.role.as_ptr() as usize)
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn roster_key_pointer(position: usize) -> usize {
    SESSION.with(|state| {
        state
            .borrow()
            .work
            .as_ref()
            .and_then(|w| w.proposal.as_ref())
            .and_then(|p| p.records().get(position))
            .map_or(0, |r| r.public_key().as_ptr() as usize)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn commitment_begin(length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Session { input, work } = &mut *state;
        let Some(work) = work.as_mut() else {
            return 1;
        };
        if length != 78 || work.commitment_hash.is_some() {
            return 1;
        }
        let Some(proposal) = work.proposal.as_ref() else {
            return 1;
        };
        let position = u16::from_le_bytes(input[..2].try_into().unwrap()) as usize;
        let Ok(hash) = ContributionCommitmentHasher::new(
            proposal,
            position,
            input[2..66].try_into().unwrap(),
            &input[66..78],
        ) else {
            return 1;
        };
        work.commitment_hash = Some(hash);
        work.commitment = None;
        0
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn commitment_polynomial(index: usize, offset: usize, length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Session { input, work } = &mut *state;
        if length > 1 << 20 {
            return 1;
        }
        let Some(hash) = work.as_mut().and_then(|work| work.commitment_hash.as_mut()) else {
            return 1;
        };
        u32::from(
            hash.push_polynomial(index, offset, &input[..length])
                .is_err(),
        )
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn commitment_proof(offset: usize, length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Session { input, work } = &mut *state;
        if length > 1 << 20 {
            return 1;
        }
        let Some(hash) = work.as_mut().and_then(|work| work.commitment_hash.as_mut()) else {
            return 1;
        };
        u32::from(hash.push_proof(offset, &input[..length]).is_err())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn commitment_finish() -> usize {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Some(work) = state.work.as_mut() else {
            return 0;
        };
        let Some(hash) = work.commitment_hash.as_mut() else {
            return 0;
        };
        let Ok(digest) = hash.finish() else {
            return 0;
        };
        work.commitment = Some(*digest.digest());
        work.commitment_hash = None;
        64
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn commitment_digest_pointer() -> usize {
    SESSION.with(|state| {
        state
            .borrow()
            .work
            .as_ref()
            .and_then(|work| work.commitment.as_ref())
            .map_or(0, |bytes| bytes.as_ptr() as usize)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn roster_authenticate(length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Session { input, work } = &mut *state;
        let Some(work) = work.as_mut() else {
            return 1;
        };
        if length != 3309 || work.proposal.is_none() || work.signed_proposal.is_some() {
            return 1;
        }
        let Ok(proposal) = work.verifier.finish() else {
            return 1;
        };
        let Ok(signed) = verify_roster_proposal(proposal, &input[..length]) else {
            return 1;
        };
        work.signed_proposal = Some(Arc::new(signed));
        0
    })
}

fn signed_message(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    if bytes.len() < 4 {
        return None;
    }
    let length = u32::from_le_bytes(bytes[..4].try_into().ok()?) as usize;
    if length > 1024 || bytes.len() != 4 + length + 3309 {
        return None;
    }
    Some((&bytes[4..4 + length], &bytes[4 + length..]))
}

#[unsafe(no_mangle)]
pub extern "C" fn confirmation_accept(length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Session { input, work } = &mut *state;
        let Some(bytes) = input.get(..length) else {
            return 1;
        };
        let Some((body, signature)) = signed_message(bytes) else {
            return 1;
        };
        let Some(work) = work.as_mut() else {
            return 1;
        };
        if work.inventory.is_some() {
            return 1;
        }
        let Some(proposal) = &work.signed_proposal else {
            return 1;
        };
        let Ok(confirmation) = verify_confirmation(proposal, body, signature) else {
            return 1;
        };
        if work
            .confirmations
            .iter()
            .any(|existing| existing.position() == confirmation.position())
        {
            return 1;
        }
        work.confirmations.push(confirmation);
        0
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn inventory_finish() -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Some(work) = state.work.as_mut() else {
            return 0;
        };
        if work.inventory.is_some() {
            return 0;
        }
        let Some(proposal) = &work.signed_proposal else {
            return 0;
        };
        if work.confirmations.len() != proposal.proposal().records().len() {
            return 0;
        }
        let Ok(inventory) =
            CommitmentInventory::new(proposal.clone(), std::mem::take(&mut work.confirmations))
        else {
            return 0;
        };
        work.inventory = Some(inventory);
        1
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn inventory_identity_pointer() -> usize {
    SESSION.with(|state| {
        state
            .borrow()
            .work
            .as_ref()
            .and_then(|work| work.inventory.as_ref())
            .map_or(0, |inventory| inventory.identity_bytes().as_ptr() as usize)
    })
}

/// Returns authenticated header position plus one, or zero on refusal.
/// Body commitment and setup-proof verification are separate predicates.
#[unsafe(no_mangle)]
pub extern "C" fn opening_authenticate(length: usize) -> u32 {
    SESSION.with(|state| {
        let state = state.borrow();
        let Some(bytes) = state.input.get(..length) else {
            return 0;
        };
        let Some((body, signature)) = signed_message(bytes) else {
            return 0;
        };
        let Some(inventory) = state.work.as_ref().and_then(|work| work.inventory.as_ref()) else {
            return 0;
        };
        verify_opening(inventory, body, signature)
            .map_or(0, |opening| opening.position() as u32 + 1)
    })
}
