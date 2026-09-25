use crate::{
    CHUNK_BYTES,
    verified::{SetupAggregator, VerifiedSetupAggregate},
};
use registration_credentials::{
    contribution_authentication::{CommitmentInventory, VerifiedConfirmation, verify_confirmation},
    poll::VerifiedPoll,
    roster_authentication::{OrganizerSignedRoster, verify_roster_proposal},
    roster_input::RosterInputVerifier,
};
use std::{cell::RefCell, sync::Arc};
use supported_profile::relation::PROOF_HEADER_BYTES;

const INPUT_BYTES: usize = 1_572_864;
struct Session {
    input: Vec<u8>,
    roster: Option<RosterInputVerifier>,
    proposal: Option<Arc<OrganizerSignedRoster>>,
    poll: Option<Arc<VerifiedPoll>>,
    confirmations: Vec<VerifiedConfirmation>,
    aggregator: Option<SetupAggregator>,
    verified: Option<Arc<VerifiedSetupAggregate>>,
    inventory: [u8; 64],
}
thread_local! { static SESSION: RefCell<Session> = RefCell::new(Session {
    input: vec![0; INPUT_BYTES], roster: None, proposal: None, poll: None, confirmations: Vec::new(), aggregator: None, verified: None, inventory: [0;64],
}); }

pub fn context() -> Option<(Arc<VerifiedPoll>, Arc<VerifiedSetupAggregate>)> {
    SESSION.with(|value| {
        let value = value.borrow();
        Some((value.poll.clone()?, value.verified.clone()?))
    })
}
fn packet(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let length = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
    if length > 1024 || bytes.len() != 4 + length + 3309 {
        return None;
    }
    Some((&bytes[4..4 + length], &bytes[4 + length..]))
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_input_pointer() -> usize {
    SESSION.with(|value| value.borrow_mut().input.as_mut_ptr() as usize)
}
/// The input buffer's length; the host never writes more.
#[unsafe(no_mangle)]
pub extern "C" fn setup_input_capacity() -> usize {
    INPUT_BYTES
}
/// The largest aggregated chunk. Its incoming bytes start the input buffer
/// and the previous aggregate follows at this offset.
#[unsafe(no_mangle)]
pub extern "C" fn setup_chunk_capacity() -> usize {
    CHUNK_BYTES
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_roster_begin(length: usize) -> u32 {
    SESSION.with(|value| {
        let mut value = value.borrow_mut();
        let Some(bytes) = value.input.get(..length) else {
            return 1;
        };
        let Ok(roster) = RosterInputVerifier::new(bytes) else {
            return 1;
        };
        value.roster = Some(roster);
        value.proposal = None;
        value.poll = None;
        value.confirmations.clear();
        value.aggregator = None;
        value.verified = None;
        value.inventory.fill(0);
        0
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_roster_record(operation: u32, length: usize) -> u32 {
    SESSION.with(|value| {
        let mut value = value.borrow_mut();
        let Session {
            input,
            roster,
            proposal,
            ..
        } = &mut *value;
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
pub extern "C" fn setup_roster_finish(length: usize) -> u32 {
    SESSION.with(|value| {
        let mut value = value.borrow_mut();
        if value.proposal.is_some() || length != 3309 {
            return 0;
        }
        let Some(roster) = &value.roster else {
            return 0;
        };
        let Ok(proposal) = roster.finish() else {
            return 0;
        };
        let Ok(proposal) = verify_roster_proposal(proposal, &value.input[..length]) else {
            return 0;
        };
        value.proposal = Some(Arc::new(proposal));
        value.poll = Some(Arc::new(value.roster.take().unwrap().into_poll()));
        1
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_confirmation(length: usize) -> u32 {
    SESSION.with(|value| {
        let mut value = value.borrow_mut();
        if value.aggregator.is_some() || value.verified.is_some() {
            return 1;
        }
        let Some(bytes) = value.input.get(..length) else {
            return 1;
        };
        let Some((body, signature)) = packet(bytes) else {
            return 1;
        };
        let Some(proposal) = &value.proposal else {
            return 1;
        };
        let Ok(confirmation) = verify_confirmation(proposal, body, signature) else {
            return 1;
        };
        if value
            .confirmations
            .iter()
            .any(|old| old.position() == confirmation.position())
        {
            return 1;
        }
        value.confirmations.push(confirmation);
        0
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_inventory_finish() -> u32 {
    SESSION.with(|value| {
        let mut value = value.borrow_mut();
        if value.aggregator.is_some() || value.verified.is_some() {
            return 0;
        }
        let Some(proposal) = value.proposal.clone() else {
            return 0;
        };
        if value.confirmations.len() != proposal.proposal().records().len() {
            return 0;
        }
        let confirmations = std::mem::take(&mut value.confirmations);
        let Ok(inventory) = CommitmentInventory::new(proposal, confirmations) else {
            return 0;
        };
        let Ok(aggregator) = SetupAggregator::new(Arc::new(inventory)) else {
            return 0;
        };
        value.aggregator = Some(aggregator);
        1
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_begin_opening(length: usize) -> u32 {
    SESSION.with(|value| {
        let mut value = value.borrow_mut();
        let Session {
            input, aggregator, ..
        } = &mut *value;
        let Some(bytes) = input.get(..length) else {
            return 1;
        };
        let Some(prefix) = bytes.get(..4) else {
            return 1;
        };
        let packet_length = u32::from_le_bytes(prefix.try_into().unwrap()) as usize;
        if packet_length > 4 + 1024 + 3309
            || bytes.len() != 4 + packet_length + 12 + PROOF_HEADER_BYTES
        {
            return 1;
        }
        let Some((body, signature)) = packet(&bytes[4..4 + packet_length]) else {
            return 1;
        };
        let Some(aggregator) = aggregator else {
            return 1;
        };
        let start = 4 + packet_length;
        u32::from(
            aggregator
                .begin(
                    body,
                    signature,
                    &bytes[start..start + 12],
                    &bytes[start + 12..],
                )
                .is_err(),
        )
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_polynomial(index: usize, offset: usize, length: usize) -> u32 {
    SESSION.with(|value| {
        let mut value = value.borrow_mut();
        let Session {
            input, aggregator, ..
        } = &mut *value;
        let Some(aggregator) = aggregator else {
            return 1;
        };
        if length > CHUNK_BYTES {
            return 1;
        }
        let (incoming, previous) = input.split_at_mut(CHUNK_BYTES);
        u32::from(
            aggregator
                .polynomial(index, offset, &incoming[..length], &mut previous[..length])
                .is_err(),
        )
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_proof(offset: usize, length: usize) -> u32 {
    SESSION.with(|value| {
        let mut value = value.borrow_mut();
        let Session {
            input, aggregator, ..
        } = &mut *value;
        let Some(bytes) = input.get(..length) else {
            return 1;
        };
        let Some(aggregator) = aggregator else {
            return 1;
        };
        u32::from(aggregator.proof(offset, bytes).is_err())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_finish_contribution() -> u32 {
    SESSION.with(|value| {
        value
            .borrow_mut()
            .aggregator
            .as_mut()
            .map_or(0, |aggregator| {
                u32::from(aggregator.finish_contribution().is_ok())
            })
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_accepted() -> usize {
    SESSION.with(|value| {
        value
            .borrow()
            .aggregator
            .as_ref()
            .map_or(0, SetupAggregator::accepted)
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_finish() -> u32 {
    SESSION.with(|value| {
        let mut value = value.borrow_mut();
        if value
            .aggregator
            .as_ref()
            .is_none_or(|aggregator| !aggregator.complete())
        {
            return 0;
        }
        let Ok(verified) = value.aggregator.take().unwrap().finish() else {
            return 0;
        };
        value.inventory = verified.inventory().identity();
        value.verified = Some(Arc::new(verified));
        1
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_inventory_pointer() -> usize {
    SESSION.with(|value| {
        let value = value.borrow();
        if value.verified.is_none() {
            0
        } else {
            value.inventory.as_ptr() as usize
        }
    })
}
