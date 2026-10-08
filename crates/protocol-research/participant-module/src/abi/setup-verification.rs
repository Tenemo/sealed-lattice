//! The public setup verification, whose verified setup the later stages
//! read.
use protocol_foundations::{
    Credential, poll::VerifiedPoll, roster_authentication::AuthenticatedRosterProposal,
    roster_input::RecordStep, setup_selection::SelectionProposal,
};
use setup_aggregate::{
    CHUNK_BYTES,
    setup_session::{Refused, SETUP_INPUT_BYTES, SetupSession},
    verified::{VerifiedSelectionInputs, VerifiedSetupAggregate},
};
use std::{cell::RefCell, sync::Arc};

thread_local! {static SETUP: RefCell<SetupSession> = RefCell::new(SetupSession::new());}

// Runs one verification step, which answers one when it is refused.
fn step(run: impl FnOnce(&mut SetupSession) -> Result<(), Refused>) -> u32 {
    SETUP.with(|setup| u32::from(run(&mut setup.borrow_mut()).is_err()))
}

/// The verified poll and setup, once this visit's setup verifies.
pub(super) fn verified_setup() -> Option<(Arc<VerifiedPoll>, Arc<VerifiedSetupAggregate>)> {
    SETUP.with(|setup| setup.borrow().verified_setup())
}
pub(super) fn restore_setup(credential: &Credential, retained: &[u8]) -> bool {
    SETUP.with(|setup| setup.borrow_mut().restore_setup(credential, retained))
}
pub(super) fn roster_context() -> Option<(Arc<VerifiedPoll>, Arc<AuthenticatedRosterProposal>)> {
    SETUP.with(|setup| setup.borrow().roster_context())
}
pub(super) fn unsigned_selection() -> Option<SelectionProposal> {
    SETUP.with(|setup| setup.borrow().unsigned_selection())
}
pub(super) fn selection_inputs() -> Option<Arc<VerifiedSelectionInputs>> {
    SETUP.with(|setup| setup.borrow().selection_inputs())
}
pub(super) fn restore_inputs(credential: &Credential, retained: &[u8]) -> bool {
    SETUP.with(|setup| setup.borrow_mut().restore_inputs(credential, retained))
}

#[unsafe(no_mangle)]
pub extern "C" fn setup_input_pointer() -> usize {
    SETUP.with(|setup| setup.borrow_mut().input().as_mut_ptr() as usize)
}
/// The input buffer's length; the host never writes more.
#[unsafe(no_mangle)]
pub extern "C" fn setup_input_capacity() -> usize {
    SETUP_INPUT_BYTES
}
/// The largest aggregated chunk. Its incoming bytes start the input buffer
/// and the previous aggregate follows at this offset.
#[unsafe(no_mangle)]
pub extern "C" fn setup_chunk_capacity() -> usize {
    CHUNK_BYTES
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_roster_begin(length: usize) -> u32 {
    step(|setup| setup.begin_roster_input(length))
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_roster_record(operation: u32, position: usize, length: usize) -> u32 {
    step(|setup| {
        let record = RecordStep::from_code(operation).ok_or(Refused)?;
        setup.roster_record(record, position, length)
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_roster_finish(length: usize) -> u32 {
    step(|setup| setup.finish_roster(length))
}
/// The option count of the poll whose roster this verification verified, or
/// zero before the roster verifies.
#[unsafe(no_mangle)]
pub extern "C" fn setup_option_count() -> usize {
    SETUP.with(|setup| setup.borrow().option_count())
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_output_pointer() -> usize {
    SETUP.with(|setup| setup.borrow().output().as_ptr() as usize)
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_output_length() -> usize {
    SETUP.with(|setup| setup.borrow().output().len())
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_offer_begin(length: usize) -> u32 {
    step(|setup| setup.begin_offer(length))
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_offer_polynomial(index: usize, offset: usize, length: usize) -> u32 {
    step(|setup| setup.offer_polynomial(index, offset, length))
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_offer_proof(offset: usize, length: usize) -> u32 {
    step(|setup| setup.offer_proof(offset, length))
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_offer_finish() -> u32 {
    step(SetupSession::finish_offer)
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_offer_available(position: usize, length: usize) -> u32 {
    SETUP.with(|setup| u32::from(setup.borrow().offer_available(position, length)))
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_selection_build(length: usize) -> u32 {
    step(|setup| setup.propose_selection(length))
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_selection_begin(length: usize) -> u32 {
    step(|setup| setup.begin_selection(length))
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_selection_count() -> usize {
    SETUP.with(|setup| setup.borrow().selection_count())
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_selection_position(ordinal: usize) -> usize {
    SETUP.with(|setup| {
        setup
            .borrow()
            .selection_position(ordinal)
            .unwrap_or(usize::MAX)
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_selection_body_identity_pointer(ordinal: usize) -> usize {
    SETUP.with(|setup| {
        setup
            .borrow()
            .selection_body_identity(ordinal)
            .map_or(0, |identity| identity.as_ptr() as usize)
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_selection_identity_pointer() -> usize {
    SETUP.with(|setup| {
        let mut setup = setup.borrow_mut();
        if setup.output_selection_identity() {
            setup.output().as_ptr() as usize
        } else {
            0
        }
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_selection_aggregate() -> u32 {
    step(SetupSession::aggregate_selection)
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_discard_aggregation() -> u32 {
    SETUP.with(|setup| setup.borrow_mut().discard_aggregation());
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_begin_selected_offer_verification(length: usize) -> u32 {
    step(|setup| setup.begin_selected_offer_verification(length))
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_selected_offer_proof(offset: usize, length: usize) -> u32 {
    step(|setup| setup.selected_offer_proof(offset, length))
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_begin_selected_offer(position: usize) -> u32 {
    step(|setup| setup.begin_selected_offer(position))
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_polynomial(index: usize, offset: usize, length: usize) -> u32 {
    step(|setup| setup.aggregate_polynomial(index, offset, length))
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_finish_selected_offer() -> u32 {
    step(SetupSession::finish_selected_offer)
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_accepted() -> usize {
    SETUP.with(|setup| setup.borrow().accepted())
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_selection_finish() -> u32 {
    step(SetupSession::finish_selection)
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_endorsement(length: usize) -> u32 {
    step(|setup| setup.add_endorsement(length))
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_certificate_build() -> u32 {
    step(SetupSession::build_certificate)
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_certificate(length: usize) -> u32 {
    step(|setup| setup.begin_certificate(length))
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_finish_certificate() -> u32 {
    step(SetupSession::finish_certificate)
}
