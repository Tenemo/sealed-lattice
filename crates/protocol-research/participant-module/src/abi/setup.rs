//! The setup: the participant's selection signatures, the retained selection
//! inputs and setup, and the retirement of the contribution sources.
use super::{SESSION, Session, emitted_packet, original_context, signed_packet};
use crate::offer_signing::OfferSigning;
use protocol_foundations::SIGNATURE_BYTES;
use zeroize::{Zeroize, Zeroizing};

protocol_foundations::operation_codes! {
    /// The participant's selection signing commands.
    enum SelectionOperation {
        UnsignedBody = 0,
        SignProposal = 1,
        Endorse = 2,
        RestoreProposal = 3,
        RestoreEndorsement = 4,
        EndorsementBody = 5,
    }
}
fn selection_operation(
    state: &mut Session,
    operation: u32,
    length: usize,
) -> Result<(), protocol_foundations::Error> {
    use protocol_foundations::{Error, setup_selection};
    let operation = SelectionOperation::from_code(operation);
    if length > state.input.len() {
        return Err(Error::Shape);
    }
    let input = Zeroizing::new(state.input[..length].to_vec());
    state.input[..length].zeroize();
    let context = original_context(state)?;
    let (_, roster) = super::setup_verification::roster_context().ok_or(Error::Context)?;
    if roster.proposal().identity_bytes() != context.identity() {
        return Err(Error::Context);
    }
    match operation {
        Some(SelectionOperation::UnsignedBody) => {
            if !input.is_empty() {
                return Err(Error::Shape);
            }
            let selection =
                super::setup_verification::unsigned_selection().ok_or(Error::Context)?;
            if selection.roster_identity() != context.identity() {
                return Err(Error::Context);
            }
            state.contribution_output = selection.body().to_vec();
            state.unsigned_selection = Some(selection);
        }
        Some(SelectionOperation::SignProposal) => {
            if !input.is_empty() {
                return Err(Error::Shape);
            }
            let selection = state.unsigned_selection.as_ref().ok_or(Error::Context)?;
            let signature = state
                .enrollment
                .as_mut()
                .ok_or(Error::Context)?
                .credential
                .sign_selection_proposal(&roster, selection)?;
            state.contribution_output = emitted_packet(selection.body(), &signature);
        }
        Some(SelectionOperation::Endorse | SelectionOperation::EndorsementBody) => {
            let inputs = super::setup_verification::selection_inputs().ok_or(Error::Context)?;
            if inputs.roster().proposal().identity_bytes() != context.identity() {
                return Err(Error::Context);
            }
            let selection = inputs.selection().selection();
            state.contribution_output = if operation == Some(SelectionOperation::Endorse) {
                if !input.is_empty() {
                    return Err(Error::Shape);
                }
                state
                    .enrollment
                    .as_mut()
                    .ok_or(Error::Context)?
                    .credential
                    .endorse_selection(&roster, selection, context.position())?
            } else {
                if !input.is_empty() {
                    return Err(Error::Shape);
                }
                setup_selection::endorsement_body(selection.identity(), context.position())?
            };
        }
        Some(SelectionOperation::RestoreProposal) => {
            let (body, signature) = signed_packet(&input).ok_or(Error::Shape)?;
            let proposal = setup_selection::authenticate_selection(roster, body, signature)?;
            state
                .enrollment
                .as_mut()
                .ok_or(Error::Context)?
                .credential
                .restore_selection_proposal(&proposal)?;
        }
        Some(SelectionOperation::RestoreEndorsement) => {
            let prefix = input.get(..4).ok_or(Error::Shape)?;
            let length = u32::from_le_bytes(prefix.try_into().unwrap()) as usize;
            if length > setup_selection::MAXIMUM_SELECTION_BYTES
                || input.len() != 4 + length + SIGNATURE_BYTES + setup_selection::ENDORSEMENT_BYTES
            {
                return Err(Error::Shape);
            }
            let proposal = setup_selection::authenticate_selection(
                roster.clone(),
                &input[4..4 + length],
                &input[4 + length..4 + length + SIGNATURE_BYTES],
            )?;
            let endorsement = setup_selection::authenticate_endorsement(
                &roster,
                proposal.selection(),
                &input[4 + length + SIGNATURE_BYTES..],
            )?;
            state
                .enrollment
                .as_mut()
                .ok_or(Error::Context)?
                .credential
                .restore_selection_endorsement(&roster, &endorsement)?;
        }
        None => return Err(Error::Shape),
    }
    Ok(())
}
#[unsafe(no_mangle)]
pub extern "C" fn selection_signing_command(operation: u32, length: usize) -> u32 {
    SESSION.with(|state| {
        u32::from(selection_operation(&mut state.borrow_mut(), operation, length).is_err())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn retain_selection_inputs() -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        state.contribution_output.clear();
        let Some(enrollment) = state.enrollment.as_ref() else {
            return 1;
        };
        let Some((poll, _)) = super::setup_verification::roster_context() else {
            return 1;
        };
        let Some(inputs) = super::setup_verification::selection_inputs() else {
            return 1;
        };
        let Ok(retained) = inputs.retain(&enrollment.credential, &poll) else {
            return 1;
        };
        state.contribution_output = retained;
        0
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn restore_selection_inputs(length: usize) -> u32 {
    SESSION.with(|state| {
        let state = state.borrow();
        let (Some(enrollment), Some(bytes)) =
            (state.enrollment.as_ref(), state.input.get(..length))
        else {
            return 1;
        };
        u32::from(!super::setup_verification::restore_inputs(
            &enrollment.credential,
            bytes,
        ))
    })
}

/// Emits the retained setup reference from this instance's completed owning
/// setup verifier, keyed to the restored credential. No caller-supplied digest
/// or status can enter it.
#[unsafe(no_mangle)]
pub extern "C" fn retain_setup() -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        state.contribution_output.clear();
        let Some(enrollment) = state.enrollment.as_ref() else {
            return 1;
        };
        let Some((poll, setup)) = super::setup_verification::verified_setup() else {
            return 1;
        };
        let Ok(reference) =
            crate::ballot::retained_setup_reference(&enrollment.credential, &poll, &setup)
        else {
            return 1;
        };
        state.contribution_output = reference;
        0
    })
}

/// The worker calls retirement only after authenticated setup retention and
/// durable deletion of the source capsule and its wrapping key.
#[unsafe(no_mangle)]
pub extern "C" fn retire_contribution_sources() -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Some(enrollment) = state.enrollment.as_ref() else {
            return 1;
        };
        if enrollment.sources_retired() {
            return 1;
        }
        let Some((poll, setup)) = super::setup_verification::verified_setup() else {
            return 1;
        };
        let Some(original) = super::own_verification::verified() else {
            return 1;
        };
        let proposal = setup.roster().proposal();
        let Some(position) = proposal.records().iter().position(|record| {
            record.body_digest() == original.body_digest()
                && record.header().signing_public == *enrollment.credential.signing_public()
        }) else {
            return 1;
        };
        let same_context = if let Some(context) = state.retained_context.as_ref() {
            context.position() == position && *context.identity() == proposal.identity()
        } else {
            state
                .signed_proposal
                .as_ref()
                .is_some_and(|held| held.proposal().identity() == proposal.identity())
        };
        if !same_context
            || poll.identity() != state.poll_identity
            || poll.identity() != original.header().poll
            || poll.runtime() != original.header().runtime
        {
            return 1;
        }
        state.enrollment.as_mut().unwrap().retire_sources();
        state.offer = OfferSigning::default();
        state.unsigned_selection = None;
        super::contribution::retire();
        0
    })
}

/// Restores the verified setup from the retained setup reference and its
/// tag, once the setup verifier holds this visit's verified roster and
/// selection certificate, instead of verifying every selected offer again.
#[unsafe(no_mangle)]
pub extern "C" fn restore_setup(length: usize) -> u32 {
    SESSION.with(|state| {
        let state = state.borrow();
        let (Some(enrollment), Some(retained)) =
            (state.enrollment.as_ref(), state.input.get(..length))
        else {
            return 1;
        };
        u32::from(!super::setup_verification::restore_setup(
            &enrollment.credential,
            retained,
        ))
    })
}
