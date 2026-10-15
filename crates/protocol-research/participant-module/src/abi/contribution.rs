//! The contribution: its offer signing, its proof and checkpoints, and the
//! retained proposal it names.
use super::{SESSION, Session, original_context};
use crate::contribution_session::{CONTRIBUTION_INPUT_BYTES, ContributionSession};
use protocol_foundations::{roster::RetainedContributionContext, signed_packet};
use std::cell::RefCell;
use zeroize::{Zeroize, Zeroizing};
protocol_foundations::operation_codes! {
    /// The offer signing commands.
    enum OfferSigningOperation {
        BeginBody = 1,
        Polynomial = 2,
        Proof = 3,
        FinishBody = 4,
        SignOffer = 5,
        BodyHeader = 8,
    }
}
fn offer_operation(
    state: &mut Session,
    operation: u32,
    argument: usize,
    length: usize,
) -> Result<(), protocol_foundations::Refusal> {
    use protocol_foundations::Refusal;
    let operation = OfferSigningOperation::from_code(operation);
    if length > state.input.len()
        || (!matches!(
            operation,
            Some(OfferSigningOperation::Polynomial | OfferSigningOperation::Proof)
        ) && argument != 0)
    {
        return Err(Refusal::Shape);
    }
    let input = Zeroizing::new(state.input[..length].to_vec());
    state.input[..length].zeroize();
    let context = original_context(state)?;
    match operation {
        Some(OfferSigningOperation::BeginBody | OfferSigningOperation::BodyHeader) => {
            if input.len() != 10
                || usize::from(u16::from_le_bytes(input[..2].try_into().unwrap()))
                    != context.position()
            {
                return Err(Refusal::Shape);
            }
            let proof_length = usize::try_from(u64::from_le_bytes(input[2..].try_into().unwrap()))
                .map_err(|_| Refusal::Shape)?;
            let enrollment = state.enrollment.as_ref().ok_or(Refusal::Context)?;
            enrollment.credential.validate_offer_owner(&context)?;
            let header = protocol_foundations::contribution_body::body_header(
                context.profile(),
                proof_length,
            )
            .map_err(|_| Refusal::Context)?;
            if operation == Some(OfferSigningOperation::BeginBody) {
                let original_coordinate = super::own_registration::with_poll(|poll| {
                    enrollment.contribution_coordinate_hash(poll, context.profile())
                })
                .ok_or(Refusal::Context)?
                .map_err(|_| Refusal::Context)?;
                state.offer.begin_body(
                    &enrollment.credential,
                    context,
                    &header,
                    original_coordinate,
                )?;
            }
            state.participant_output = header.to_vec();
        }
        Some(OfferSigningOperation::Polynomial) => {
            if !(5..=4 + (1 << 20)).contains(&input.len()) {
                return Err(Refusal::Shape);
            }
            let offset = u32::from_le_bytes(input[..4].try_into().unwrap()) as usize;
            state.offer.polynomial(argument, offset, &input[4..])?;
        }
        Some(OfferSigningOperation::Proof) => state.offer.proof(argument, &input)?,
        Some(OfferSigningOperation::FinishBody) => {
            if !input.is_empty() {
                return Err(Refusal::Shape);
            }
            state.offer.finish_body()?;
            state.participant_output = state
                .offer
                .envelope()
                .ok_or(Refusal::Consumed)?
                .bytes()
                .to_vec();
        }
        Some(OfferSigningOperation::SignOffer) => {
            if !input.is_empty() {
                return Err(Refusal::Shape);
            }
            let credential = &mut state
                .enrollment
                .as_mut()
                .ok_or(Refusal::Context)?
                .credential;
            state.offer.sign(credential)?;
            let (envelope, signature) = state.offer.offer().ok_or(Refusal::Consumed)?;
            state.participant_output = signed_packet::encode(envelope.bytes(), signature);
        }
        None => return Err(Refusal::Shape),
    }
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn offer_signing_command(operation: u32, argument: usize, length: usize) -> u32 {
    SESSION.with(|state| {
        u32::from(offer_operation(&mut state.borrow_mut(), operation, argument, length).is_err())
    })
}

// The host receives each chunk of the public setup objects in order.
fn send_public_chunk(object: usize, offset: usize, bytes: &[u8]) {
    #[link(wasm_import_module = "contribution")]
    unsafe extern "C" {
        fn public_chunk(object: u32, offset: u32, pointer: *const u8, length: usize) -> u32;
    }
    assert_eq!(
        unsafe { public_chunk(object as u32, offset as u32, bytes.as_ptr(), bytes.len()) },
        0
    );
}

thread_local! {static CONTRIBUTION: RefCell<ContributionSession> = RefCell::new(ContributionSession::new(Box::new(send_public_chunk)));}

/// Drops the completed contribution's private prover state and its
/// remaining random stream state.
pub(super) fn retire() {
    CONTRIBUTION.with(|session| session.borrow_mut().retire());
    super::operation_random::retire_contribution();
}

#[unsafe(no_mangle)]
pub extern "C" fn begin_contribution(position: usize) -> u32 {
    SESSION.with(|state| {
        let state = state.borrow();
        if state.offer.body_started() {
            return 1;
        }
        let Ok(context) = original_context(&state) else {
            return 1;
        };
        if context.position() != position {
            return 1;
        }
        let Some(enrollment) = state.enrollment.as_ref() else {
            return 1;
        };
        let Some(proposal) = state.signed_proposal.as_ref() else {
            return 1;
        };
        if proposal.proposal().identity_bytes() != context.identity() {
            return 1;
        }
        if enrollment
            .credential
            .validate_offer_context(&context)
            .is_err()
        {
            return 1;
        }
        let Some(Ok(source)) = super::own_registration::with_poll(|poll| {
            enrollment.contribution_source(poll, proposal.proposal().profile())
        }) else {
            return 1;
        };
        let Ok(source) = enrollment
            .credential
            .source_contribution(proposal, position, source)
        else {
            return 1;
        };
        CONTRIBUTION.with(|session| {
            u32::from(
                session
                    .borrow_mut()
                    .begin_verified(proposal.proposal(), position, source)
                    .is_err(),
            )
        })
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn contribution_proof_input_pointer() -> usize {
    CONTRIBUTION.with(|session| session.borrow_mut().input().as_mut_ptr() as usize)
}

/// The input buffer's length; the host never writes more.
#[unsafe(no_mangle)]
pub extern "C" fn contribution_proof_input_capacity() -> usize {
    CONTRIBUTION_INPUT_BYTES
}

#[unsafe(no_mangle)]
pub extern "C" fn contribution_proof_command(
    operation: u32,
    argument: usize,
    length: usize,
) -> u32 {
    CONTRIBUTION.with(|session| {
        u32::from(
            session
                .borrow_mut()
                .command(operation, argument, length)
                .is_err(),
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn contribution_proof_phase() -> u32 {
    CONTRIBUTION.with(|session| session.borrow().phase())
}

#[unsafe(no_mangle)]
pub extern "C" fn contribution_proof_output_pointer() -> usize {
    CONTRIBUTION.with(|session| session.borrow().output().as_ptr() as usize)
}

#[unsafe(no_mangle)]
pub extern "C" fn contribution_proof_output_length() -> usize {
    CONTRIBUTION.with(|session| session.borrow().output().len())
}

#[unsafe(no_mangle)]
pub extern "C" fn contribution_checkpoint_records() -> usize {
    CONTRIBUTION.with(|session| session.borrow().checkpoint_records())
}

#[unsafe(no_mangle)]
pub extern "C" fn contribution_checkpoint_command(
    operation: u32,
    position: usize,
    length: usize,
) -> u32 {
    SESSION.with(|state| {
        let state = state.borrow();
        let (Some(enrollment), Some(context)) =
            (state.enrollment.as_ref(), state.retained_context.as_ref())
        else {
            return 1;
        };
        if enrollment.sources_retired()
            || enrollment
                .credential
                .validate_offer_context(context)
                .is_err()
        {
            return 1;
        }
        CONTRIBUTION.with(|session| {
            u32::from(
                session
                    .borrow_mut()
                    .checkpoint_command(operation, position, length, context)
                    .is_err(),
            )
        })
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn contribution_checkpoint_key(position: usize, length: usize) -> u32 {
    CONTRIBUTION.with(|session| {
        u32::from(
            session
                .borrow_mut()
                .checkpoint_key(position, length)
                .is_err(),
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn retain_proposal(length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        // The proposal names the poll of this instance's verified
        // registration, which fixes the option count.
        let Some(verified) = super::own_registration::verified() else {
            return 1;
        };
        let Some(enrollment) = state.enrollment.as_ref() else {
            return 1;
        };
        if !(70..=state.input.len()).contains(&length)
            || state.retained_context.is_some()
            || state.offer.body_started()
            || CONTRIBUTION.with(|session| session.borrow().phase()) != 0
        {
            return 1;
        }
        let input = &state.input[..length];
        let body_length = u32::from_le_bytes(input[66..70].try_into().unwrap()) as usize;
        if body_length > protocol_foundations::roster::MAXIMUM_PROPOSAL_BYTES
            || length != 70 + body_length
            || input[..64] != verified.header().poll
        {
            return 1;
        }
        let Some(Ok(context)) = super::own_registration::with_poll(|poll| {
            RetainedContributionContext::parse(
                &enrollment.credential,
                &verified,
                poll,
                u16::from_le_bytes(input[64..66].try_into().unwrap()) as usize,
                &input[70..],
            )
        }) else {
            return 1;
        };
        if state
            .signed_proposal
            .as_ref()
            .is_some_and(|proposal| proposal.proposal().identity_bytes() != context.identity())
        {
            return 1;
        }
        state.retained_context = Some(context);
        state.started = true;
        0
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn retained_proposal_identity_pointer() -> usize {
    SESSION.with(|state| {
        state
            .borrow()
            .retained_context
            .as_ref()
            .map_or(0, |context| context.identity().as_ptr() as usize)
    })
}
