//! The contribution: its offer signing, its proof and checkpoints, and the
//! retained proposal it names.
use super::{SESSION, Session, emitted_packet, original_context, signed_packet};
use protocol_foundations::roster::RetainedContributionContext;
use zeroize::{Zeroize, Zeroizing};
fn offer_operation(
    state: &mut Session,
    operation: u32,
    argument: usize,
    length: usize,
) -> Result<(), protocol_foundations::Error> {
    use protocol_foundations::Error;
    if length > state.input.len() || (!matches!(operation, 2 | 3) && argument != 0) {
        return Err(Error::Shape);
    }
    let input = Zeroizing::new(state.input[..length].to_vec());
    state.input[..length].zeroize();
    let context = original_context(state)?;
    match operation {
        1 | 8 => {
            if input.len() != 10
                || usize::from(u16::from_le_bytes(input[..2].try_into().unwrap()))
                    != context.position()
            {
                return Err(Error::Shape);
            }
            let proof_length = usize::try_from(u64::from_le_bytes(input[2..].try_into().unwrap()))
                .map_err(|_| Error::Shape)?;
            let enrollment = state.enrollment.as_ref().ok_or(Error::Context)?;
            enrollment.credential.validate_offer_owner(&context)?;
            let header = enrollment
                .contribution_header(context.profile(), proof_length)
                .map_err(|_| Error::Context)?;
            if operation == 1 {
                state
                    .offer
                    .begin_body(&enrollment.credential, context, &header)?;
            }
            state.contribution_output = header.to_vec();
        }
        2 => {
            if !(5..=4 + (1 << 20)).contains(&input.len()) {
                return Err(Error::Shape);
            }
            let offset = u32::from_le_bytes(input[..4].try_into().unwrap()) as usize;
            state.offer.polynomial(argument, offset, &input[4..])?;
        }
        3 => state.offer.proof(argument, &input)?,
        4 | 6 => {
            if !input.is_empty() {
                return Err(Error::Shape);
            }
            if operation == 4 {
                state.offer.finish_body()?;
            }
            state.contribution_output = state
                .offer
                .envelope()
                .ok_or(Error::Consumed)?
                .bytes()
                .to_vec();
        }
        5 => {
            if !input.is_empty() {
                return Err(Error::Shape);
            }
            let credential = &mut state.enrollment.as_mut().ok_or(Error::Context)?.credential;
            state.offer.sign(credential)?;
            let (envelope, signature) = state.offer.offer().ok_or(Error::Consumed)?;
            state.contribution_output = emitted_packet(envelope.bytes(), signature);
        }
        7 => {
            let (envelope, signature) = signed_packet(&input).ok_or(Error::Shape)?;
            let credential = &mut state.enrollment.as_mut().ok_or(Error::Context)?.credential;
            state.offer.restore(credential, envelope, signature)?;
        }
        _ => return Err(Error::Shape),
    }
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn offer_signing_command(operation: u32, argument: usize, length: usize) -> u32 {
    SESSION.with(|state| {
        u32::from(offer_operation(&mut state.borrow_mut(), operation, argument, length).is_err())
    })
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
        let Ok(source) = enrollment.contribution_source(proposal.proposal().profile()) else {
            return 1;
        };
        u32::from(
            contribution_prover::browser::begin_verified(proposal.proposal(), position, source)
                .is_err(),
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn contribution_proof_input_pointer() -> usize {
    contribution_prover::browser::input_pointer()
}

#[unsafe(no_mangle)]
pub extern "C" fn contribution_proof_input_capacity() -> usize {
    contribution_prover::browser::input_capacity()
}

#[unsafe(no_mangle)]
pub extern "C" fn contribution_proof_command(
    operation: u32,
    argument: usize,
    length: usize,
) -> u32 {
    contribution_prover::browser::command(operation, argument, length)
}

#[unsafe(no_mangle)]
pub extern "C" fn contribution_proof_phase() -> u32 {
    contribution_prover::browser::phase()
}

#[unsafe(no_mangle)]
pub extern "C" fn contribution_proof_output_pointer() -> usize {
    contribution_prover::browser::output_pointer()
}

#[unsafe(no_mangle)]
pub extern "C" fn contribution_proof_output_length() -> usize {
    contribution_prover::browser::output_length()
}

#[unsafe(no_mangle)]
pub extern "C" fn contribution_checkpoint_records() -> usize {
    contribution_prover::browser::checkpoint_records()
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
        contribution_prover::browser::checkpoint_command(operation, position, length, Some(context))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn contribution_checkpoint_key(position: usize, length: usize) -> u32 {
    contribution_prover::browser::checkpoint_key(position, length)
}

#[unsafe(no_mangle)]
pub extern "C" fn retain_proposal(length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        // The proposal names the poll and runtime of this instance's verified
        // registration, whose poll fixes the option count.
        let Some(verified) = super::own_verification::verified() else {
            return 1;
        };
        let Some(enrollment) = state.enrollment.as_ref() else {
            return 1;
        };
        if !(134..=state.input.len()).contains(&length)
            || state.retained_context.is_some()
            || state.offer.body_started()
            || contribution_prover::browser::phase() != 0
        {
            return 1;
        }
        let input = &state.input[..length];
        let body_length = u32::from_le_bytes(input[130..134].try_into().unwrap()) as usize;
        if body_length > protocol_foundations::roster::MAXIMUM_PROPOSAL_BYTES
            || length != 134 + body_length
            || input[..64] != verified.header().poll
            || input[64..128] != verified.header().runtime
        {
            return 1;
        }
        let Some(Ok(context)) = super::own_verification::with_poll(|poll| {
            RetainedContributionContext::parse(
                &enrollment.credential,
                &verified,
                poll,
                u16::from_le_bytes(input[128..130].try_into().unwrap()) as usize,
                &input[134..],
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
