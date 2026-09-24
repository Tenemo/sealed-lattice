use crate::{Enrollment, contribution_signing::ContributionSigning};
use registration_credentials::foundation::{RegistrationHeader, normalize_username};
use registration_credentials::{
    roster::{RetainedContributionContext, RosterProposal},
    roster_authentication::{OrganizerSignedRoster, verify_roster_proposal},
    roster_input::RosterInputVerifier,
};
use std::{cell::RefCell, sync::Arc};
use zeroize::{Zeroize, Zeroizing};
#[path = "finality-browser.rs"]
mod finality_browser;
#[path = "release-browser.rs"]
mod release_browser;
const INPUT_BYTES: usize = 128 + 4 + 4096 + 128 + 64 + 65536 * 21 + 532 + 52 + 2;
struct Session {
    input: Vec<u8>,
    started: bool,
    restored: bool,
    enrollment: Option<Enrollment>,
    poll_identity: [u8; 64],
    roster: Option<RosterInputVerifier>,
    proposal: Option<RosterProposal>,
    proposal_signature: Option<[u8; 3309]>,
    signed_proposal: Option<Arc<OrganizerSignedRoster>>,
    contribution: ContributionSigning,
    contribution_output: Vec<u8>,
    retained_context: Option<RetainedContributionContext>,
    ballot: Option<crate::ballot::BallotWork>,
    close: Option<crate::close_work::CloseWork>,
    finality: Option<crate::finality_work::FinalityWork>,
    release: Option<release_browser::ReleaseState>,
}
thread_local! {static SESSION:RefCell<Session>=RefCell::new(Session{input:vec![0;INPUT_BYTES],started:false,restored:false,enrollment:None,poll_identity:[0;64],roster:None,proposal:None,proposal_signature:None,signed_proposal:None,contribution:ContributionSigning::default(),contribution_output:Vec::new(),retained_context:None,ballot:None,close:None,finality:None,release:None});}
#[unsafe(no_mangle)]
pub extern "C" fn input_pointer() -> usize {
    SESSION.with(|state| state.borrow_mut().input.as_mut_ptr() as usize)
}

#[unsafe(no_mangle)]
pub extern "C" fn poll_identity_pointer() -> usize {
    SESSION.with(|state| state.borrow().poll_identity.as_ptr() as usize)
}

fn creator_context(
    input: &[u8],
) -> Option<(
    registration_credentials::poll::PollDraft,
    [u8; 64],
    usize,
    usize,
)> {
    use registration_credentials::foundation::{CanonicalDecodeLimits, ceremony::Manifest};
    if input.len() < 74 {
        return None;
    }
    let runtime = input[..64].try_into().ok()?;
    let top_count = u16::from_le_bytes(input[64..66].try_into().ok()?);
    let manifest_length = u32::from_le_bytes(input[66..70].try_into().ok()?) as usize;
    if manifest_length > registration_credentials::poll::MAXIMUM_POLL_BYTES
        || input.len() < 74 + manifest_length
    {
        return None;
    }
    let manifest = Manifest::decode(
        &input[70..70 + manifest_length],
        &CanonicalDecodeLimits::default(),
    )
    .ok()?;
    let draft = registration_credentials::poll::PollDraft::new(manifest, top_count).ok()?;
    let name_length = u32::from_le_bytes(
        input[70 + manifest_length..74 + manifest_length]
            .try_into()
            .ok()?,
    ) as usize;
    let name_start = 74 + manifest_length;
    if name_length > 512 || input.len() < name_start + name_length {
        return None;
    }
    normalize_username(&input[name_start..name_start + name_length]).ok()?;
    Some((draft, runtime, name_start, name_start + name_length))
}
fn join_context(
    input: &[u8],
) -> Option<(registration_credentials::poll::VerifiedPoll, usize, usize)> {
    if input.len() < 132 {
        return None;
    }
    let length = u32::from_le_bytes(input[128..132].try_into().ok()?) as usize;
    if length > registration_credentials::poll::MAXIMUM_POLL_BYTES
        || input.len() < 132 + length + 3309 + 4
    {
        return None;
    }
    let poll = registration_credentials::poll::verify_poll(
        input[..64].try_into().ok()?,
        input[64..128].try_into().ok()?,
        &input[132..132 + length],
        &input[132 + length..132 + length + 3309],
    )
    .ok()?;
    let name_start = 132 + length + 3309 + 4;
    let name_length =
        u32::from_le_bytes(input[name_start - 4..name_start].try_into().ok()?) as usize;
    if name_length > 512 || input.len() < name_start + name_length {
        return None;
    }
    normalize_username(&input[name_start..name_start + name_length]).ok()?;
    Some((poll, name_start, name_start + name_length))
}

#[unsafe(no_mangle)]
pub extern "C" fn validate_creator(length: usize) -> u32 {
    SESSION.with(|state| {
        let state = state.borrow();
        if length > INPUT_BYTES {
            return 1;
        }
        u32::from(
            creator_context(&state.input[..length]).is_none_or(|(_, _, _, end)| end != length),
        )
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn validate_join(length: usize) -> u32 {
    SESSION.with(|state| {
        let state = state.borrow();
        if length > INPUT_BYTES {
            return 1;
        }
        u32::from(join_context(&state.input[..length]).is_none_or(|(_, _, end)| end != length))
    })
}

fn staged_output(kind: u32, offset: usize, bytes: &[u8]) {
    #[link(wasm_import_module = "enrollment")]
    unsafe extern "C" {
        fn staged_chunk(kind: u32, offset: usize, pointer: *const u8, length: usize) -> u32;
    }
    for (index, chunk) in bytes.chunks(1 << 20).enumerate() {
        assert_eq!(
            unsafe {
                staged_chunk(
                    kind,
                    offset + index * (1 << 20),
                    chunk.as_ptr(),
                    chunk.len(),
                )
            },
            0
        );
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn prepare_creator(length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        if state.started || length > INPUT_BYTES {
            return 1;
        }
        let Some((draft, runtime, start, end)) = creator_context(&state.input[..length]) else {
            return 1;
        };
        if length != end + 64 || state.input[end..end + 32] == state.input[end + 32..length] {
            return 1;
        }
        state.started = true;
        let input = Zeroizing::new(state.input[..length].to_vec());
        state.input[..length].zeroize();
        let Ok((poll, enrollment)) = Enrollment::create_creator(
            draft,
            runtime,
            &input[start..end],
            input[end..end + 32].try_into().unwrap(),
            input[end + 32..].try_into().unwrap(),
            staged_output,
        ) else {
            return 1;
        };
        staged_output(6, 0, &poll.body);
        staged_output(7, 0, &poll.signature);
        state.poll_identity = poll.identity;
        state.enrollment = Some(enrollment);
        0
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn prepare_join(length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        if state.started || length > INPUT_BYTES {
            return 1;
        }
        let Some((poll, start, end)) = join_context(&state.input[..length]) else {
            return 1;
        };
        if length != end + 64 || state.input[end..end + 32] == state.input[end + 32..length] {
            return 1;
        }
        state.started = true;
        let input = Zeroizing::new(state.input[..length].to_vec());
        state.input[..length].zeroize();
        let Ok(enrollment) = Enrollment::create_for_poll(
            &poll,
            &input[start..end],
            input[end..end + 32].try_into().unwrap(),
            input[end + 32..].try_into().unwrap(),
            staged_output,
        ) else {
            return 1;
        };
        state.poll_identity = poll.identity();
        state.enrollment = Some(enrollment);
        0
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn restore(length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        if state.restored
            || (state.started && state.enrollment.is_none())
            || !(132..=INPUT_BYTES).contains(&length)
        {
            return 1;
        }
        state.restored = true;
        state.started = true;
        let input = Zeroizing::new(state.input[..length].to_vec());
        state.input[..length].zeroize();
        let header_length = u32::from_le_bytes(input[128..132].try_into().unwrap()) as usize;
        if header_length > 4096
            || length != 132 + header_length + 128 + 64 + 65536 * 21 + 532 + 52 + 2
        {
            return 1;
        }
        let Ok((header, consumed)) =
            RegistrationHeader::decode_prefix(&input[132..132 + header_length])
        else {
            return 1;
        };
        if consumed != header_length
            || header.poll.as_slice() != &input[..64]
            || header.runtime.as_slice() != &input[64..128]
        {
            return 1;
        }
        let start = 132 + header_length;
        let proof_hash = input[start..start + 64].try_into().unwrap();
        let body_digest = input[start + 64..start + 128].try_into().unwrap();
        let data_keys = input[start + 128..start + 192].try_into().unwrap();
        let public_start = start + 192;
        let capsule_start = public_start + 65536 * 21;
        // The authenticated participant root names the purposes its records
        // show unused. Every other purpose of the restored credential stays
        // locked; completed messages are restored from their own records.
        let unused = u16::from_le_bytes(input[length - 2..].try_into().unwrap());
        let Some(verified) = crate::own_verification::verified() else {
            return 1;
        };
        if verified.header().encode().ok().as_deref() != Some(&input[132..132 + header_length])
            || verified.proof_hash() != proof_hash
            || verified.body_digest() != body_digest
            || verified.public_key() != &input[public_start..capsule_start]
        {
            return 1;
        }
        let Ok(mut enrollment) = Enrollment::restore(
            &header,
            &input[public_start..capsule_start],
            proof_hash,
            body_digest,
            data_keys,
            &input[capsule_start..capsule_start + 532],
            &input[capsule_start + 532..length - 2],
        ) else {
            return 1;
        };
        if let Some(original) = state.enrollment.as_ref() {
            // A newly created instance retains its actual consumed authority.
            // Reopening validates the saved capsules without replacing it.
            if unused != 0
                || state.poll_identity != header.poll
                || original.credential.signing_public() != enrollment.credential.signing_public()
                || original.key.public_key() != enrollment.key.public_key()
            {
                return 1;
            }
        } else {
            if enrollment
                .credential
                .unlock_unused_purposes(unused)
                .is_err()
            {
                return 1;
            }
            state.enrollment = Some(enrollment);
        }
        state.poll_identity = header.poll;
        0
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn check_retained() -> u32 {
    SESSION.with(|state| {
        state
            .borrow()
            .enrollment
            .as_ref()
            .map_or(1, |value| u32::from(!value.check()))
    })
}

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
        state.roster = Some(roster);
        state.proposal = None;
        state.proposal_signature = None;
        state.signed_proposal = None;
        0
    })
}
fn roster_step(operation: u32, length: usize) -> u32 {
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
                1 => roster.push_key(bytes),
                2 => roster.finish_key(),
                3 => roster.push_proof(bytes),
                4 => roster.finish_record(),
                _ => unreachable!(),
            }
            .is_err(),
        )
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn roster_record_begin(length: usize) -> u32 {
    roster_step(0, length)
}
#[unsafe(no_mangle)]
pub extern "C" fn roster_record_key(length: usize) -> u32 {
    roster_step(1, length)
}
#[unsafe(no_mangle)]
pub extern "C" fn roster_record_key_finish() -> u32 {
    roster_step(2, 0)
}
#[unsafe(no_mangle)]
pub extern "C" fn roster_record_proof(length: usize) -> u32 {
    roster_step(3, length)
}
#[unsafe(no_mangle)]
pub extern "C" fn roster_record_finish() -> u32 {
    roster_step(4, 0)
}
#[unsafe(no_mangle)]
pub extern "C" fn roster_finish() -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Some(roster) = state.roster.as_ref() else {
            return 0;
        };
        let Ok(proposal) = roster.finish() else {
            return 0;
        };
        state.proposal = Some(proposal);
        1
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
        if length != 96 {
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
        let randomness = input[64..96].try_into().unwrap();
        input[..96].zeroize();
        let Ok(signature) = enrollment
            .credential
            .sign_roster_proposal(proposal, randomness)
        else {
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
        if length != 3309 {
            return 0;
        }
        let Some(roster) = state.roster.as_ref() else {
            return 0;
        };
        let Ok(proposal) = roster.finish() else {
            return 0;
        };
        let Ok(verified) = verify_roster_proposal(proposal, &state.input[..length]) else {
            return 0;
        };
        state.proposal_signature = Some(*verified.signature());
        state.signed_proposal = Some(Arc::new(verified));
        1
    })
}

fn signed_packet(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let length = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
    if length > 1024 || bytes.len() != 4 + length + 3309 {
        return None;
    }
    Some((&bytes[4..4 + length], &bytes[4 + length..]))
}

fn emitted_packet(body: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut output = Vec::from((body.len() as u32).to_le_bytes());
    output.extend(body);
    output.extend(signature);
    output
}

fn contribution_operation(
    state: &mut Session,
    operation: u32,
    argument: usize,
    length: usize,
) -> Result<(), registration_credentials::Error> {
    use registration_credentials::Error;
    if length > INPUT_BYTES || (operation != 2 && operation != 3 && argument != 0) {
        return Err(Error::Shape);
    }
    let input = Zeroizing::new(state.input[..length].to_vec());
    state.input[..length].zeroize();
    let credential = &mut state.enrollment.as_mut().ok_or(Error::Context)?.credential;
    match operation {
        1 => {
            if length != 78 {
                return Err(Error::Shape);
            }
            let position = u16::from_le_bytes(input[..2].try_into().unwrap()) as usize;
            if let Some(context) = &state.retained_context {
                if context.position() != position {
                    return Err(Error::Context);
                }
                state.contribution.begin_retained_body(
                    credential,
                    context.clone(),
                    input[2..66].try_into().unwrap(),
                    &input[66..],
                )?;
            } else {
                let proposal = state.signed_proposal.clone().ok_or(Error::Context)?;
                state.contribution.begin_body(
                    credential,
                    proposal,
                    position,
                    input[2..66].try_into().unwrap(),
                    &input[66..],
                )?;
            }
        }
        2 => {
            if !(5..=4 + (1 << 20)).contains(&length) {
                return Err(Error::Shape);
            }
            let offset = u32::from_le_bytes(input[..4].try_into().unwrap()) as usize;
            state
                .contribution
                .polynomial(argument, offset, &input[4..])?;
        }
        3 => {
            if !(1..=1 << 20).contains(&length) {
                return Err(Error::Shape);
            }
            state.contribution.proof(argument, &input)?;
        }
        4 => {
            if length != 0 {
                return Err(Error::Shape);
            }
            state.contribution.finish_body()?;
            state.contribution_output = state
                .contribution
                .commitment()
                .ok_or(Error::Consumed)?
                .to_vec();
        }
        5 => {
            if length != 96 {
                return Err(Error::Shape);
            }
            state.contribution.sign_confirmation(
                credential,
                input[..64].try_into().unwrap(),
                input[64..].try_into().unwrap(),
            )?;
            let confirmation = state.contribution.confirmation().ok_or(Error::Consumed)?;
            state.contribution_output =
                emitted_packet(confirmation.body(), confirmation.signature());
        }
        6 => {
            let (body, signature) = signed_packet(&input).ok_or(Error::Shape)?;
            state
                .contribution
                .restore_confirmation(credential, body, signature)?;
        }
        7 => {
            let (body, signature) = signed_packet(&input).ok_or(Error::Shape)?;
            state.contribution.accept_confirmation(body, signature)?;
        }
        8 => {
            if length != 0 {
                return Err(Error::Shape);
            }
            state.contribution.finish_inventory()?;
            state.contribution_output = state
                .contribution
                .inventory()
                .ok_or(Error::Consumed)?
                .identity()
                .to_vec();
        }
        9 => {
            if length != 96 {
                return Err(Error::Shape);
            }
            state.contribution.sign_opening(
                credential,
                input[..64].try_into().unwrap(),
                input[64..].try_into().unwrap(),
            )?;
            let opening = state.contribution.opening().ok_or(Error::Consumed)?;
            state.contribution_output = emitted_packet(opening.body(), opening.signature());
        }
        10 => {
            let (body, signature) = signed_packet(&input).ok_or(Error::Shape)?;
            state
                .contribution
                .consume_opening(credential, body, signature)?;
        }
        11 => {
            if length != 2 {
                return Err(Error::Shape);
            }
            let position = u16::from_le_bytes(input[..2].try_into().unwrap()) as usize;
            credential.validate_confirmation_position(
                state.signed_proposal.as_ref().ok_or(Error::Context)?,
                position,
            )?;
        }
        12 | 13 => {
            if length != 0 {
                return Err(Error::Shape);
            }
            state.contribution_output = if operation == 12 {
                state.contribution.confirmation_body(credential)?
            } else {
                state.contribution.opening_body(credential)?
            };
        }
        _ => return Err(Error::Shape),
    }
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn contribution_signing(operation: u32, argument: usize, length: usize) -> u32 {
    SESSION.with(|state| {
        u32::from(
            contribution_operation(&mut state.borrow_mut(), operation, argument, length).is_err(),
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn contribution_output_pointer() -> usize {
    SESSION.with(|state| state.borrow().contribution_output.as_ptr() as usize)
}

#[unsafe(no_mangle)]
pub extern "C" fn contribution_output_length() -> usize {
    SESSION.with(|state| state.borrow().contribution_output.len())
}

#[unsafe(no_mangle)]
pub extern "C" fn begin_contribution(position: usize) -> u32 {
    SESSION.with(|state| {
        let state = state.borrow();
        if state.contribution.body_started() || state.retained_context.is_some() {
            return 1;
        }
        let Some(enrollment) = state.enrollment.as_ref() else {
            return 1;
        };
        let Some(proposal) = state.signed_proposal.as_ref() else {
            return 1;
        };
        if enrollment
            .credential
            .validate_confirmation_position(proposal, position)
            .is_err()
        {
            return 1;
        }
        u32::from(
            contribution_prover::browser::begin_verified(proposal.proposal(), position).is_err(),
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn contribution_proof_input_pointer() -> usize {
    contribution_prover::browser::input_pointer()
}

#[unsafe(no_mangle)]
pub extern "C" fn contribution_proof_command(
    operation: u32,
    argument: usize,
    length: usize,
) -> u32 {
    if operation == 1 {
        return 1;
    }
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
    contribution_prover::browser::checkpoint_command(operation, position, length)
}

#[unsafe(no_mangle)]
pub extern "C" fn contribution_checkpoint_key(position: usize, length: usize) -> u32 {
    contribution_prover::browser::checkpoint_key(position, length)
}

#[unsafe(no_mangle)]
pub extern "C" fn retain_proposal(length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        if !(134..=INPUT_BYTES).contains(&length)
            || state.retained_context.is_some()
            || state.signed_proposal.is_some()
            || state.contribution.body_started()
            || contribution_prover::browser::phase() != 0
        {
            return 1;
        }
        let input = &state.input[..length];
        let body_length = u32::from_le_bytes(input[130..134].try_into().unwrap()) as usize;
        if body_length > 2048 || length != 134 + body_length {
            return 1;
        }
        let Ok(context) = RetainedContributionContext::parse(
            input[..64].try_into().unwrap(),
            input[64..128].try_into().unwrap(),
            u16::from_le_bytes(input[128..130].try_into().unwrap()) as usize,
            &input[134..],
        ) else {
            return 1;
        };
        state.retained_context = Some(context);
        state.started = true;
        0
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
        let Some((poll, setup)) = setup_aggregate::setup_browser::context() else {
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

#[unsafe(no_mangle)]
pub extern "C" fn participant_ballot_command(
    operation: u32,
    argument: usize,
    length: usize,
) -> u32 {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        session.contribution_output.clear();
        if length > INPUT_BYTES {
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
        match ballot.command(&mut enrollment.credential, operation, argument, &input) {
            Ok(bytes) => {
                *contribution_output = bytes;
                0
            }
            Err(_) => 1,
        }
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn participant_close_command(operation: u32, argument: usize, length: usize) -> u32 {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        session.contribution_output.clear();
        if length > INPUT_BYTES {
            return 1;
        }
        let input = Zeroizing::new(session.input[..length].to_vec());
        session.input[..length].zeroize();
        if operation == 0 {
            if argument != 0 || session.close.is_some() || session.ballot.is_some() {
                return 1;
            }
            let Some(enrollment) = session.enrollment.as_ref() else {
                return 1;
            };
            let Some(context) = session.retained_context.as_ref() else {
                return 1;
            };
            let Some((poll, setup)) = setup_aggregate::setup_browser::context() else {
                return 1;
            };
            let Ok(ballot) =
                crate::ballot::BallotWork::new(&enrollment.credential, context, &input)
            else {
                return 1;
            };
            let Ok(close) = crate::close_work::CloseWork::new(ballot.into_owner(), poll, setup)
            else {
                return 1;
            };
            session.close = Some(close);
            return 0;
        }
        let Session {
            enrollment,
            close,
            contribution_output,
            ..
        } = &mut *session;
        let Some(enrollment) = enrollment.as_mut() else {
            return 1;
        };
        let Some(close) = close.as_mut() else {
            return 1;
        };
        match close.command(&mut enrollment.credential, operation, argument, &input) {
            Ok(bytes) => {
                *contribution_output = bytes;
                0
            }
            Err(_) => 1,
        }
    })
}
