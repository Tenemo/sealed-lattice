use crate::{Enrollment, offer_signing::OfferSigning};
use registration_credentials::foundation::{
    MAXIMUM_USERNAME_INGRESS_BYTES, RegistrationHeader, normalize_username,
};
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
fn input_bytes() -> usize {
    let retained_setup = supported_profile::Profile::all()
        .map(|profile| {
            4 + 64
                + 64 * profile.contribution_body_polynomials().len()
                + registration_credentials::RETAINED_TAG_BYTES
        })
        .max()
        .unwrap();
    let restore = 128
        + 4
        + RegistrationHeader::maximum_bytes()
        + 128
        + registration_credentials::registration::KEY_BYTES
        + setup_witness::registration::SEALED_KEY_BYTES
        + registration_credentials::SEALED_SIGNING_SEED_BYTES
        + 2
        + (96 + crate::fhe_sources::maximum_capsule_bytes()).max(64 + 4 + retained_setup);
    let enrollment = 128
        + 4
        + registration_credentials::poll::MAXIMUM_POLL_BYTES
        + registration_credentials::SIGNATURE_BYTES
        + 4
        + MAXIMUM_USERNAME_INGRESS_BYTES
        + 96;
    restore.max(enrollment)
}
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
    offer: OfferSigning,
    contribution_output: Vec<u8>,
    unsigned_selection: Option<registration_credentials::setup_selection::SelectionProposal>,
    retained_context: Option<RetainedContributionContext>,
    ballot: Option<crate::ballot::BallotWork>,
    close: Option<crate::close_work::CloseWork>,
    finality: Option<crate::finality_work::FinalityWork>,
    release: Option<release_browser::ReleaseState>,
    // A retained evaluated target the host streams in, and its length.
    evaluation: Option<(usize, Vec<u8>)>,
}
thread_local! {static SESSION:RefCell<Session>=RefCell::new(Session{input:vec![0;input_bytes()],started:false,restored:false,enrollment:None,poll_identity:[0;64],roster:None,proposal:None,proposal_signature:None,signed_proposal:None,offer:OfferSigning::default(),contribution_output:Vec::new(),unsigned_selection:None,retained_context:None,ballot:None,close:None,finality:None,release:None,evaluation:None});}
#[unsafe(no_mangle)]
pub extern "C" fn input_pointer() -> usize {
    SESSION.with(|state| state.borrow_mut().input.as_mut_ptr() as usize)
}

/// The input buffer's length; the host never writes more.
#[unsafe(no_mangle)]
pub extern "C" fn input_capacity() -> usize {
    SESSION.with(|state| state.borrow().input.len())
}

#[unsafe(no_mangle)]
pub extern "C" fn poll_identity_pointer() -> usize {
    SESSION.with(|state| state.borrow().poll_identity.as_ptr() as usize)
}

/// The bytes after a four-byte length at an offset, as their range, when the
/// input holds them and they fit a poll definition.
fn framed(input: &[u8], offset: usize) -> Option<(usize, usize)> {
    let start = offset.checked_add(4)?;
    let length = u32::from_le_bytes(input.get(offset..start)?.try_into().ok()?) as usize;
    if length > registration_credentials::poll::MAXIMUM_POLL_BYTES {
        return None;
    }
    let end = start.checked_add(length)?;
    (end <= input.len()).then_some((start, end))
}
/// The creator input is the runtime, the result length, the participant
/// maximum, the question, the option count, each option's label in order and
/// the username, each text after its four-byte length. The question and
/// labels become the poll's manifest under the module's own normalization,
/// option `i` named `option-i`, and the poll definition bounds them all.
fn creator_context(
    input: &[u8],
) -> Option<(
    registration_credentials::poll::PollDraft,
    [u8; 64],
    usize,
    usize,
)> {
    use registration_credentials::foundation::{
        StabilizedDisplayText,
        ceremony::{Manifest, OptionDefinition},
    };
    let runtime = input.get(..64)?.try_into().ok()?;
    let top_count = u16::from_le_bytes(input.get(64..66)?.try_into().ok()?);
    let maximum_participants = u16::from_le_bytes(input.get(66..68)?.try_into().ok()?);
    let (start, end) = framed(input, 68)?;
    let question = StabilizedDisplayText::from_ingress_utf8(&input[start..end]).ok()?;
    let option_count = u16::from_le_bytes(input.get(end..end + 2)?.try_into().ok()?);
    let mut offset = end + 2;
    // An option index past the supported count is refused, which bounds
    // this loop.
    let mut options = Vec::new();
    for index in 0..option_count {
        let (start, end) = framed(input, offset)?;
        offset = end;
        options.push(
            OptionDefinition::new(
                index,
                format!("option-{index}"),
                StabilizedDisplayText::from_ingress_utf8(&input[start..end]).ok()?,
            )
            .ok()?,
        );
    }
    let manifest = Manifest::new(question, options).ok()?;
    let draft =
        registration_credentials::poll::PollDraft::new(manifest, top_count, maximum_participants)
            .ok()?;
    let (name_start, name_end) = framed(input, offset)?;
    if name_end - name_start > MAXIMUM_USERNAME_INGRESS_BYTES {
        return None;
    }
    normalize_username(&input[name_start..name_end]).ok()?;
    Some((draft, runtime, name_start, name_end))
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
    if name_length > MAXIMUM_USERNAME_INGRESS_BYTES || input.len() < name_start + name_length {
        return None;
    }
    normalize_username(&input[name_start..name_start + name_length]).ok()?;
    Some((poll, name_start, name_start + name_length))
}

#[unsafe(no_mangle)]
pub extern "C" fn validate_creator(length: usize) -> u32 {
    SESSION.with(|state| {
        let state = state.borrow();
        if length > state.input.len() {
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
        if length > state.input.len() {
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
        if state.started || length > state.input.len() {
            return 1;
        }
        let Some((draft, runtime, start, end)) = creator_context(&state.input[..length]) else {
            return 1;
        };
        if length != end + 96
            || !crate::distinct_data_keys(
                state.input[end..end + 32].try_into().unwrap(),
                state.input[end + 32..end + 64].try_into().unwrap(),
                state.input[end + 64..length].try_into().unwrap(),
            )
        {
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
            input[end + 32..end + 64].try_into().unwrap(),
            input[end + 64..].try_into().unwrap(),
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
        if state.started || length > state.input.len() {
            return 1;
        }
        let Some((poll, start, end)) = join_context(&state.input[..length]) else {
            return 1;
        };
        if length != end + 96
            || !crate::distinct_data_keys(
                state.input[end..end + 32].try_into().unwrap(),
                state.input[end + 32..end + 64].try_into().unwrap(),
                state.input[end + 64..length].try_into().unwrap(),
            )
        {
            return 1;
        }
        state.started = true;
        let input = Zeroizing::new(state.input[..length].to_vec());
        state.input[..length].zeroize();
        let Ok(enrollment) = Enrollment::create_for_poll(
            &poll,
            &input[start..end],
            input[end..end + 32].try_into().unwrap(),
            input[end + 32..end + 64].try_into().unwrap(),
            input[end + 64..].try_into().unwrap(),
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
    restore_enrollment(length, false)
}
/// The prepared path authenticates a retained setup result and accepts no
/// source capsule or source wrapping key.
#[unsafe(no_mangle)]
pub extern "C" fn restore_prepared(length: usize) -> u32 {
    restore_enrollment(length, true)
}
fn restore_enrollment(length: usize, prepared: bool) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        if state.restored
            || (state.started && state.enrollment.is_none())
            || !(132..=state.input.len()).contains(&length)
        {
            return 1;
        }
        state.restored = true;
        state.started = true;
        let input = Zeroizing::new(state.input[..length].to_vec());
        state.input[..length].zeroize();
        let header_length = u32::from_le_bytes(input[128..132].try_into().unwrap()) as usize;
        if header_length > RegistrationHeader::maximum_bytes() {
            return 1;
        }
        let key_bytes = if prepared { 64 } else { 96 };
        let key_polynomial_bytes = registration_credentials::registration::KEY_BYTES;
        let recipient_bytes = setup_witness::registration::SEALED_KEY_BYTES;
        let signing_bytes = registration_credentials::SEALED_SIGNING_SEED_BYTES;
        let base_length = 132
            + header_length
            + 128
            + key_bytes
            + key_polynomial_bytes
            + recipient_bytes
            + signing_bytes;
        if length < base_length + 2 {
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
        let data_keys = &input[start + 128..start + 128 + key_bytes];
        let public_start = start + 128 + key_bytes;
        let capsule_start = public_start + key_polynomial_bytes;
        let recipient_capsule = &input[capsule_start..capsule_start + recipient_bytes];
        let signing_capsule = &input[capsule_start + recipient_bytes..base_length];
        // The authenticated participant root names the purposes its records
        // show unused. Every other purpose of the restored credential stays
        // locked; completed messages are restored from their own records.
        let unused = u16::from_le_bytes(input[length - 2..].try_into().unwrap());
        let Some(Ok(mut enrollment)) = crate::own_verification::with_poll(|poll| {
            if prepared {
                let framed = input
                    .get(base_length..length - 2)
                    .ok_or(crate::Error::Shape)?;
                let frame_length = usize::try_from(u32::from_le_bytes(
                    framed
                        .get(..4)
                        .ok_or(crate::Error::Shape)?
                        .try_into()
                        .unwrap(),
                ))
                .map_err(|_| crate::Error::Shape)?;
                if frame_length != framed.len() - 4 {
                    return Err(crate::Error::Shape);
                }
                Enrollment::restore_prepared(
                    poll,
                    &header,
                    &input[public_start..capsule_start],
                    proof_hash,
                    body_digest,
                    data_keys.try_into().unwrap(),
                    [recipient_capsule, signing_capsule, &framed[4..]],
                )
            } else {
                if length != base_length + crate::fhe_sources::capsule_bytes(poll) + 2 {
                    return Err(crate::Error::Shape);
                }
                Enrollment::restore(
                    poll,
                    &header,
                    &input[public_start..capsule_start],
                    proof_hash,
                    body_digest,
                    data_keys.try_into().unwrap(),
                    [
                        recipient_capsule,
                        signing_capsule,
                        &input[base_length..length - 2],
                    ],
                )
            }
        }) else {
            return 1;
        };
        // The registration this instance verified, or else the verification
        // of an earlier visit, which only the credential just opened restores.
        // The keys stay only if it names the root's exact inputs.
        let Some(verified) = crate::own_verification::verified()
            .or_else(|| crate::own_verification::restore(&enrollment.credential))
        else {
            return 1;
        };
        if verified.header().encode().ok().as_deref() != Some(&input[132..132 + header_length])
            || verified.proof_hash() != proof_hash
            || verified.body_digest() != body_digest
            || verified.public_key() != &input[public_start..capsule_start]
        {
            return 1;
        }
        if let Some(original) = state.enrollment.as_ref() {
            // A newly created instance retains its actual consumed authority.
            // Reopening validates the saved capsules without replacing it.
            if unused != 0
                || state.poll_identity != header.poll
                || original.credential.signing_public() != enrollment.credential.signing_public()
                || original.key.public_key() != enrollment.key.public_key()
                || original.sources_retired() != enrollment.sources_retired()
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
        if prepared {
            contribution_prover::browser::retire();
            crate::operation_random::retire_contribution();
        }
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
fn retained_roster(state: &Session, begin: usize, length: usize) -> Option<RosterInputVerifier> {
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
/// Starts a setup verification whose roster restores this participant's
/// earlier roster verification.
#[unsafe(no_mangle)]
pub extern "C" fn setup_roster_begin_retained(begin: usize, length: usize) -> u32 {
    let Some(roster) = SESSION.with(|state| retained_roster(&state.borrow(), begin, length)) else {
        return 1;
    };
    setup_aggregate::setup_browser::begin_roster(roster);
    0
}
/// Writes the poll this instance verified the participant's own registration
/// against to the contribution output: the two-byte result length, the
/// question, the two-byte option count and each option's identifier and
/// label, each text after its four-byte length.
#[unsafe(no_mangle)]
pub extern "C" fn own_registration_poll() -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        state.contribution_output.clear();
        let Some(poll) = crate::own_verification::verified_poll() else {
            return 1;
        };
        state.contribution_output = poll;
        0
    })
}
/// Emits this instance's verification of the participant's own
/// registration, keyed to the restored credential, so that a later visit
/// restores it instead of reading and verifying the proof again.
#[unsafe(no_mangle)]
pub extern "C" fn retain_registration() -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        state.contribution_output.clear();
        let Some(retained) = state
            .enrollment
            .as_ref()
            .and_then(|enrollment| crate::own_verification::retain(&enrollment.credential))
        else {
            return 1;
        };
        state.contribution_output = retained;
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
    registration_credentials::roster_input::open_record_limit() as u32
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
                3 => roster.push_proof(position, bytes),
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
        let Some(roster) = state.roster.as_mut() else {
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
    if length > registration_credentials::setup_selection::MAXIMUM_SELECTION_BYTES
        || bytes.len() != 4 + length + 3309
    {
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

fn original_context(
    state: &Session,
) -> Result<RetainedContributionContext, registration_credentials::Error> {
    use registration_credentials::Error;
    if let Some(context) = &state.retained_context {
        return Ok(context.clone());
    }
    let enrollment = state.enrollment.as_ref().ok_or(Error::Context)?;
    let original = crate::own_verification::verified().ok_or(Error::Context)?;
    let proposal = state
        .signed_proposal
        .as_ref()
        .ok_or(Error::Context)?
        .proposal();
    let position = proposal
        .records()
        .iter()
        .position(|record| {
            record.body_digest() == original.body_digest()
                && record.header().signing_public == *enrollment.credential.signing_public()
        })
        .ok_or(Error::Context)?;
    crate::own_verification::with_poll(|poll| {
        RetainedContributionContext::parse(
            &enrollment.credential,
            &original,
            poll,
            position,
            proposal.body(),
        )
    })
    .ok_or(Error::Context)?
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

fn offer_operation(
    state: &mut Session,
    operation: u32,
    argument: usize,
    length: usize,
) -> Result<(), registration_credentials::Error> {
    use registration_credentials::Error;
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
            if input.len() != 32 {
                return Err(Error::Shape);
            }
            let credential = &mut state.enrollment.as_mut().ok_or(Error::Context)?.credential;
            state
                .offer
                .sign(credential, input[..].try_into().unwrap())?;
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
pub extern "C" fn offer_signing(operation: u32, argument: usize, length: usize) -> u32 {
    SESSION.with(|state| {
        u32::from(offer_operation(&mut state.borrow_mut(), operation, argument, length).is_err())
    })
}

fn selection_operation(
    state: &mut Session,
    operation: u32,
    length: usize,
) -> Result<(), registration_credentials::Error> {
    use registration_credentials::{Error, setup_selection};
    if length > state.input.len() {
        return Err(Error::Shape);
    }
    let input = Zeroizing::new(state.input[..length].to_vec());
    state.input[..length].zeroize();
    let context = original_context(state)?;
    let (_, roster) = setup_aggregate::setup_browser::roster_context().ok_or(Error::Context)?;
    if roster.proposal().identity_bytes() != context.identity() {
        return Err(Error::Context);
    }
    match operation {
        0 => {
            if !input.is_empty() {
                return Err(Error::Shape);
            }
            let selection =
                setup_aggregate::setup_browser::unsigned_selection().ok_or(Error::Context)?;
            if selection.roster_identity() != context.identity() {
                return Err(Error::Context);
            }
            state.contribution_output = selection.body().to_vec();
            state.unsigned_selection = Some(selection);
        }
        1 => {
            if input.len() != 32 {
                return Err(Error::Shape);
            }
            let selection = state.unsigned_selection.as_ref().ok_or(Error::Context)?;
            let signature = state
                .enrollment
                .as_mut()
                .ok_or(Error::Context)?
                .credential
                .sign_selection_proposal(&roster, selection, input[..].try_into().unwrap())?;
            state.contribution_output = emitted_packet(selection.body(), &signature);
        }
        2 | 5 => {
            let inputs =
                setup_aggregate::setup_browser::selection_inputs().ok_or(Error::Context)?;
            if inputs.roster().proposal().identity_bytes() != context.identity() {
                return Err(Error::Context);
            }
            let selection = inputs.selection().selection();
            state.contribution_output = if operation == 2 {
                if input.len() != 32 {
                    return Err(Error::Shape);
                }
                state
                    .enrollment
                    .as_mut()
                    .ok_or(Error::Context)?
                    .credential
                    .endorse_selection(
                        &roster,
                        selection,
                        context.position(),
                        input[..].try_into().unwrap(),
                    )?
            } else {
                if !input.is_empty() {
                    return Err(Error::Shape);
                }
                setup_selection::endorsement_body(selection.identity(), context.position())?
            };
        }
        3 => {
            let (body, signature) = signed_packet(&input).ok_or(Error::Shape)?;
            let proposal = setup_selection::authenticate_selection(roster, body, signature)?;
            state
                .enrollment
                .as_mut()
                .ok_or(Error::Context)?
                .credential
                .restore_selection_proposal(&proposal)?;
        }
        4 => {
            let prefix = input.get(..4).ok_or(Error::Shape)?;
            let length = u32::from_le_bytes(prefix.try_into().unwrap()) as usize;
            if length > setup_selection::MAXIMUM_SELECTION_BYTES
                || input.len() != 4 + length + 3309 + setup_selection::ENDORSEMENT_BYTES
            {
                return Err(Error::Shape);
            }
            let proposal = setup_selection::authenticate_selection(
                roster.clone(),
                &input[4..4 + length],
                &input[4 + length..4 + length + 3309],
            )?;
            let endorsement = setup_selection::authenticate_endorsement(
                &roster,
                proposal.selection(),
                &input[4 + length + 3309..],
            )?;
            state
                .enrollment
                .as_mut()
                .ok_or(Error::Context)?
                .credential
                .restore_selection_endorsement(&roster, &endorsement)?;
        }
        6 => {
            if !input.is_empty() {
                return Err(Error::Shape);
            }
            state.contribution_output = state
                .unsigned_selection
                .as_ref()
                .ok_or(Error::Context)?
                .identity()
                .to_vec();
        }
        _ => return Err(Error::Shape),
    }
    Ok(())
}
#[unsafe(no_mangle)]
pub extern "C" fn selection_signing(operation: u32, length: usize) -> u32 {
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
        let Some((poll, _)) = setup_aggregate::setup_browser::roster_context() else {
            return 1;
        };
        let Some(inputs) = setup_aggregate::setup_browser::selection_inputs() else {
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
        u32::from(!setup_aggregate::setup_browser::restore_inputs(
            &enrollment.credential,
            bytes,
        ))
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
        let Some(verified) = crate::own_verification::verified() else {
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
        if body_length > registration_credentials::roster::MAXIMUM_PROPOSAL_BYTES
            || length != 134 + body_length
            || input[..64] != verified.header().poll
            || input[64..128] != verified.header().runtime
        {
            return 1;
        }
        let Some(Ok(context)) = crate::own_verification::with_poll(|poll| {
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
        let Some((poll, setup)) = setup_aggregate::setup_browser::context() else {
            return 1;
        };
        let Some(original) = crate::own_verification::verified() else {
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
        contribution_prover::browser::retire();
        crate::operation_random::retire_contribution();
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
        u32::from(!setup_aggregate::setup_browser::restore(
            &enrollment.credential,
            retained,
        ))
    })
}

/// Emits the target this instance evaluated, keyed to the restored
/// credential, so that a later visit restores it instead of evaluating
/// again.
#[unsafe(no_mangle)]
pub extern "C" fn retain_evaluation() -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        state.contribution_output.clear();
        let (Some(enrollment), Some(target)) = (
            state.enrollment.as_ref(),
            evaluation_target::verified_browser_target(),
        ) else {
            return 1;
        };
        let Ok(retained) = target.retain(&enrollment.credential) else {
            return 1;
        };
        state.contribution_output = retained;
        0
    })
}

fn restore_evaluation_step(state: &mut Session, operation: u32, length: usize) -> Option<()> {
    match operation {
        0 => {
            let (_, setup) = setup_aggregate::setup_browser::context()?;
            let maximum = 8
                + registration_credentials::target_signing::MAXIMUM_TARGET_BODY_BYTES
                + 2 * supported_profile::relation::SYSTEMATIC
                    * linked_release_proof::statement::release_coefficient_bytes(setup.profile())
                + registration_credentials::RETAINED_TAG_BYTES;
            (state.evaluation.is_none() && length <= maximum).then_some(())?;
            state.evaluation = Some((length, Vec::with_capacity(length)));
        }
        1 => {
            let bytes = state.input.get(..length)?;
            let (expected, copy) = state.evaluation.as_mut()?;
            (length <= *expected - copy.len()).then_some(())?;
            copy.extend(bytes);
        }
        2 => {
            let (expected, copy) = state.evaluation.take()?;
            (length == 0 && copy.len() == expected).then_some(())?;
            let (poll, setup) = setup_aggregate::setup_browser::context()?;
            let target = evaluation_target::target::VerifiedEvaluationTarget::restore(
                &state.enrollment.as_ref()?.credential,
                poll,
                setup,
                &copy,
            )
            .ok()?;
            evaluation_target::restore_browser_target(target).then_some(())?;
        }
        _ => return None,
    }
    Some(())
}
/// Restores the target this participant evaluated from its retained copy,
/// which the host streams in: operation zero begins a copy of the given
/// length, one appends that many input bytes and two restores the complete
/// copy for this instance's verified poll and setup.
#[unsafe(no_mangle)]
pub extern "C" fn restore_evaluation(operation: u32, length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let restored = restore_evaluation_step(&mut state, operation, length);
        if restored.is_none() {
            state.evaluation = None;
        }
        u32::from(restored.is_none())
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
            && !crate::operation_random::ready(crate::operation_random::Purpose::Ballot)
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

#[unsafe(no_mangle)]
pub extern "C" fn participant_close_command(operation: u32, argument: usize, length: usize) -> u32 {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        session.contribution_output.clear();
        if length > session.input.len() {
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
            if !enrollment.sources_retired() {
                return 1;
            }
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
