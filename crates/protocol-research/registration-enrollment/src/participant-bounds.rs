//! The sizes from which the participant worker derives every bound it
//! enforces. Each value comes from the code that encodes or verifies its
//! object; the worker adds the layouts of the state it retains itself.

use registration_credentials::{
    SEALED_SIGNING_SEED_BYTES, SIGNATURE_BYTES,
    ballot_authentication::ENVELOPE_BYTES,
    ballot_body,
    close_signing::{
        ClosePurpose, MAXIMUM_LISTED_ENVELOPES_PER_SLOT, close_quorum, close_response_bytes,
        maximum_close_message_bytes,
    },
    contribution_body::{self, BODY_HEADER_BYTES},
    contribution_offer::offer_envelope_bytes,
    foundation::{MAXIMUM_USERNAME_INGRESS_BYTES, RegistrationHeader},
    poll::MAXIMUM_POLL_BYTES,
    registration::{KEY_BYTES, RETAINED_REGISTRATION_BYTES},
    release_signing::{self, RELEASE_BODY_HEADER_BYTES, RELEASE_ENVELOPE_BYTES},
    retained_roster::retained_roster_bytes,
    roster::{MAXIMUM_PROPOSAL_BYTES, proposal_bytes},
    setup_selection::{self, ENDORSEMENT_BYTES},
    target_signing::{MAXIMUM_TARGET_BODY_BYTES, TARGET_VOTE_BYTES},
};
use supported_profile::{
    DEGREE, MAXIMUM_SCORE, MINIMUM_SCORE, Profile,
    relation::{PROOF_HEADER_BYTES, setup_relation},
};

/// A packet is a four-byte body length, the body and its signature.
fn packet_bytes(body: usize) -> usize {
    4 + body + SIGNATURE_BYTES
}

/// The bounds every profile shares, in the order the worker reads them.
pub fn limits() -> Vec<u64> {
    let participants = Profile::participant_range();
    let options = Profile::option_range();
    let intent = maximum_close_message_bytes(ClosePurpose::Intent, *participants.start());
    [
        *participants.start(),
        *participants.end(),
        *options.start(),
        *options.end(),
        KEY_BYTES,
        RegistrationHeader::maximum_bytes(),
        MAXIMUM_POLL_BYTES,
        MAXIMUM_USERNAME_INGRESS_BYTES,
        SIGNATURE_BYTES,
        setup_witness::registration::SEALED_KEY_BYTES,
        SEALED_SIGNING_SEED_BYTES,
        crate::fhe_sources::maximum_capsule_bytes(),
        MAXIMUM_PROPOSAL_BYTES,
        RETAINED_REGISTRATION_BYTES,
        BODY_HEADER_BYTES,
        PROOF_HEADER_BYTES,
        offer_envelope_bytes(),
        setup_selection::endorsement_body_bytes(),
        ENDORSEMENT_BYTES,
        MINIMUM_SCORE,
        MAXIMUM_SCORE,
        ballot_proof::CHUNK_LIMIT,
        ballot_body::HEADER_BYTES,
        ENVELOPE_BYTES,
        ENVELOPE_BYTES + SIGNATURE_BYTES,
        intent,
        packet_bytes(intent),
        close_response_bytes(0),
        MAXIMUM_LISTED_ENVELOPES_PER_SLOT,
        MAXIMUM_TARGET_BODY_BYTES,
        TARGET_VOTE_BYTES,
        linked_release_proof::CHUNK_LIMIT,
        RELEASE_BODY_HEADER_BYTES,
        RELEASE_ENVELOPE_BYTES,
        DEGREE,
    ]
    .map(|value| value as u64)
    .to_vec()
}

/// One profile's bounds, in the order the worker reads them. Lists carry
/// their length first.
pub fn profile_bounds(profile: Profile) -> Vec<u64> {
    let participants = profile.participants();
    let contribution = contribution_body::proof_lengths(profile);
    let (checkpoint_header, checkpoint_records) = contribution_prover::checkpoint_layout(profile);
    let ballot = ballot_body::body_lengths(profile);
    let response = maximum_close_message_bytes(ClosePurpose::Response, participants);
    let proposal = maximum_close_message_bytes(ClosePurpose::Proposal, participants);
    let release = release_signing::body_lengths(profile);
    let mut bounds = vec![
        participants,
        profile.options(),
        proposal_bytes(participants),
        retained_roster_bytes(participants),
        profile.setup_polynomials(),
        setup_relation(profile).columns(),
        profile.setup_statement_length(),
        *contribution.start(),
        *contribution.end(),
        checkpoint_header,
        *ballot.start(),
        *ballot.end(),
        close_quorum(participants),
        profile.corrupt(),
        profile.setup_contributors(),
        profile.setup_eligible_contributors(),
        response,
        packet_bytes(response),
        proposal,
        packet_bytes(proposal),
        *release.start(),
        *release.end(),
        evaluation_target::stored_coefficient_bytes(profile),
        setup_selection::selection_body_bytes(profile),
        setup_selection::certificate_bytes(profile, setup_selection::selection_body_bytes(profile))
            .expect("Canonical selection certificate"),
        setup_aggregate::selection_reference_bytes(profile),
        checkpoint_records.len(),
    ];
    bounds.extend(checkpoint_records);
    let polynomials = profile.contribution_body_polynomials();
    bounds.push(polynomials.len());
    for index in polynomials {
        let family = profile
            .setup_family(index)
            .expect("A body polynomial is a setup polynomial.");
        bounds.extend([
            index,
            profile
                .setup_polynomial_bytes(index)
                .expect("A body polynomial is a setup polynomial."),
            profile.family_degree(family),
        ]);
    }
    bounds.into_iter().map(|value| value as u64).collect()
}

#[cfg(target_arch = "wasm32")]
mod browser {
    use std::cell::RefCell;
    use supported_profile::Profile;

    thread_local! {static OUTPUT: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };}

    fn publish(values: Vec<u64>) -> usize {
        OUTPUT.with(|output| {
            let count = values.len();
            *output.borrow_mut() = values;
            count
        })
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn participant_bounds_pointer() -> usize {
        OUTPUT.with(|output| output.borrow().as_ptr() as usize)
    }

    /// Writes the shared bounds and returns their count of 64-bit words.
    #[unsafe(no_mangle)]
    pub extern "C" fn participant_limits() -> usize {
        publish(super::limits())
    }

    /// Writes a supported profile's bounds and returns their count of
    /// 64-bit words, or zero for an unsupported profile.
    #[unsafe(no_mangle)]
    pub extern "C" fn participant_profile_bounds(participants: usize, options: usize) -> usize {
        Profile::new(participants, options).map_or_else(
            |_| publish(Vec::new()),
            |profile| publish(super::profile_bounds(profile)),
        )
    }

    /// The highest linear-memory address any allocation of this instance has
    /// reached, which the worker reports with each operation.
    #[unsafe(no_mangle)]
    pub extern "C" fn linear_memory_high_water() -> usize {
        parallel_work::scalar_allocator::linear_memory_high_water()
    }

    // An operation's memory plan with the helpers, which evaluates the
    // ranking program when `evaluation` is one.
    fn plan(helpers: usize, evaluation: u32, share: fn(usize, bool) -> Option<usize>) -> usize {
        match evaluation {
            0 | 1 => share(helpers, evaluation == 1).unwrap_or(0),
            _ => 0,
        }
    }

    /// The bound of each helper of an operation with the helpers, or zero
    /// without a plan. It allocates nothing.
    #[unsafe(no_mangle)]
    pub extern "C" fn helper_memory_bound(helpers: usize, evaluation: u32) -> usize {
        plan(helpers, evaluation, crate::memory_plan::helper_memory_bytes)
    }

    /// The bound of the worker of an operation with the helpers, or zero
    /// without a plan. It allocates nothing.
    #[unsafe(no_mangle)]
    pub extern "C" fn worker_memory_bound(helpers: usize, evaluation: u32) -> usize {
        plan(helpers, evaluation, crate::memory_plan::worker_memory_bytes)
    }

    /// Bounds the worker's instance, before its first allocation, to its
    /// share of the operation's memory plan. Returns zero when the bound
    /// applies.
    #[unsafe(no_mangle)]
    pub extern "C" fn worker_reserve(helpers: usize, evaluation: u32) -> u32 {
        let bytes = worker_memory_bound(helpers, evaluation);
        u32::from(bytes == 0 || !parallel_work::scalar_allocator::limit_linear_memory(bytes))
    }
}

#[cfg(test)]
#[path = "participant-bounds-tests.rs"]
mod tests;
