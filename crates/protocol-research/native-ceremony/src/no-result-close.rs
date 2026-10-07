use crate::close::{
    Submission, authenticate, authenticate_responses, close_work, deliver, now_milliseconds, open,
    organize, replay, respond, write_records,
};
use crate::scenario::Scenario;
use ballot_proof::{
    body::SignedBallotVerifier,
    close::{CloseContext, ClosedSlot, VerifiedCloseBarrier},
    submission::{AuthenticatedBallotBody, authenticate_envelope},
};
use registration_credentials::{
    ballot_authentication::BallotEnvelope, ballot_body, poll::VerifiedPoll,
};
use registration_enrollment::Enrollment;
use setup_aggregate::verified::VerifiedSetupAggregate;
use std::{io::Write, path::Path, sync::Arc};

// One statically corrupt creator signs a complete, correctly framed body
// whose minimum-length proof is malformed. No honest ballot is generated.
fn invalid_source(
    output: &Path,
    poll: &Arc<VerifiedPoll>,
    setup: &Arc<VerifiedSetupAggregate>,
    enrollment: &mut Enrollment,
    scenario: &Scenario,
) -> Submission {
    let directory = output.join("ballot");
    std::fs::create_dir(&directory).unwrap();
    let path = crate::ballot_body_path(&directory, scenario, 0);
    let profile = setup.profile();
    let relation = ballot_proof::statement::header(
        &poll.identity(),
        &setup.identity(),
        0,
        poll.manifest().option_count(),
        usize::from(poll.top_count()),
    )
    .unwrap();
    let proof_bytes = *ballot_body::proof_lengths(profile).start();
    let header = ballot_body::header(profile, &relation, proof_bytes).unwrap();
    let mut hash = ballot_body::header_body_hasher(profile, &header).unwrap();
    let mut file = crate::public_output::PublicOutput::create(&path).unwrap();
    file.write_all(&header).unwrap();
    let zeros = vec![0; 1 << 20];
    let remaining = ballot_body::ciphertext_bytes(profile) + proof_bytes;
    for offset in (0..remaining).step_by(zeros.len()) {
        let bytes = &zeros[..zeros.len().min(remaining - offset)];
        file.write_all(bytes).unwrap();
        hash.push(bytes).unwrap();
    }
    file.finish().unwrap();
    let envelope = BallotEnvelope::new(
        profile,
        poll.identity(),
        setup.identity(),
        0,
        now_milliseconds(),
        header.len() + remaining,
        hash.finish().unwrap(),
    )
    .unwrap();
    let signature = enrollment
        .credential
        .sign_ballot_envelope(setup.roster(), &envelope)
        .unwrap();
    crate::write(directory.join("envelope.bin"), envelope.bytes());
    crate::write(directory.join("signature.bin"), &signature);
    let authentication = authenticate_envelope(setup, envelope.bytes(), &signature).unwrap();
    assert!(
        SignedBallotVerifier::new(poll.clone(), setup.clone(), authentication, &header, None)
            .unwrap()
            .requires_key()
    );
    for mode in ["header", "truncated"] {
        assert!(
            crate::aggregate::classify_ballot(
                poll.clone(),
                setup.clone(),
                envelope.bytes(),
                &signature,
                &path,
                &crate::aggregate::final_keys(output, profile),
                mode,
            )
            .is_err(),
            "Changed delivery was classified as an authenticated invalid ballot"
        );
    }
    Submission {
        envelope,
        signature,
        body: path,
    }
}

/// Every other participant responds; the organizer then answers and proposes
/// responses 0 to `n - f - 1`. Without ballots every slot is absent; the corrupt
/// creator's invalid ballot, held by everyone, is the only usable slot.
pub fn run(
    output: &Path,
    poll: Arc<VerifiedPoll>,
    setup: Arc<VerifiedSetupAggregate>,
    enrollments: &mut crate::OriginalEnrollments,
    invalid_only: bool,
    scenario: &Scenario,
) -> VerifiedCloseBarrier {
    let count = enrollments.len();
    let context = CloseContext::new(poll.clone(), setup.clone()).unwrap();
    let mut works: Vec<_> = (0..count)
        .map(|position| close_work(&enrollments[position], &poll, &setup, position))
        .collect();
    let invalid =
        invalid_only.then(|| invalid_source(output, &poll, &setup, &mut enrollments[0], scenario));
    let (intent_body, intent_signature) = open(&mut works, enrollments, now_milliseconds());
    let intent = context
        .authenticate_intent(&intent_body, &intent_signature)
        .unwrap();
    let held: Vec<&Submission> = invalid.iter().collect();
    let mut hashed = 0;
    let mut responses: Vec<Vec<u8>> = vec![Vec::new(); count];
    for position in 1..count {
        responses[position] = respond(
            &mut works[position],
            &mut enrollments[position].credential,
            &held,
            &mut hashed,
        );
    }
    for submission in &held {
        deliver(
            &mut works[0],
            &mut enrollments[0].credential,
            submission,
            &mut hashed,
        );
    }
    let arrivals: Vec<&Vec<u8>> = responses[1..].iter().collect();
    let (own, proposal) = organize(
        &mut works[0],
        &mut enrollments[0].credential,
        count,
        &arrivals,
    );
    responses[0] = own;
    for position in 0..count {
        let fresh = close_work(&enrollments[position], &poll, &setup, position);
        replay(
            &works[position],
            fresh,
            &mut enrollments[position].credential,
            &responses[position],
            (position == 0).then_some(proposal.as_slice()),
        );
    }
    let bodies: Vec<AuthenticatedBallotBody> = held
        .iter()
        .map(|submission| authenticate(&setup, submission, &mut hashed))
        .collect();
    let envelopes: Vec<_> = bodies
        .iter()
        .map(|body| body.authentication().clone())
        .collect();
    let authenticated = authenticate_responses(&context, &intent, &responses, &envelopes);
    let length = u32::from_le_bytes(proposal[..4].try_into().unwrap()) as usize;
    let barrier = context
        .verify_proposal(
            intent,
            &proposal[4..4 + length],
            &proposal[4 + length..],
            &authenticated,
            &bodies,
        )
        .unwrap();
    assert!(
        barrier
            .slots()
            .iter()
            .enumerate()
            .all(|(author, slot)| match slot {
                ClosedSlot::Usable(_) => invalid_only && author == 0,
                ClosedSlot::Absent => !invalid_only || author != 0,
                ClosedSlot::Conflicting(_) => false,
            })
    );
    let intent_packet = crate::close::packet(&intent_body, &intent_signature);
    write_records(
        &output.join("close"),
        output,
        &intent_packet,
        responses.iter().enumerate(),
        &proposal,
        &held,
    );
    println!("Verified original-credential no-result close responses");
    barrier
}
