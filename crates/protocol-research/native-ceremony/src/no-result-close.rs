use crate::close::{
    Submission, authenticate, authenticate_responses, close_work, deliver, now_milliseconds, open,
    organize, respond, write_records,
};
use ballot_proof::{
    body::SignedBallotVerifier,
    close::{CloseContext, ClosedSlot, VerifiedCloseBarrier},
    submission::{AuthenticatedBallotBody, authenticate_envelope},
};
use registration_credentials::{
    ballot_authentication::BallotEnvelope,
    ballot_body::{self, BallotBodyHasher, CIPHERTEXT_BYTES, MINIMUM_PROOF_BYTES},
    contribution_authentication::SignedOpening,
    poll::VerifiedPoll,
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
) -> Submission {
    let directory = output.join("ballot");
    std::fs::create_dir(&directory).unwrap();
    let path = crate::ballot_body_path(&directory, 0);
    let mut relation = Vec::from(b"LBS1".as_slice());
    relation.extend(poll.identity());
    relation.extend(setup.inventory().identity());
    relation.extend(0u16.to_le_bytes());
    relation.push(poll.manifest().option_count() as u8);
    relation.push(poll.top_count() as u8);
    let header = ballot_body::header(&relation, MINIMUM_PROOF_BYTES).unwrap();
    let mut hash = BallotBodyHasher::new(&header).unwrap();
    let mut file = crate::public_output::PublicOutput::create(&path).unwrap();
    file.write_all(&header).unwrap();
    let zeros = vec![0; 1 << 20];
    let remaining = CIPHERTEXT_BYTES + MINIMUM_PROOF_BYTES;
    for offset in (0..remaining).step_by(zeros.len()) {
        let bytes = &zeros[..zeros.len().min(remaining - offset)];
        file.write_all(bytes).unwrap();
        hash.push(bytes).unwrap();
    }
    file.finish().unwrap();
    let envelope = BallotEnvelope::new(
        poll.identity(),
        setup.inventory().identity(),
        0,
        now_milliseconds(),
        header.len() + remaining,
        hash.finish().unwrap(),
    )
    .unwrap();
    let signature = enrollment
        .credential
        .sign_ballot_envelope(
            setup.inventory().proposal(),
            &envelope,
            *crate::random::<32>(),
        )
        .unwrap();
    crate::write(directory.join("envelope.bin"), envelope.bytes());
    crate::write(directory.join("signature.bin"), &signature);
    let authentication = authenticate_envelope(setup, envelope.bytes(), &signature).unwrap();
    assert!(
        SignedBallotVerifier::new(poll.clone(), setup.clone(), authentication, &header)
            .unwrap()
            .requires_keys()
    );
    for mode in ["header", "truncated"] {
        assert!(
            crate::aggregate::classify_ballot(
                poll.clone(),
                setup.clone(),
                envelope.bytes(),
                &signature,
                &path,
                &output.join("aggregates/after-participant-9"),
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
/// responses 0 to 6. Without ballots every slot is absent; the corrupt
/// creator's invalid ballot, held by everyone, is the only usable slot.
pub fn run(
    output: &Path,
    poll: Arc<VerifiedPoll>,
    setup: Arc<VerifiedSetupAggregate>,
    enrollments: &mut [Enrollment],
    openings: &[SignedOpening],
    invalid_only: bool,
) -> VerifiedCloseBarrier {
    let count = enrollments.len();
    let context = CloseContext::new(poll.clone(), setup.clone()).unwrap();
    let mut works: Vec<_> = (0..count)
        .map(|position| {
            close_work(
                &enrollments[position],
                &poll,
                &setup,
                &openings[position],
                position,
            )
        })
        .collect();
    let invalid = invalid_only.then(|| invalid_source(output, &poll, &setup, &mut enrollments[0]));
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
        &[],
        &arrivals,
    );
    responses[0] = own;
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
        &responses,
        &proposal,
        &held,
    );
    println!("Verified original-credential no-result close responses");
    barrier
}
