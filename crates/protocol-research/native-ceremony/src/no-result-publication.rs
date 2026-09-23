use ballot_proof::{
    body::SignedBallotVerifier,
    publication::{AuthenticatedSource, PublicationContext, SourceValue},
    submission::{BallotBodyAuthentication, authenticate_envelope},
};
use registration_credentials::{
    Error,
    ballot_authentication::BallotEnvelope,
    ballot_body::{self, BallotBodyHasher, CIPHERTEXT_BYTES, MINIMUM_PROOF_BYTES},
    contribution_authentication::SignedOpening,
    poll::VerifiedPoll,
    publication_signing::PublicationPurpose,
    roster::RetainedContributionContext,
};
use registration_enrollment::{Enrollment, publication_work::PublicationWork};
use setup_aggregate::verified::VerifiedSetupAggregate;
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
    sync::Arc,
};

fn packet(body: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::from((body.len() as u32).to_le_bytes());
    bytes.extend(body);
    bytes.extend(signature);
    bytes
}

fn read_ballot_chunks(path: &Path, mut consume: impl FnMut(&[u8])) {
    let mut file = File::open(path).unwrap();
    let mut buffer = vec![0; 1 << 20];
    loop {
        let count = file.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        consume(&buffer[..count]);
    }
}

// One statically corrupt creator signs a complete, correctly framed body
// whose minimum-length proof is malformed. No honest ballot is generated.
fn invalid_source(
    output: &Path,
    poll: &Arc<VerifiedPoll>,
    setup: &Arc<VerifiedSetupAggregate>,
    enrollment: &mut Enrollment,
    context: &PublicationContext,
) -> (AuthenticatedSource, Vec<u8>) {
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
    let authentication = authenticate_envelope(setup, envelope.bytes(), &signature).unwrap();
    let mut verifier = BallotBodyAuthentication::new(authentication).unwrap();
    read_ballot_chunks(&path, |bytes| verifier.push(bytes).unwrap());
    let source = context.ballot_source(verifier.finish().unwrap()).unwrap();
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
    let mut packet = Vec::from(envelope.bytes().as_slice());
    packet.extend(signature);
    (source, packet)
}

pub fn run(
    output: &Path,
    poll: Arc<VerifiedPoll>,
    setup: Arc<VerifiedSetupAggregate>,
    enrollments: &mut [Enrollment],
    openings: &[SignedOpening],
    invalid_only: bool,
) -> ballot_proof::publication::VerifiedClosedSlots {
    let directory = output.join("publication");
    std::fs::create_dir(&directory).unwrap();
    let context = PublicationContext::new(poll.clone(), setup.clone()).unwrap();
    let mut works = Vec::new();
    for (position, enrollment) in enrollments.iter_mut().enumerate() {
        let retained = RetainedContributionContext::parse(
            poll.identity(),
            poll.runtime(),
            position,
            setup.inventory().proposal().proposal().body(),
        )
        .unwrap();
        let owner = enrollment
            .credential
            .retain_ballot_owner(
                &poll,
                &retained,
                setup.inventory().identity(),
                openings[position].body(),
                openings[position].signature(),
            )
            .unwrap();
        works.push(PublicationWork::new(owner, poll.clone(), setup.clone()).unwrap());
    }
    let mut invalid =
        invalid_only.then(|| invalid_source(output, &poll, &setup, &mut enrollments[0], &context));
    let close_body = works[0]
        .command(&mut enrollments[0].credential, 1, 0, &[])
        .unwrap();
    let mut intent = close_body.clone();
    intent.extend(*crate::random::<32>());
    let close_signature = works[0]
        .command(&mut enrollments[0].credential, 8, 0, &intent)
        .unwrap();
    let close = context
        .authenticate_close(&close_body, &close_signature)
        .unwrap();
    crate::write(directory.join("close.bin"), &close_body);
    crate::write(directory.join("close-signature.bin"), &close_signature);
    let close_packet = packet(&close_body, &close_signature);
    let mut sources = Vec::new();
    let mut packets = Vec::new();
    for (position, (work, enrollment)) in works.iter_mut().zip(enrollments.iter_mut()).enumerate() {
        work.command(&mut enrollment.credential, 2, 0, &close_packet)
            .unwrap();
        if position == 0 && invalid_only {
            let body = context.empty_body(&close, position).unwrap();
            assert!(matches!(
                enrollment.credential.sign_publication_message(
                    &work.owner(),
                    setup.inventory().proposal(),
                    PublicationPurpose::Empty,
                    &body,
                    Some(close.signature()),
                    [0; 32],
                ),
                Err(Error::Consumed)
            ));
            let (source, packet) = invalid.take().unwrap();
            sources.push(source);
            packets.push(packet);
            continue;
        }
        let body = work.command(&mut enrollment.credential, 1, 1, &[]).unwrap();
        let mut intent = body.clone();
        intent.extend(*crate::random::<32>());
        let signature = work
            .command(&mut enrollment.credential, 8, 0, &intent)
            .unwrap();
        sources.push(
            context
                .authenticate_empty(&close, &body, &signature)
                .unwrap(),
        );
        packets.push(packet(&body, &signature));
        crate::write(
            directory.join(format!("source-{position}-empty.bin")),
            &body,
        );
        crate::write(
            directory.join(format!("source-{position}-signature.bin")),
            &signature,
        );
    }
    let mut batches = Vec::new();
    for (position, (work, enrollment)) in works.iter_mut().zip(enrollments.iter_mut()).enumerate() {
        for author in context.assigned_sources(position).unwrap() {
            if invalid_only && author == 0 {
                work.command(&mut enrollment.credential, 3, 0, &packets[author])
                    .unwrap();
                read_ballot_chunks(&output.join("ballot/body.bin"), |bytes| {
                    work.command(&mut enrollment.credential, 4, 0, bytes)
                        .unwrap();
                });
                work.command(&mut enrollment.credential, 5, 0, &[]).unwrap();
            } else {
                work.command(&mut enrollment.credential, 6, 0, &packets[author])
                    .unwrap();
            }
        }
        let body = work.command(&mut enrollment.credential, 1, 2, &[]).unwrap();
        let mut intent = body.clone();
        intent.extend(*crate::random::<32>());
        let signature = work
            .command(&mut enrollment.credential, 8, 0, &intent)
            .unwrap();
        batches.push(context.authenticate_witness(&body, &signature).unwrap());
        assert!(
            work.command(&mut enrollment.credential, 8, 0, &intent)
                .is_err()
        );
        crate::write(directory.join(format!("witness-{position}.bin")), &body);
        crate::write(
            directory.join(format!("witness-{position}-signature.bin")),
            &signature,
        );
    }
    let slots = sources
        .into_iter()
        .enumerate()
        .map(|(author, source)| {
            context
                .verify_slot(
                    source,
                    (0..enrollments.len())
                        .filter(|signer| {
                            context.assigned_sources(*signer).unwrap().contains(&author)
                        })
                        .map(|signer| batches[signer].clone())
                        .collect(),
                )
                .unwrap()
        })
        .collect();
    let closed = context.verify_closed_slots(close, slots).unwrap();
    assert!(
        closed
            .slots()
            .iter()
            .enumerate()
            .all(
                |(author, slot)| matches!(slot.source().value(), SourceValue::Ballot(_))
                    == (invalid_only && author == 0)
            )
    );
    crate::write(directory.join("closed-slots.bin"), closed.body());
    crate::write(
        directory.join("closed-slots-identity.bin"),
        closed.identity(),
    );
    println!("Verified original-credential no-result source publication");
    closed
}
