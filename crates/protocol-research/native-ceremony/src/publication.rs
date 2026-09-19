use ballot_proof::{
    publication::{AuthenticatedSource, PublicationContext, SourceValue},
    submission::{BallotBodyAuthentication, authenticate_envelope},
};
use registration_credentials::{
    Credential, ballot_authentication::BallotEnvelope, contribution_authentication::SignedOpening,
    poll::VerifiedPoll, publication_signing::PublicationPurpose,
    roster::RetainedContributionContext,
};
use registration_enrollment::Enrollment;
use setup_aggregate::verified::VerifiedSetupAggregate;
use std::{fs::File, io::Read, path::Path, sync::Arc, time::Instant};

pub fn run(
    output: &Path,
    poll: Arc<VerifiedPoll>,
    setup: Arc<VerifiedSetupAggregate>,
    enrollments: &mut [Enrollment],
    openings: &[SignedOpening],
    corrupt_credentials: [Credential; 2],
    ballots: [(&BallotEnvelope, &[u8; 3309], &Path); 3],
) -> ballot_proof::publication::VerifiedClosedSlots {
    let [mut corrupt_fork, mut restored] = corrupt_credentials;
    let began = Instant::now();
    let directory = output.join("publication");
    std::fs::create_dir(&directory).unwrap();
    let context = PublicationContext::new(poll.clone(), setup.clone()).unwrap();
    let roster = setup.inventory().proposal();
    let owners: Vec<_> = enrollments
        .iter()
        .enumerate()
        .map(|(position, enrollment)| {
            let retained = RetainedContributionContext::parse(
                poll.identity(),
                poll.runtime(),
                position,
                roster.proposal().body(),
            )
            .unwrap();
            enrollment
                .credential
                .retain_ballot_owner(
                    &poll,
                    &retained,
                    setup.inventory().identity(),
                    openings[position].body(),
                    openings[position].signature(),
                )
                .unwrap()
        })
        .collect();
    let mut works: Vec<_> = enrollments
        .iter()
        .enumerate()
        .map(|(position, enrollment)| {
            let retained = RetainedContributionContext::parse(
                poll.identity(),
                poll.runtime(),
                position,
                roster.proposal().body(),
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
            registration_enrollment::publication_work::PublicationWork::new(
                owner,
                poll.clone(),
                setup.clone(),
            )
            .unwrap()
        })
        .collect();
    let mut private_publication_body_bytes = 0usize;
    let packet = |body: &[u8], signature: &[u8]| {
        let mut result = Vec::from((body.len() as u32).to_le_bytes());
        result.extend(body);
        result.extend(signature);
        result
    };
    let close_body = context.close_body().unwrap();
    assert!(
        enrollments[1]
            .credential
            .sign_publication_message(
                &owners[1],
                roster,
                PublicationPurpose::Close,
                &close_body,
                None,
                *crate::random::<32>()
            )
            .is_err()
    );
    assert_eq!(
        works[0]
            .command(&mut enrollments[0].credential, 1, 0, &[])
            .unwrap(),
        close_body
    );
    let mut close_input = close_body.clone();
    close_input.extend(*crate::random::<32>());
    let close_signature: [u8; 3309] = works[0]
        .command(&mut enrollments[0].credential, 8, 0, &close_input)
        .unwrap()
        .try_into()
        .unwrap();
    assert!(
        enrollments[0]
            .credential
            .sign_publication_message(
                &owners[0],
                roster,
                PublicationPurpose::Close,
                &close_body,
                None,
                *crate::random::<32>()
            )
            .is_err()
    );
    let close = context
        .authenticate_close(&close_body, &close_signature)
        .unwrap();
    crate::write(directory.join("close.bin"), &close_body);
    crate::write(directory.join("close-signature.bin"), &close_signature);
    let mut changed_signature = close_signature;
    changed_signature[0] ^= 1;
    assert!(
        context
            .authenticate_close(&close_body, &changed_signature)
            .is_err()
    );
    let mut changed_body = close_body.clone();
    changed_body.push(0);
    assert!(
        context
            .authenticate_close(&changed_body, &close_signature)
            .is_err()
    );
    for (work, enrollment) in works.iter_mut().zip(enrollments.iter_mut()) {
        work.command(
            &mut enrollment.credential,
            2,
            0,
            &packet(&close_body, &close_signature),
        )
        .unwrap();
    }
    let mut sources: Vec<AuthenticatedSource> = Vec::new();
    let mut authenticated_body_bytes = 0usize;
    for (envelope, signature, path) in ballots {
        let authenticate = || authenticate_envelope(&setup, envelope.bytes(), signature).unwrap();
        let mut body = BallotBodyAuthentication::new(authenticate()).unwrap();
        let mut corrupted = BallotBodyAuthentication::new(authenticate()).unwrap();
        let mut file = File::open(path).unwrap();
        let mut buffer = vec![0u8; 1 << 20];
        let mut offset = 0;
        loop {
            let length = file.read(&mut buffer).unwrap();
            if length == 0 {
                break;
            }
            body.push(&buffer[..length]).unwrap();
            if offset == 0 {
                buffer[0] ^= 1;
            }
            corrupted.push(&buffer[..length]).unwrap();
            offset += length;
        }
        assert!(corrupted.finish().is_err());
        authenticated_body_bytes += offset;
        sources.push(context.ballot_source(body.finish().unwrap()).unwrap());
    }
    for position in 0..3 {
        let empty = context.empty_body(&close, position).unwrap();
        assert!(
            enrollments[position]
                .credential
                .sign_publication_message(
                    &owners[position],
                    roster,
                    PublicationPurpose::Empty,
                    &empty,
                    Some(&close_signature),
                    *crate::random::<32>()
                )
                .is_err()
        );
    }
    for position in 3..enrollments.len() {
        let body = context.empty_body(&close, position).unwrap();
        assert!(
            enrollments[position]
                .credential
                .sign_publication_message(
                    &owners[position],
                    roster,
                    PublicationPurpose::Empty,
                    &body,
                    None,
                    *crate::random::<32>()
                )
                .is_err()
        );
        assert_eq!(
            works[position]
                .command(&mut enrollments[position].credential, 1, 1, &[])
                .unwrap(),
            body
        );
        let mut signing_input = body.clone();
        signing_input.extend(*crate::random::<32>());
        let signature: [u8; 3309] = works[position]
            .command(&mut enrollments[position].credential, 8, 0, &signing_input)
            .unwrap()
            .try_into()
            .unwrap();
        crate::write(
            directory.join(format!("source-{position}-empty.bin")),
            &body,
        );
        crate::write(
            directory.join(format!("source-{position}-signature.bin")),
            &signature,
        );
        sources.push(
            context
                .authenticate_empty(&close, &body, &signature)
                .unwrap(),
        );
        assert!(
            enrollments[position]
                .credential
                .reserve_ballot_attempt(&owners[position])
                .is_err()
        );
        assert!(
            enrollments[position]
                .credential
                .sign_publication_message(
                    &owners[position],
                    roster,
                    PublicationPurpose::Empty,
                    &body,
                    Some(&close_signature),
                    *crate::random::<32>()
                )
                .is_err()
        );
    }
    let mut batches = Vec::new();
    let mut signed_metadata_bytes = close_body.len() + close_signature.len();
    for position in 0..enrollments.len() {
        let assigned = context.assigned_sources(position).unwrap();
        let values = assigned
            .iter()
            .map(|author| &sources[*author])
            .collect::<Vec<_>>();
        assert!(
            context
                .witness_body(position, &values[..values.len() - 1])
                .is_err()
        );
        let body = context.witness_body(position, &values).unwrap();
        assert!(
            works[position]
                .command(&mut enrollments[position].credential, 1, 2, &[])
                .is_err()
        );
        for author in &assigned {
            match sources[*author].value() {
                SourceValue::Empty { body, signature } => {
                    works[position]
                        .command(
                            &mut enrollments[position].credential,
                            6,
                            0,
                            &packet(body, signature),
                        )
                        .unwrap();
                }
                SourceValue::Ballot(authenticated) => {
                    let envelope = authenticated.authentication().envelope();
                    let mut control = envelope.bytes().to_vec();
                    control.extend(authenticated.authentication().signature());
                    works[position]
                        .command(&mut enrollments[position].credential, 3, 0, &control)
                        .unwrap();
                    let mut file = File::open(ballots[*author].2).unwrap();
                    let mut buffer = vec![0u8; 1 << 20];
                    loop {
                        let length = file.read(&mut buffer).unwrap();
                        if length == 0 {
                            break;
                        }
                        private_publication_body_bytes += length;
                        works[position]
                            .command(
                                &mut enrollments[position].credential,
                                4,
                                0,
                                &buffer[..length],
                            )
                            .unwrap();
                    }
                    works[position]
                        .command(&mut enrollments[position].credential, 5, 0, &[])
                        .unwrap();
                }
            }
        }
        assert_eq!(
            works[position]
                .command(&mut enrollments[position].credential, 1, 2, &[])
                .unwrap(),
            body
        );
        let mut signing_input = body.clone();
        signing_input.extend(*crate::random::<32>());
        signing_input[body.len() - 1] ^= 1;
        assert!(
            works[position]
                .command(&mut enrollments[position].credential, 8, 0, &signing_input)
                .is_err()
        );
        signing_input[body.len() - 1] ^= 1;
        let signature: [u8; 3309] = works[position]
            .command(&mut enrollments[position].credential, 8, 0, &signing_input)
            .unwrap()
            .try_into()
            .unwrap();
        signed_metadata_bytes += body.len() + signature.len();
        crate::write(directory.join(format!("witness-{position}.bin")), &body);
        crate::write(
            directory.join(format!("witness-{position}-signature.bin")),
            &signature,
        );
        batches.push(context.authenticate_witness(&body, &signature).unwrap());
        assert!(
            enrollments[position]
                .credential
                .sign_publication_message(
                    &owners[position],
                    roster,
                    PublicationPurpose::Witness,
                    &body,
                    None,
                    *crate::random::<32>()
                )
                .is_err()
        );
        let mut corrupt = body.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(context.authenticate_witness(&corrupt, &signature).is_err());
    }
    let selected = |author: usize| {
        batches
            .iter()
            .filter(|batch| {
                context
                    .assigned_sources(batch.signer())
                    .unwrap()
                    .contains(&author)
            })
            .cloned()
            .collect::<Vec<_>>()
    };
    let mut slots = Vec::new();
    for source in &sources {
        let required = selected(source.author());
        assert!(
            context
                .verify_slot(source.clone(), required[..required.len() - 1].to_vec())
                .is_err()
        );
        let mut duplicated = required.clone();
        duplicated[1] = duplicated[0].clone();
        assert!(context.verify_slot(source.clone(), duplicated).is_err());
        slots.push(context.verify_slot(source.clone(), required).unwrap());
    }
    let closed = context
        .verify_closed_slots(close.clone(), slots.clone())
        .unwrap();
    assert!(
        context
            .verify_closed_slots(close.clone(), slots[..slots.len() - 1].to_vec())
            .is_err()
    );
    let mut reordered = slots.clone();
    reordered.swap(0, 1);
    assert!(
        context
            .verify_closed_slots(close.clone(), reordered)
            .is_err()
    );
    crate::write(directory.join("closed-slots.bin"), closed.body());
    crate::write(
        directory.join("closed-slots-identity.bin"),
        closed.identity(),
    );
    // Participant three is in the fixed corrupt set {1, 2, 3}. Forking that
    // participant's own state models permitted corruption, not honest recovery.
    let original_body = ballots[0];
    let alternate_envelope = BallotEnvelope::new(
        poll.identity(),
        setup.inventory().identity(),
        3,
        original_body.0.body_length(),
        *original_body.0.body_identity(),
    )
    .unwrap();
    let alternate_signature = corrupt_fork
        .sign_retained_ballot_envelope(&owners[3], &alternate_envelope, *crate::random::<32>())
        .unwrap();
    let authentication =
        authenticate_envelope(&setup, alternate_envelope.bytes(), &alternate_signature).unwrap();
    let mut authentication = BallotBodyAuthentication::new(authentication).unwrap();
    let mut file = File::open(original_body.2).unwrap();
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        let length = file.read(&mut buffer).unwrap();
        if length == 0 {
            break;
        }
        authentication.push(&buffer[..length]).unwrap();
    }
    let alternate = context
        .ballot_source(authentication.finish().unwrap())
        .unwrap();
    assert!(context.verify_slot(alternate, selected(3)).is_err());
    let mut changed_batch = batches[3].body().to_vec();
    *changed_batch.last_mut().unwrap() ^= 1;
    let changed_signature = corrupt_fork
        .sign_publication_message(
            &owners[3],
            roster,
            PublicationPurpose::Witness,
            &changed_batch,
            None,
            *crate::random::<32>(),
        )
        .unwrap();
    let changed_batch = context
        .authenticate_witness(&changed_batch, &changed_signature)
        .unwrap();
    crate::write(
        directory.join("witness-3-equivocation.bin"),
        changed_batch.body(),
    );
    crate::write(
        directory.join("witness-3-equivocation-signature.bin"),
        changed_batch.signature(),
    );
    let mut changed_carriers = selected(0);
    changed_carriers[2] = changed_batch.clone();
    let mut changed_slots = slots.clone();
    changed_slots[0] = context
        .verify_slot(sources[0].clone(), changed_carriers)
        .unwrap();
    assert_eq!(
        context
            .verify_closed_slots(close.clone(), changed_slots)
            .unwrap()
            .identity(),
        closed.identity()
    );
    let mut changed_carriers = selected(2);
    changed_carriers[0] = changed_batch;
    assert!(
        context
            .verify_slot(sources[2].clone(), changed_carriers)
            .is_err()
    );
    if let SourceValue::Empty { body, signature } = sources[3].value() {
        let mut bad = *signature;
        bad[0] ^= 1;
        assert!(
            restored
                .restore_publication_message(
                    &owners[3],
                    roster,
                    PublicationPurpose::Empty,
                    body,
                    &bad
                )
                .is_err()
        );
        restored
            .restore_publication_message(
                &owners[3],
                roster,
                PublicationPurpose::Empty,
                body,
                signature,
            )
            .unwrap();
        assert!(restored.reserve_ballot_attempt(&owners[3]).is_err());
    } else {
        panic!("Expected the original empty source");
    }
    let mut bad = *batches[3].signature();
    bad[0] ^= 1;
    assert!(
        restored
            .restore_publication_message(
                &owners[3],
                roster,
                PublicationPurpose::Witness,
                batches[3].body(),
                &bad
            )
            .is_err()
    );
    restored
        .restore_publication_message(
            &owners[3],
            roster,
            PublicationPurpose::Witness,
            batches[3].body(),
            batches[3].signature(),
        )
        .unwrap();
    assert!(
        restored
            .sign_publication_message(
                &owners[3],
                roster,
                PublicationPurpose::Witness,
                batches[3].body(),
                None,
                *crate::random::<32>()
            )
            .is_err()
    );
    assert_eq!(
        context
            .verify_closed_slots(close, slots)
            .unwrap()
            .identity(),
        closed.identity()
    );
    assert!(matches!(
        closed.slots()[0].source().value(),
        SourceValue::Ballot(_)
    ));
    assert!(matches!(
        closed.slots()[3].source().value(),
        SourceValue::Empty { .. }
    ));
    let source_metadata_bytes: usize = sources
        .iter()
        .map(|source| match source.value() {
            SourceValue::Ballot(body) => {
                body.authentication().envelope().bytes().len()
                    + body.authentication().signature().len()
            }
            SourceValue::Empty { body, signature } => body.len() + signature.len(),
        })
        .sum();
    let body_hash_bytes = authenticated_body_bytes * 2
        + original_body.0.body_length()
        + private_publication_body_bytes;
    let body_read_bytes =
        authenticated_body_bytes + original_body.0.body_length() + private_publication_body_bytes;
    crate::write(directory.join("measurements.json"), format!("{{\"sourceBodyBytes\":{authenticated_body_bytes},\"privatePublicationBodyBytes\":{private_publication_body_bytes},\"bodyHashBytesIncludingFaultControls\":{body_hash_bytes},\"bodyReadBytesIncludingFaultControls\":{body_read_bytes},\"closeAndWitnessMetadataBytes\":{signed_metadata_bytes},\"sourceMetadataBytes\":{source_metadata_bytes},\"elapsedMilliseconds\":{},\"sourceCount\":{},\"witnessBatchCount\":{}}}\n", began.elapsed().as_millis(), closed.slots().len(), batches.len()).as_bytes());
    println!(
        "Verified actual closed slot evidence, exact bodies, fixed witness sets and late corrupt equivocation"
    );
    closed
}
