use ballot_proof::publication::{PublicationContext, SourceValue};
use registration_credentials::{
    contribution_authentication::SignedOpening, poll::VerifiedPoll,
    roster::RetainedContributionContext,
};
use registration_enrollment::{Enrollment, publication_work::PublicationWork};
use setup_aggregate::verified::VerifiedSetupAggregate;
use std::{path::Path, sync::Arc};

fn packet(body: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::from((body.len() as u32).to_le_bytes());
    bytes.extend(body);
    bytes.extend(signature);
    bytes
}
pub fn run(
    output: &Path,
    poll: Arc<VerifiedPoll>,
    setup: Arc<VerifiedSetupAggregate>,
    enrollments: &mut [Enrollment],
    openings: &[SignedOpening],
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
            work.command(&mut enrollment.credential, 6, 0, &packets[author])
                .unwrap();
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
            .all(|slot| matches!(slot.source().value(), SourceValue::Empty { .. }))
    );
    crate::write(directory.join("closed-slots.bin"), closed.body());
    crate::write(
        directory.join("closed-slots-identity.bin"),
        closed.identity(),
    );
    println!("Verified original-credential empty publication for every participant");
    closed
}
