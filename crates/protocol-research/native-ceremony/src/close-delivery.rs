use participant_module::close_work::CloseOperation;
use protocol_foundations::{Error, close_signing::CloseResponseMessage, poll::VerifiedPoll};
use setup_aggregate::verified::VerifiedSetupAggregate;
use std::sync::Arc;

use super::Forged;
use super::records::{Submission, control, read_chunks, split, wanted_bytes};
use super::work::{LoggedWork, close_work, deliver, gather};

pub(super) struct CloseDeliveryInputs<'a> {
    pub(super) intent_packet: &'a [u8],
    pub(super) arrivals: &'a [&'a Vec<u8>],
    pub(super) common: &'a [&'a Submission],
    pub(super) everything: &'a [&'a Submission],
    pub(super) omitted: Option<&'a Submission>,
    pub(super) forged: Option<&'a Forged>,
}

pub(super) fn exercise_body_delivery(
    poll: &Arc<VerifiedPoll>,
    setup: &Arc<VerifiedSetupAggregate>,
    enrollments: &mut crate::OriginalEnrollments,
    nonorganizer: &mut LoggedWork,
    inputs: CloseDeliveryInputs<'_>,
) -> usize {
    let count = enrollments.len();
    let CloseDeliveryInputs {
        intent_packet,
        arrivals,
        common,
        everything,
        omitted,
        forged,
    } = inputs;
    // Only the organizer takes responses. Delivery adds at most two envelopes
    // to a slot, and the intent lock discards and then refuses late ones.
    assert!(matches!(
        nonorganizer.command(
            &mut enrollments[1].credential,
            CloseOperation::AdmitResponse,
            0,
            arrivals[0]
        ),
        Err(Error::Context)
    ));
    let mut probe = close_work(&enrollments[0], poll, setup, 0);
    let mut hashed = 0;
    if let Some(forged) = &forged {
        for submission in [&forged.a, &forged.late] {
            deliver(
                &mut probe,
                &mut enrollments[0].credential,
                submission,
                &mut hashed,
            );
        }
        assert!(matches!(
            probe.command(
                &mut enrollments[0].credential,
                CloseOperation::BeginHeldBody,
                0,
                &control(&forged.b)
            ),
            Err(Error::Consumed)
        ));
    }
    probe
        .command(
            &mut enrollments[0].credential,
            CloseOperation::LockIntent,
            0,
            intent_packet,
        )
        .unwrap();
    if let Some(forged) = &forged {
        assert!(matches!(
            probe.command(
                &mut enrollments[0].credential,
                CloseOperation::BeginHeldBody,
                0,
                &control(&forged.late)
            ),
            Err(Error::Context)
        ));
        deliver(
            &mut probe,
            &mut enrollments[0].credential,
            &forged.b,
            &mut hashed,
        );
    }
    // A response carries exactly the unknown envelopes it lists: adding one
    // it does not list, or one already known, refuses the whole response.
    let first = CloseResponseMessage::parse(split(arrivals[0]).0, count).unwrap();
    let lists = |submission: &Submission| {
        first
            .listed()
            .iter()
            .any(|(_, identity)| *identity == submission.envelope.identity())
    };
    let known = common[0];
    assert!(lists(known));
    // The complete valid body may arrive before transport reports failure.
    // Cancellation must not install it or block its later genuine delivery.
    probe
        .command(
            &mut enrollments[0].credential,
            CloseOperation::BeginHeldBody,
            0,
            &control(known),
        )
        .unwrap();
    hashed += read_chunks(&known.body, |bytes| {
        probe
            .command(
                &mut enrollments[0].credential,
                CloseOperation::PushHeldBody,
                0,
                bytes,
            )
            .unwrap();
    });
    assert!(matches!(
        probe.command(
            &mut enrollments[0].credential,
            CloseOperation::DiscardHeldBody,
            0,
            &[0]
        ),
        Err(Error::Shape)
    ));
    probe
        .command(
            &mut enrollments[0].credential,
            CloseOperation::DiscardHeldBody,
            0,
            &[],
        )
        .unwrap();
    assert!(matches!(
        probe.command(
            &mut enrollments[0].credential,
            CloseOperation::FinishHeldBody,
            0,
            &[]
        ),
        Err(Error::Context)
    ));
    deliver(
        &mut probe,
        &mut enrollments[0].credential,
        known,
        &mut hashed,
    );
    probe
        .command(
            &mut enrollments[0].credential,
            CloseOperation::DiscardHeldBody,
            0,
            &[],
        )
        .unwrap();
    // An input that changes nothing is refused, so no log of accepted inputs
    // records it.
    assert!(matches!(
        probe.command(
            &mut enrollments[0].credential,
            CloseOperation::BeginHeldBody,
            0,
            &control(known)
        ),
        Err(Error::Consumed)
    ));
    let missing: Vec<u8> = common[1..]
        .iter()
        .flat_map(|submission| control(submission))
        .collect();
    let unlisted = forged
        .as_ref()
        .map(|forged| &forged.late)
        .into_iter()
        .chain(omitted)
        .find(|submission| !lists(submission));
    for extra in unlisted.into_iter().chain([known]) {
        assert!(matches!(
            probe.command(
                &mut enrollments[0].credential,
                CloseOperation::AdmitResponse,
                0,
                &[arrivals[0].as_slice(), &missing, &control(extra)].concat()
            ),
            Err(Error::Context)
        ));
    }
    probe
        .command(
            &mut enrollments[0].credential,
            CloseOperation::AdmitResponse,
            0,
            &[arrivals[0].as_slice(), &missing].concat(),
        )
        .unwrap();
    assert!(matches!(
        probe.command(
            &mut enrollments[0].credential,
            CloseOperation::AdmitResponse,
            0,
            arrivals[0]
        ),
        Err(Error::Consumed)
    ));
    let mut lacking = close_work(&enrollments[0], poll, setup, 0);
    lacking
        .command(
            &mut enrollments[0].credential,
            CloseOperation::LockIntent,
            0,
            intent_packet,
        )
        .unwrap();
    gather(
        &mut lacking,
        &mut enrollments[0].credential,
        count,
        everything,
        arrivals,
    );
    let mut all_wanted = common.to_vec();
    all_wanted.extend(omitted);
    assert_eq!(
        lacking
            .command(
                &mut enrollments[0].credential,
                CloseOperation::WantedBodies,
                0,
                &[]
            )
            .unwrap(),
        wanted_bytes(&all_wanted)
    );
    // Each wanted body is named by the identity the close work reports for
    // its envelope, and bytes that are not an envelope have none.
    for submission in &all_wanted {
        assert_eq!(
            lacking
                .command(
                    &mut enrollments[0].credential,
                    CloseOperation::EnvelopeIdentity,
                    0,
                    submission.envelope.bytes()
                )
                .unwrap(),
            submission.envelope.identity()
        );
    }
    let mut malformed = all_wanted[0].envelope.bytes().to_vec();
    malformed[0] ^= 1;
    assert!(
        lacking
            .command(
                &mut enrollments[0].credential,
                CloseOperation::EnvelopeIdentity,
                0,
                &malformed
            )
            .is_err()
    );
    for operation in [
        CloseOperation::PrepareResponse,
        CloseOperation::PrepareProposal,
    ] {
        assert!(matches!(
            lacking.command(&mut enrollments[0].credential, operation, 0, &[]),
            Err(Error::Context)
        ));
    }

    hashed
}
