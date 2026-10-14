use participant_module::close_work::CloseOperation;
use protocol_foundations::{Refusal, close_signing::CloseResponseMessage, poll::VerifiedPoll};
use setup_aggregate::verified::VerifiedSetupAggregate;
use std::sync::Arc;

use super::EquivocatedSubmissions;
use super::records::{Submission, control, read_chunks, split, wanted_bytes};
use super::work::{LoggedWork, close_work, deliver, gather};

pub(super) struct CloseDeliveryInputs<'a> {
    pub(super) intent_packet: &'a [u8],
    pub(super) arrivals: &'a [&'a Vec<u8>],
    pub(super) common: &'a [&'a Submission],
    pub(super) everything: &'a [&'a Submission],
    pub(super) omitted: Option<&'a Submission>,
    pub(super) equivocated: Option<&'a EquivocatedSubmissions>,
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
        equivocated,
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
        Err(Refusal::Context)
    ));
    let mut probe = close_work(&enrollments[0], poll, setup, 0);
    let mut hashed = 0;
    if let Some(equivocated) = &equivocated {
        for submission in [&equivocated.first_on_time, &equivocated.late] {
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
                &control(&equivocated.second_on_time)
            ),
            Err(Refusal::Consumed)
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
    if let Some(equivocated) = &equivocated {
        assert!(matches!(
            probe.command(
                &mut enrollments[0].credential,
                CloseOperation::BeginHeldBody,
                0,
                &control(&equivocated.late)
            ),
            Err(Refusal::Context)
        ));
        deliver(
            &mut probe,
            &mut enrollments[0].credential,
            &equivocated.second_on_time,
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
        Err(Refusal::Shape)
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
        Err(Refusal::Context)
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
        Err(Refusal::Consumed)
    ));
    let missing: Vec<u8> = common[1..]
        .iter()
        .flat_map(|submission| control(submission))
        .collect();
    let unlisted = equivocated
        .as_ref()
        .map(|equivocated| &equivocated.late)
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
            Err(Refusal::Context)
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
        Err(Refusal::Consumed)
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
    let envelope = all_wanted[0].envelope.bytes();
    assert!(
        lacking
            .command(
                &mut enrollments[0].credential,
                CloseOperation::EnvelopeIdentity,
                0,
                &envelope[..envelope.len() - 1]
            )
            .is_err()
    );
    for operation in [
        CloseOperation::PrepareResponse,
        CloseOperation::PrepareProposal,
    ] {
        assert!(matches!(
            lacking.command(&mut enrollments[0].credential, operation, 0, &[]),
            Err(Refusal::Context)
        ));
    }

    hashed
}
