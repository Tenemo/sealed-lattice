use crate::{BallotInputs, OriginalEnrollments, Scenario, aggregate, close, completion};
use evaluation_target::close::{CloseContext, ClosedSlot};
use registration_credentials::poll::{SignedPoll, VerifiedPoll};
use registration_enrollment::finality_work::OwnBallotInclusion;
use setup_aggregate::verified::VerifiedSetupAggregate;
use std::{fs, path::Path, sync::Arc};

/// Completes from the original active participants after either an early
/// departure or the corrupt organizer's losing selection endorsement.
pub fn run(
    output: &Path,
    scratch: &Path,
    poll: Arc<VerifiedPoll>,
    setup: Arc<VerifiedSetupAggregate>,
    definition: &SignedPoll,
    enrollments: &mut OriginalEnrollments,
    scenario: &Scenario,
) {
    let active = enrollments.positions();
    assert_eq!(active, scenario.active());
    assert_eq!(setup.profile().participants(), 4);
    let directory = output.join("ballot");
    fs::create_dir(&directory).unwrap();
    let final_keys = aggregate::final_keys(output, scenario.profile());
    let inputs = BallotInputs {
        poll: &poll,
        setup: &setup,
        definition,
        final_keys: &final_keys,
        directory: &directory,
        scenario,
    };
    let submissions: Vec<_> = active
        .iter()
        .map(|position| {
            inputs.cast(
                &mut enrollments[*position],
                *position,
                &scenario.scores(*position),
            )
        })
        .collect();
    let held: Vec<_> = submissions.iter().collect();
    let mut works: Vec<_> = active
        .iter()
        .map(|position| close::close_work(&enrollments[*position], &poll, &setup, *position))
        .collect();
    let mut hashed = 0;
    for (ordinal, position) in active.iter().enumerate() {
        for submission in &held {
            close::deliver(
                &mut works[ordinal],
                &mut enrollments[*position].credential,
                submission,
                &mut hashed,
            );
        }
    }
    let (body, signature) = close::open(&mut works, enrollments, close::now_milliseconds());
    let context = CloseContext::new(poll.clone(), setup.clone()).unwrap();
    let intent = context.authenticate_intent(&body, &signature).unwrap();
    let mut responses = vec![Vec::new(); active.len()];
    for ordinal in 1..active.len() {
        responses[ordinal] = close::respond(
            &mut works[ordinal],
            &mut enrollments[active[ordinal]].credential,
            &[],
            &mut hashed,
        );
    }
    let arrivals = responses[1..].iter().collect::<Vec<_>>();
    let (own, proposal) = close::organize(
        &mut works[0],
        &mut enrollments[0].credential,
        scenario.profile().participants(),
        &arrivals,
    );
    responses[0] = own;
    let bodies: Vec<_> = held
        .iter()
        .map(|submission| close::authenticate(&setup, submission, &mut hashed))
        .collect();
    let envelopes: Vec<_> = bodies
        .iter()
        .map(|body| body.authentication().clone())
        .collect();
    let authenticated = close::authenticate_responses(&context, &intent, &responses, &envelopes);
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
    for (position, slot) in barrier.slots().iter().enumerate() {
        assert_eq!(
            matches!(slot, ClosedSlot::Usable(_)),
            active.contains(&position)
        );
        assert!(!matches!(slot, ClosedSlot::Conflicting(_)));
    }
    close::write_records(
        &output.join("close"),
        output,
        &close::packet(&body, &signature),
        active.iter().copied().zip(&responses),
        &proposal,
        &held,
    );
    for (ordinal, position) in active.iter().enumerate() {
        let fresh = close::close_work(&enrollments[*position], &poll, &setup, *position);
        close::replay(
            &works[ordinal],
            fresh,
            &mut enrollments[*position].credential,
            &responses[ordinal],
            (*position == 0).then_some(proposal.as_slice()),
        );
    }
    completion::run(
        output,
        scratch,
        barrier,
        enrollments,
        completion::Finality {
            signers: active.clone(),
            statuses: active
                .iter()
                .map(|position| (*position, OwnBallotInclusion::Included))
                .collect(),
            forks: Vec::new(),
        },
        scenario,
    );
    if scenario.departed.is_some() {
        for name in [
            "contribution-1",
            "selection-endorsement-1.bin",
            "close/response-1.bin",
            "ballot/envelope-1.bin",
            "completion/target-vote-1.bin",
            "completion/release-1.bin",
            "completion/release-envelope-1.bin",
        ] {
            assert!(
                !output.join(name).exists(),
                "A departed participant emitted a later message: {name}"
            );
        }
    }
}
