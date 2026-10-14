#[path = "close-delivery.rs"]
mod delivery;
#[path = "close-records.rs"]
mod records;
#[path = "close-work.rs"]
mod work;
pub use records::{Submission, authenticate, envelope, packet, write_records};
use records::{control, split, wanted_bytes};
pub use work::{
    authenticate_responses, close_work, deliver, now_milliseconds, open, organize, owner_of,
    replay, respond, sign,
};
use work::{conclude, gather};

use crate::scenario::Scenario;
use ballot_proof::submission::{AuthenticatedBallotBody, AuthenticatedBallotEnvelope};
use evaluation_target::close::{
    CloseContext, ClosedSlot, Error as CloseError, VerifiedCloseBarrier,
};
use participant_module::close_work::CloseOperation;
use protocol_foundations::{
    Credential, Error,
    ballot_authentication::{BallotEnvelope, RetainedBallotOwner},
    close_signing::{
        CloseIntentMessage, CloseMessage, ClosePurpose, CloseResponseMessage, close_quorum,
        maximum_close_message_bytes,
    },
    foundation::{CanonicalItem, CanonicalTuple},
    poll::VerifiedPoll,
};
use setup_aggregate::verified::VerifiedSetupAggregate;
use std::{path::Path, sync::Arc, time::Instant};

/// A corrupt equivocator's credentials restored from its sealed capsule.
/// Forking its own signing state models permitted corruption, not honest
/// recovery.
pub struct Equivocator {
    pub forks: [Credential; 3],
    pub restored: Credential,
}
/// Credentials restored from sealed capsules. The organizer's restored
/// credential stays locked and only replays its completed messages.
pub struct Restored {
    pub equivocator: Option<Equivocator>,
    pub organizer: Credential,
}

/// The result case of the scenario. The organizer proposes responses 0 to
/// `n - f - 1`. A corrupt equivocator signs two on-time envelopes, which
/// make its slot conflicting, and a late envelope. The organizer holds only
/// the late one, which its intent lock discards, and lists both on-time
/// envelopes from other responses without their bodies. The relay delivers
/// the omitted voter's ballot only to the last `f` positions, so the
/// proposal omits it within the bound of `f`. Returns the barrier and the
/// late fork.
pub fn run(
    output: &Path,
    poll: Arc<VerifiedPoll>,
    setup: Arc<VerifiedSetupAggregate>,
    enrollments: &mut crate::OriginalEnrollments,
    submissions: &[Option<Submission>],
    restored: Restored,
    scenario: &Scenario,
) -> (VerifiedCloseBarrier, Option<Credential>) {
    let began = Instant::now();
    let profile = scenario.profile();
    let count = enrollments.len();
    assert_eq!(count, profile.participants());
    let quorum = close_quorum(count);
    assert_eq!(quorum, profile.inventory_threshold());
    let context = CloseContext::new(poll.clone(), setup.clone()).unwrap();
    let roster = setup.roster();
    let mut hashed = 0;
    let mut works: Vec<_> = (0..count)
        .map(|position| close_work(&enrollments[position], &poll, &setup, position))
        .collect();
    let base = submissions[0].as_ref().unwrap();
    let first_honest = scenario.first_honest_responder();
    let close_time = now_milliseconds() + 2;
    // The equivocator signs two on-time envelopes over one body, then a late
    // one, each from its own fork. Their times are fixed against the close
    // time, so however long signing takes, the first two stay on time.
    let Restored {
        equivocator,
        organizer: mut organizer_restored,
    } = restored;
    let (mut equivocation, forged) = equivocator
        .map(|equivocator| {
            let position = scenario.equivocator.unwrap();
            let Equivocator {
                forks: [mut first, mut second, mut late_fork],
                restored,
            } = equivocator;
            let owner = owner_of(&first, &poll, &setup, position);
            let equivocate = |fork: &mut Credential, time: u64| {
                let envelope = BallotEnvelope::new(
                    profile,
                    poll.identity(),
                    setup.identity(),
                    position,
                    time,
                    base.envelope.body_length(),
                    *base.envelope.body_identity(),
                )
                .unwrap();
                let signature = fork
                    .sign_retained_ballot_envelope(&owner, &envelope)
                    .unwrap();
                Submission {
                    envelope,
                    signature,
                    body: base.body.clone(),
                }
            };
            let a = equivocate(&mut first, close_time - 2);
            let b = equivocate(&mut second, close_time - 1);
            assert_ne!(a.envelope.identity(), b.envelope.identity());
            let late = equivocate(&mut late_fork, close_time + 1);
            (
                Equivocation {
                    position,
                    owner,
                    late_fork,
                    restored,
                },
                Forged { a, b, late },
            )
        })
        .unzip();
    if let Some(forged) = &forged {
        let position = scenario.equivocator.unwrap();
        // The late envelope reaches the organizer and the first honest
        // responder before the intent; their locks discard its body and
        // refuse it afterwards.
        for position in [0, first_honest] {
            deliver(
                &mut works[position],
                &mut enrollments[position].credential,
                &forged.late,
                &mut hashed,
            );
        }
        // A slot holds at most two bodies: a third is refused before
        // transfer.
        for submission in [&forged.a, &forged.b] {
            deliver(
                &mut works[position],
                &mut enrollments[position].credential,
                submission,
                &mut hashed,
            );
        }
        assert!(matches!(
            works[position].command(
                &mut enrollments[position].credential,
                CloseOperation::BeginHeldBody,
                0,
                &control(&forged.late)
            ),
            Err(Error::Consumed)
        ));
    }
    // Only the organizer closes, and only once.
    let mut other = close_work(&enrollments[1], &poll, &setup, 1);
    let body = other
        .command(
            &mut enrollments[1].credential,
            CloseOperation::PrepareIntent,
            0,
            &close_time.to_le_bytes(),
        )
        .unwrap();
    assert!(matches!(
        sign(&mut other, &mut enrollments[1].credential, &body),
        Err(Error::Context)
    ));
    let (intent_body, intent_signature) = open(&mut works, enrollments, close_time);
    let intent_packet = packet(&intent_body, &intent_signature);
    let mut repeated = close_work(&enrollments[0], &poll, &setup, 0);
    let later = repeated
        .command(
            &mut enrollments[0].credential,
            CloseOperation::PrepareIntent,
            0,
            &(close_time + 5).to_le_bytes(),
        )
        .unwrap();
    assert!(matches!(
        sign(&mut repeated, &mut enrollments[0].credential, &later),
        Err(Error::Consumed)
    ));
    let intent = context
        .authenticate_intent(&intent_body, &intent_signature)
        .unwrap();
    let mut changed = intent_signature.clone();
    changed[0] ^= 1;
    assert_eq!(
        context.authenticate_intent(&intent_body, &changed).err(),
        Some(CloseError::Signature)
    );
    let unsigned = context.intent(close_time + 5).unwrap();
    assert_eq!(
        context
            .authenticate_intent(unsigned.body(), &intent_signature)
            .err(),
        Some(CloseError::Signature)
    );
    let mut refused = close_work(&enrollments[first_honest], &poll, &setup, first_honest);
    assert!(
        refused
            .command(
                &mut enrollments[first_honest].credential,
                CloseOperation::LockIntent,
                0,
                &packet(unsigned.body(), &intent_signature)
            )
            .is_err()
    );
    // No attempt starts after the close intent, and no ballot is signed.
    if let Some(&nonvoter) = scenario.nonvoters.first() {
        let owner = owner_of(&enrollments[nonvoter].credential, &poll, &setup, nonvoter);
        assert!(matches!(
            enrollments[nonvoter]
                .credential
                .reserve_ballot_attempt(&owner),
            Err(Error::Consumed)
        ));
        let envelope = BallotEnvelope::new(
            profile,
            poll.identity(),
            setup.identity(),
            nonvoter,
            close_time - 1,
            base.envelope.body_length(),
            *base.envelope.body_identity(),
        )
        .unwrap();
        assert!(matches!(
            enrollments[nonvoter]
                .credential
                .sign_retained_ballot_envelope(&owner, &envelope),
            Err(Error::Consumed)
        ));
    }
    if let Some(forged) = &forged {
        for position in [0, first_honest] {
            assert!(matches!(
                works[position].command(
                    &mut enrollments[position].credential,
                    CloseOperation::BeginHeldBody,
                    0,
                    &control(&forged.late)
                ),
                Err(Error::Context)
            ));
        }
    }
    // The relay's schedule. Everyone holds the usable slots' submissions; the
    // equivocator's first envelope reaches the lower half of the other
    // positions and its second the upper half, and the omitted ballot
    // reaches only the last `f` positions.
    let common: Vec<&Submission> = scenario
        .usable()
        .iter()
        .map(|author| submissions[*author].as_ref().unwrap())
        .collect();
    let omitted = scenario
        .omitted
        .map(|author| submissions[author].as_ref().unwrap());
    let mut held: Vec<Vec<&Submission>> = vec![common.clone(); count];
    if let Some(forged) = &forged {
        for (second, submission) in [(false, &forged.a), (true, &forged.b)] {
            for position in scenario.equivocation_holders(second) {
                held[position].push(submission);
            }
        }
    }
    if let Some(omitted) = omitted {
        for position in scenario.omitted_holders() {
            held[position].push(omitted);
        }
    }
    // The organizer answers only when it can propose.
    for submission in &common {
        deliver(
            &mut works[0],
            &mut enrollments[0].credential,
            submission,
            &mut hashed,
        );
    }
    assert!(matches!(
        works[0].command(
            &mut enrollments[0].credential,
            CloseOperation::PrepareResponse,
            0,
            &[]
        ),
        Err(Error::Context)
    ));
    // A voter's response must list its own on-time ballot.
    let voter = scenario.omitted.unwrap_or(*scenario.voters.last().unwrap());
    let mut incomplete = close_work(&enrollments[voter], &poll, &setup, voter);
    incomplete
        .command(
            &mut enrollments[voter].credential,
            CloseOperation::LockIntent,
            0,
            &intent_packet,
        )
        .unwrap();
    for submission in common
        .iter()
        .filter(|submission| submission.envelope.position() != voter)
    {
        deliver(
            &mut incomplete,
            &mut enrollments[voter].credential,
            submission,
            &mut hashed,
        );
    }
    let body = incomplete
        .command(
            &mut enrollments[voter].credential,
            CloseOperation::PrepareResponse,
            0,
            &[],
        )
        .unwrap();
    assert!(matches!(
        sign(&mut incomplete, &mut enrollments[voter].credential, &body),
        Err(Error::Context)
    ));
    // Every other participant responds without waiting.
    let mut responses: Vec<Vec<u8>> = vec![Vec::new(); count];
    for position in 1..count {
        responses[position] = respond(
            &mut works[position],
            &mut enrollments[position].credential,
            &held[position],
            &mut hashed,
        );
    }
    let mut everything: Vec<&Submission> = common.clone();
    if let Some(forged) = &forged {
        everything.extend([&forged.a, &forged.b, &forged.late]);
    }
    everything.extend(omitted);
    let available: Vec<AuthenticatedBallotEnvelope> = everything
        .iter()
        .map(|submission| envelope(&setup, submission))
        .collect();
    let mut late_response = None;
    if let (Some(equivocation), Some(forged)) = (equivocation.as_mut(), &forged) {
        // A corrupt fork may sign a response that lists its late envelope; no
        // verifier authenticates it.
        let position = equivocation.position;
        let late_fork = &mut equivocation.late_fork;
        late_fork
            .unlock_unused_purposes(protocol_foundations::SigningPurpose::CloseResponse.mask())
            .unwrap();
        late_fork
            .lock_close_intent(
                &equivocation.owner,
                roster,
                intent.message(),
                &intent_signature,
            )
            .unwrap();
        let late_listing = CloseResponseMessage::new(
            poll.identity(),
            setup.identity(),
            *intent.message().identity(),
            position,
            count,
            &[(position, forged.late.envelope.identity())],
        )
        .unwrap();
        let late_signature = late_fork
            .sign_close_response(&equivocation.owner, roster, &late_listing)
            .unwrap();
        assert_eq!(
            context
                .authenticate_response(&intent, late_listing.body(), &late_signature, &available)
                .err(),
            Some(CloseError::Context)
        );
        assert!(
            works[0]
                .command(
                    &mut enrollments[0].credential,
                    CloseOperation::AdmitResponse,
                    0,
                    &packet(late_listing.body(), &late_signature)
                )
                .is_err()
        );
        // Three envelopes for one slot are refused before any signature
        // check.
        let mut entries: Vec<_> = [&forged.a, &forged.b, &forged.late]
            .iter()
            .map(|submission| (position as u16, submission.envelope.identity()))
            .collect();
        entries.sort();
        let three = CanonicalTuple::new(
            1,
            1,
            vec![
                CanonicalItem::nonempty_ascii("sealed-lattice/close-response/v1").unwrap(),
                CanonicalItem::hash512(poll.identity()),
                CanonicalItem::hash512(setup.identity()),
                CanonicalItem::hash512(*intent.message().identity()),
                CanonicalItem::unsigned16(position as u16),
                CanonicalItem::variable_bytes(
                    entries
                        .iter()
                        .flat_map(|(author, identity)| {
                            author
                                .to_le_bytes()
                                .into_iter()
                                .chain(identity.iter().copied())
                        })
                        .collect::<Vec<u8>>(),
                )
                .unwrap(),
            ],
        )
        .encode()
        .unwrap();
        assert!(three.len() <= maximum_close_message_bytes(ClosePurpose::Response, count));
        assert_eq!(
            context
                .authenticate_response(&intent, &three, &late_signature, &available)
                .err(),
            Some(CloseError::Shape)
        );
        late_response = Some(packet(late_listing.body(), &late_signature));
    }
    // A response naming another intent is refused before its signature.
    let other_intent = CloseIntentMessage::new(poll.identity(), setup.identity(), 7).unwrap();
    let (first_body, first_signature) = split(&responses[1]);
    let misdirected = CloseResponseMessage::new(
        poll.identity(),
        setup.identity(),
        *other_intent.identity(),
        1,
        count,
        CloseResponseMessage::parse(first_body, count)
            .unwrap()
            .listed(),
    )
    .unwrap();
    assert_eq!(
        context
            .authenticate_response(&intent, misdirected.body(), first_signature, &available)
            .err(),
        Some(CloseError::Context)
    );
    // A response stays pending until every listed envelope is available: the
    // first holder of the omitted ballot without it, or else the first
    // responder without the organizer's ballot.
    let (pending_responder, pending_author) = match scenario.omitted {
        Some(omitted) => (scenario.omitted_holders().start, omitted),
        None => (1, 0),
    };
    let without_pending: Vec<_> = available
        .iter()
        .filter(|value| value.envelope().position() != pending_author)
        .cloned()
        .collect();
    let (body, signature) = split(&responses[pending_responder]);
    assert_eq!(
        context
            .authenticate_response(&intent, body, signature, &without_pending)
            .err(),
        Some(CloseError::Incomplete)
    );
    let mut changed = signature.to_vec();
    changed[1] ^= 1;
    assert_eq!(
        context
            .authenticate_response(&intent, body, &changed, &available)
            .err(),
        Some(CloseError::Signature)
    );
    // An organizer that holds no body cannot answer: it wants a body for each
    // listed usable slot and none for a conflicting slot, whose two known
    // envelopes need no body.
    let arrivals: Vec<&Vec<u8>> = responses[1..].iter().collect();
    let mut hashed = delivery::exercise_body_delivery(
        &poll,
        &setup,
        enrollments,
        &mut works[1],
        delivery::CloseDeliveryInputs {
            intent_packet: &intent_packet,
            arrivals: &arrivals,
            common: &common,
            everything: &everything,
            omitted,
            forged: forged.as_ref(),
        },
    );
    // The organizer lacks the equivocator's on-time envelopes and the omitted
    // ballot. Only the omitted body is wanted, and the first `n - f - 1`
    // other responses are ready without it, so the organizer answers and
    // proposes its own response and those.
    let mut unheld: Vec<&Submission> = Vec::new();
    if let Some(forged) = &forged {
        unheld.extend([&forged.a, &forged.b]);
    }
    unheld.extend(omitted);
    gather(
        &mut works[0],
        &mut enrollments[0].credential,
        count,
        &unheld,
        &arrivals,
    );
    let omitted_wanted: Vec<&Submission> = omitted.into_iter().collect();
    assert_eq!(
        works[0]
            .command(
                &mut enrollments[0].credential,
                CloseOperation::WantedBodies,
                0,
                &[]
            )
            .unwrap(),
        wanted_bytes(&omitted_wanted)
    );
    let (own, proposal) = conclude(&mut works[0], &mut enrollments[0].credential);
    responses[0] = own;
    // Every participant's close log, replayed into a fresh state after the
    // lock retired the late envelope, reproduces its response and the
    // organizer's proposal.
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
    let again = works[0]
        .command(
            &mut enrollments[0].credential,
            CloseOperation::PrepareProposal,
            0,
            &[],
        )
        .unwrap();
    assert!(matches!(
        sign(&mut works[0], &mut enrollments[0].credential, &again),
        Err(Error::Consumed)
    ));
    let listings: Vec<CloseResponseMessage> = responses
        .iter()
        .map(|response| CloseResponseMessage::parse(split(response).0, count).unwrap())
        .collect();
    // Honest listings exclude the late envelope and cap each slot at two. The
    // organizer lists both on-time envelopes of the equivocator without
    // their bodies.
    let equivocated = usize::from(forged.is_some()) * 2;
    for (position, listing) in listings.iter().enumerate() {
        let expected = match position {
            0 => common.len(),
            position => held[position].len(),
        } + if position == 0 || Some(position) == scenario.equivocator {
            equivocated
        } else {
            0
        };
        assert_eq!(listing.listed().len(), expected, "listing {position}");
    }
    if let Some(forged) = &forged {
        let position = scenario.equivocator.unwrap();
        assert!(listings.iter().all(|listing| {
            !listing
                .listed()
                .contains(&(position, forged.late.envelope.identity()))
        }));
        for submission in [&forged.a, &forged.b] {
            assert!(
                listings[0]
                    .listed()
                    .contains(&(position, submission.envelope.identity()))
            );
        }
    }
    let authenticated = authenticate_responses(&context, &intent, &responses, &available);
    let (proposal_body, proposal_signature) = split(&proposal);
    // Only the usable slots' bodies are fetched and hashed; the conflicting
    // envelopes need none.
    let named =
        protocol_foundations::close_signing::CloseProposalMessage::parse(proposal_body, count, 0)
            .unwrap();
    let required = context
        .required_bodies(&intent, &named, &authenticated)
        .unwrap();
    assert_eq!(
        required,
        common
            .iter()
            .map(|submission| (
                submission.envelope.position(),
                submission.envelope.identity()
            ))
            .collect::<Vec<_>>()
    );
    let bodies: Vec<AuthenticatedBallotBody> = common
        .iter()
        .map(|submission| authenticate(&setup, submission, &mut hashed))
        .collect();
    let mut changed = proposal_signature.to_vec();
    changed[2] ^= 1;
    assert_eq!(
        context
            .verify_proposal(
                intent.clone(),
                proposal_body,
                &changed,
                &authenticated,
                &bodies
            )
            .err(),
        Some(CloseError::Signature)
    );
    let without_last: Vec<_> = authenticated
        .iter()
        .filter(|response| response.message().responder() != quorum - 1)
        .cloned()
        .collect();
    assert_eq!(
        context
            .verify_proposal(
                intent.clone(),
                proposal_body,
                proposal_signature,
                &without_last,
                &bodies
            )
            .err(),
        Some(CloseError::Incomplete)
    );
    assert_eq!(
        context
            .verify_proposal(
                intent.clone(),
                proposal_body,
                proposal_signature,
                &authenticated,
                &bodies[..bodies.len() - 1]
            )
            .err(),
        Some(CloseError::Incomplete)
    );
    let barrier = context
        .verify_proposal(
            intent.clone(),
            proposal_body,
            proposal_signature,
            &authenticated,
            &bodies,
        )
        .unwrap();
    let responders: Vec<_> = barrier
        .responses()
        .iter()
        .map(|response| response.message().responder())
        .collect();
    assert_eq!(responders, (0..quorum).collect::<Vec<_>>());
    let usable = scenario.usable();
    for (author, slot) in barrier.slots().iter().enumerate() {
        match slot {
            ClosedSlot::Usable(body) if usable.contains(&author) => assert_eq!(
                body.authentication().envelope().bytes(),
                submissions[author].as_ref().unwrap().envelope.bytes()
            ),
            ClosedSlot::Conflicting(identities) if Some(author) == scenario.equivocator => {
                let forged = forged.as_ref().unwrap();
                let mut expected = vec![forged.a.envelope.identity(), forged.b.envelope.identity()];
                expected.sort();
                assert_eq!(identities, &expected);
            }
            ClosedSlot::Absent
                if !usable.contains(&author) && Some(author) != scenario.equivocator => {}
            _ => panic!("Unexpected close slot {author}"),
        }
    }
    let mut late_fork = None;
    if let Some(equivocation) = equivocation {
        // A restored fork replays its completed response only after
        // relocking its intent, and signs nothing new while its purpose
        // stays locked.
        let Equivocation {
            position,
            late_fork: fork,
            mut restored,
            ..
        } = equivocation;
        let restored_owner = owner_of(&restored, &poll, &setup, position);
        let (response_body, response_signature) = split(&responses[position]);
        let response = CloseResponseMessage::parse(response_body, count).unwrap();
        assert!(matches!(
            restored.restore_close_message(
                &restored_owner,
                roster,
                CloseMessage::Response(&response),
                response_signature
            ),
            Err(Error::Context)
        ));
        restored
            .lock_close_intent(&restored_owner, roster, intent.message(), &intent_signature)
            .unwrap();
        let mut changed = response_signature.to_vec();
        changed[3] ^= 1;
        assert!(
            restored
                .restore_close_message(
                    &restored_owner,
                    roster,
                    CloseMessage::Response(&response),
                    &changed
                )
                .is_err()
        );
        restored
            .restore_close_message(
                &restored_owner,
                roster,
                CloseMessage::Response(&response),
                response_signature,
            )
            .unwrap();
        assert!(matches!(
            restored.restore_close_message(
                &restored_owner,
                roster,
                CloseMessage::Response(&response),
                response_signature
            ),
            Err(Error::Consumed)
        ));
        assert!(matches!(
            restored.sign_close_response(&restored_owner, roster, &response),
            Err(Error::Consumed)
        ));
        late_fork = Some(fork);
    }
    // The restored organizer replays its intent, response and proposal.
    let organizer_owner = owner_of(&organizer_restored, &poll, &setup, 0);
    let proposal_message = barrier.proposal().clone();
    let (own_body, own_signature) = split(&responses[0]);
    let own = CloseResponseMessage::parse(own_body, count).unwrap();
    for (message, signature) in [
        (
            CloseMessage::Intent(intent.message()),
            &intent_signature[..],
        ),
        (CloseMessage::Response(&own), own_signature),
        (
            CloseMessage::Proposal(&proposal_message),
            proposal_signature,
        ),
    ] {
        organizer_restored
            .restore_close_message(&organizer_owner, roster, message, signature)
            .unwrap();
    }
    assert!(matches!(
        organizer_restored.sign_close_proposal(&organizer_owner, roster, &proposal_message),
        Err(Error::Consumed)
    ));
    let directory = output.join("close");
    let late_identity = forged
        .as_ref()
        .map(|forged| forged.late.envelope.identity());
    let listed: Vec<&Submission> = everything
        .iter()
        .copied()
        .filter(|submission| Some(submission.envelope.identity()) != late_identity)
        .collect();
    write_records(
        &directory,
        output,
        &intent_packet,
        responses.iter().enumerate(),
        &proposal,
        &listed,
    );
    if let Some(response) = late_response {
        crate::write(directory.join("late-response.bin"), &response);
    }
    let response_bytes: usize = responses.iter().map(Vec::len).sum();
    crate::write(
        directory.join("measurements.json"),
        format!(
            "{{\"closeTime\":{close_time},\"intentPacketBytes\":{},\"responsePacketBytes\":{response_bytes},\"proposalPacketBytes\":{},\"listedEntries\":{:?},\"bodyHashBytesIncludingControls\":{hashed},\"elapsedMilliseconds\":{}}}\n",
            intent_packet.len(),
            proposal.len(),
            listings.iter().map(|listing| listing.listed().len()).collect::<Vec<_>>(),
            began.elapsed().as_millis()
        )
        .as_bytes(),
    );
    println!(
        "Verified close responses: union, conflicting equivocation, late refusal and bounded honest omission"
    );
    (barrier, late_fork)
}

/// The equivocator's credentials during the close.
struct Equivocation {
    position: usize,
    owner: RetainedBallotOwner,
    late_fork: Credential,
    restored: Credential,
}
/// The equivocator's two on-time envelopes and its late one.
struct Forged {
    a: Submission,
    b: Submission,
    late: Submission,
}
