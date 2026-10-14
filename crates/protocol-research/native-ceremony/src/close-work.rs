use ballot_proof::submission::AuthenticatedBallotEnvelope;
use evaluation_target::close::{
    AuthenticatedCloseIntent, AuthenticatedCloseResponse, CloseContext,
};
use participant_module::{
    Enrollment,
    close_work::{CloseOperation, CloseWork},
};
use protocol_foundations::{
    Credential, Error, RETAINED_TAG_BYTES, ballot_authentication::RetainedSetupOwner,
    close_signing::CloseResponseMessage, poll::VerifiedPoll, roster::RetainedContributionContext,
};
use setup_aggregate::verified::VerifiedSetupAggregate;
use std::{
    ops::{Deref, DerefMut},
    sync::Arc,
};

use super::records::{Submission, control, read_chunks, split};
use protocol_foundations::signed_packet;

/// An input a participant's close state accepted, as its persistent close log
/// retains it: a held submission, the locked intent, or a response the
/// organizer took with the envelopes delivered with it.
enum Event {
    Held(Box<Submission>),
    Lock(Vec<u8>),
    Response(Vec<u8>),
}

/// A participant's close state and the ordered log of its accepted inputs.
/// The lock retires the logged submissions timed after the close time, as
/// the state does.
pub struct LoggedWork {
    work: CloseWork,
    events: Vec<Event>,
}

impl Deref for LoggedWork {
    type Target = CloseWork;
    fn deref(&self) -> &CloseWork {
        &self.work
    }
}

impl DerefMut for LoggedWork {
    fn deref_mut(&mut self) -> &mut CloseWork {
        &mut self.work
    }
}

/// Every original participant's owner comes from its credential-authenticated
/// reference to the certified selected setup.
pub fn owner_of(
    credential: &Credential,
    poll: &VerifiedPoll,
    setup: &VerifiedSetupAggregate,
    position: usize,
) -> RetainedSetupOwner {
    let retained = RetainedContributionContext::parse(
        credential,
        &setup.roster().proposal().records()[position],
        poll,
        position,
        setup.roster().proposal().body(),
    )
    .unwrap();
    let reference =
        participant_module::ballot::retained_setup_reference(credential, poll, setup).unwrap();
    let (reference, tag) = reference.split_at(reference.len() - RETAINED_TAG_BYTES);
    credential
        .retain_setup_owner(poll, &retained, setup.identity(), reference, tag)
        .unwrap()
}

pub fn close_work(
    enrollment: &Enrollment,
    poll: &Arc<VerifiedPoll>,
    setup: &Arc<VerifiedSetupAggregate>,
    position: usize,
) -> LoggedWork {
    LoggedWork {
        work: CloseWork::new(
            owner_of(&enrollment.credential, poll, setup, position),
            poll.clone(),
            setup.clone(),
        )
        .unwrap(),
        events: Vec::new(),
    }
}

/// Delivers one held submission and its complete body to a close work.
pub fn deliver(
    work: &mut LoggedWork,
    credential: &mut Credential,
    submission: &Submission,
    hashed: &mut usize,
) {
    work.command(
        credential,
        CloseOperation::BeginHeldBody,
        0,
        &control(submission),
    )
    .unwrap();
    *hashed += read_chunks(&submission.body, |bytes| {
        work.command(credential, CloseOperation::PushHeldBody, 0, bytes)
            .unwrap();
    });
    work.command(credential, CloseOperation::FinishHeldBody, 0, &[])
        .unwrap();
    work.events.push(Event::Held(Box::new(submission.clone())));
}

/// Replays a participant's close log into a fresh state, which must accept
/// every event and prepare the same response. As in the organizer's close,
/// its credential then refuses to sign that response again, which consumes
/// the prepared body, and the fresh state takes the completed response and
/// must prepare the same proposal.
pub fn replay(
    logged: &LoggedWork,
    mut fresh: LoggedWork,
    credential: &mut Credential,
    response: &[u8],
    proposal: Option<&[u8]>,
) {
    let mut hashed = 0;
    for event in &logged.events {
        match event {
            Event::Held(submission) => deliver(&mut fresh, credential, submission, &mut hashed),
            Event::Lock(intent) => {
                fresh
                    .command(credential, CloseOperation::LockIntent, 0, intent)
                    .unwrap();
            }
            Event::Response(input) => {
                fresh
                    .command(credential, CloseOperation::AdmitResponse, 0, input)
                    .unwrap();
            }
        }
    }
    let body = fresh
        .command(credential, CloseOperation::PrepareResponse, 0, &[])
        .unwrap();
    assert_eq!(body, split(response).0);
    if let Some(proposal) = proposal {
        assert!(matches!(
            sign(&mut fresh, credential, &body),
            Err(Error::Consumed)
        ));
        fresh
            .command(credential, CloseOperation::AdmitResponse, 0, response)
            .unwrap();
        assert_eq!(
            fresh
                .command(credential, CloseOperation::PrepareProposal, 0, &[])
                .unwrap(),
            split(proposal).0
        );
    }
}

/// Signs the prepared body after the root would have committed it.
pub fn sign(
    work: &mut CloseWork,
    credential: &mut Credential,
    body: &[u8],
) -> Result<Vec<u8>, Error> {
    work.command(credential, CloseOperation::Sign, 0, body)
}

pub fn now_milliseconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// The organizer signs its intent; every participant authenticates and locks it.
pub fn open(
    works: &mut [LoggedWork],
    enrollments: &mut crate::OriginalEnrollments,
    close_time: u64,
) -> (Vec<u8>, Vec<u8>) {
    let body = works[0]
        .command(
            &mut enrollments[0].credential,
            CloseOperation::PrepareIntent,
            0,
            &close_time.to_le_bytes(),
        )
        .unwrap();
    let signature = sign(&mut works[0], &mut enrollments[0].credential, &body).unwrap();
    let intent = signed_packet::encode(&body, &signature);
    for (work, enrollment) in works
        .iter_mut()
        .zip(enrollments.iter_mut().map(|(_, enrollment)| enrollment))
    {
        work.command(
            &mut enrollment.credential,
            CloseOperation::LockIntent,
            0,
            &intent,
        )
        .unwrap();
        work.events.retain(|event| match event {
            Event::Held(submission) => submission.envelope.ballot_time() <= close_time,
            _ => true,
        });
        work.events.push(Event::Lock(intent.clone()));
    }
    (body, signature)
}

/// A participant's response from its held submissions.
pub fn respond(
    work: &mut LoggedWork,
    credential: &mut Credential,
    held: &[&Submission],
    hashed: &mut usize,
) -> Vec<u8> {
    for submission in held {
        deliver(work, credential, submission, hashed);
    }
    let body = work
        .command(credential, CloseOperation::PrepareResponse, 0, &[])
        .unwrap();
    let signature = sign(work, credential, &body).unwrap();
    // One response per participant.
    let again = work
        .command(credential, CloseOperation::PrepareResponse, 0, &[])
        .unwrap();
    assert!(matches!(
        sign(work, credential, &again),
        Err(Error::Consumed)
    ));
    signed_packet::encode(&body, &signature)
}

pub fn authenticate_responses(
    context: &CloseContext,
    intent: &AuthenticatedCloseIntent,
    responses: &[Vec<u8>],
    available: &[AuthenticatedBallotEnvelope],
) -> Vec<AuthenticatedCloseResponse> {
    responses
        .iter()
        .map(|packet| {
            let (body, signature) = split(packet);
            context
                .authenticate_response(intent, body, signature, available)
                .unwrap()
        })
        .collect()
}

/// Delivers every other response in arrival order, each with the envelopes it
/// lists from those the organizer lacks and has not yet been given, without
/// their bodies.
pub(super) fn gather(
    work: &mut LoggedWork,
    credential: &mut Credential,
    participants: usize,
    lacked: &[&Submission],
    arrivals: &[&Vec<u8>],
) {
    let mut given = Vec::new();
    for response in arrivals {
        let listing = CloseResponseMessage::parse(split(response).0, participants).unwrap();
        let mut input = response.to_vec();
        for submission in lacked {
            let identity = submission.envelope.identity();
            if !given.contains(&identity)
                && listing.listed().iter().any(|(_, value)| *value == identity)
            {
                given.push(identity);
                input.extend(control(submission));
            }
        }
        work.command(credential, CloseOperation::AdmitResponse, 0, &input)
            .unwrap();
        work.events.push(Event::Response(input));
    }
}

/// The organizer's own response, once `q-1` other responses are ready, and
/// its proposal. It needs only the bodies of usable slots, which it holds.
pub(super) fn conclude(work: &mut CloseWork, credential: &mut Credential) -> (Vec<u8>, Vec<u8>) {
    let body = work
        .command(credential, CloseOperation::PrepareResponse, 0, &[])
        .unwrap();
    let signature = sign(work, credential, &body).unwrap();
    let own = signed_packet::encode(&body, &signature);
    // One response per participant.
    let again = work
        .command(credential, CloseOperation::PrepareResponse, 0, &[])
        .unwrap();
    assert!(matches!(
        sign(work, credential, &again),
        Err(Error::Consumed)
    ));
    work.command(credential, CloseOperation::AdmitResponse, 0, &own)
        .unwrap();
    let body = work
        .command(credential, CloseOperation::PrepareProposal, 0, &[])
        .unwrap();
    let signature = sign(work, credential, &body).unwrap();
    (own, signed_packet::encode(&body, &signature))
}

/// The organizer, which knows every listed envelope, authenticates the other
/// responses and then signs its own response and the proposal.
pub fn organize(
    work: &mut LoggedWork,
    credential: &mut Credential,
    participants: usize,
    arrivals: &[&Vec<u8>],
) -> (Vec<u8>, Vec<u8>) {
    gather(work, credential, participants, &[], arrivals);
    conclude(work, credential)
}
