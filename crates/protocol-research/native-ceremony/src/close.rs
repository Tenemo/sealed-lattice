use ballot_proof::{
    close::{
        AuthenticatedCloseIntent, AuthenticatedCloseResponse, CloseContext, ClosedSlot,
        Error as CloseError, VerifiedCloseBarrier,
    },
    submission::{
        AuthenticatedBallotBody, AuthenticatedBallotEnvelope, BallotBodyAuthentication,
        authenticate_envelope,
    },
};
use registration_credentials::{
    Credential, Error,
    ballot_authentication::{BallotEnvelope, RetainedBallotOwner},
    close_signing::{
        CloseIntentMessage, CloseMessage, ClosePurpose, CloseResponseMessage, close_quorum,
        maximum_close_message_bytes,
    },
    contribution_authentication::SignedOpening,
    foundation::{CanonicalItem, CanonicalTuple},
    poll::VerifiedPoll,
    roster::RetainedContributionContext,
};
use registration_enrollment::{Enrollment, close_work::CloseWork};
use setup_aggregate::verified::VerifiedSetupAggregate;
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

/// One signed submission and its public body file.
#[derive(Clone)]
pub struct Submission {
    pub envelope: BallotEnvelope,
    pub signature: [u8; 3309],
    pub body: PathBuf,
}

pub fn packet(body: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::from((body.len() as u32).to_le_bytes());
    bytes.extend(body);
    bytes.extend(signature);
    bytes
}
fn read_chunks(path: &Path, mut consume: impl FnMut(&[u8])) -> usize {
    let mut file = File::open(path).unwrap();
    let mut buffer = vec![0; 1 << 20];
    let mut total = 0;
    loop {
        let count = file.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        consume(&buffer[..count]);
        total += count;
    }
    total
}
/// The owning envelope authentication, without the body.
pub fn envelope(
    setup: &VerifiedSetupAggregate,
    submission: &Submission,
) -> AuthenticatedBallotEnvelope {
    authenticate_envelope(setup, submission.envelope.bytes(), &submission.signature).unwrap()
}
/// Streams the complete body through the owning envelope and body checks.
pub fn authenticate(
    setup: &VerifiedSetupAggregate,
    submission: &Submission,
    hashed: &mut usize,
) -> AuthenticatedBallotBody {
    let authentication =
        authenticate_envelope(setup, submission.envelope.bytes(), &submission.signature).unwrap();
    let mut body = BallotBodyAuthentication::new(authentication).unwrap();
    *hashed += read_chunks(&submission.body, |bytes| body.push(bytes).unwrap());
    body.finish().unwrap()
}
pub fn owner(
    enrollment: &Enrollment,
    poll: &VerifiedPoll,
    setup: &VerifiedSetupAggregate,
    opening: &SignedOpening,
    position: usize,
) -> RetainedBallotOwner {
    owner_of(&enrollment.credential, poll, setup, opening, position)
}
fn owner_of(
    credential: &Credential,
    poll: &VerifiedPoll,
    setup: &VerifiedSetupAggregate,
    opening: &SignedOpening,
    position: usize,
) -> RetainedBallotOwner {
    let retained = RetainedContributionContext::parse(
        poll.identity(),
        poll.runtime(),
        position,
        setup.inventory().proposal().proposal().body(),
    )
    .unwrap();
    credential
        .retain_ballot_owner(
            poll,
            &retained,
            setup.inventory().identity(),
            opening.body(),
            opening.signature(),
        )
        .unwrap()
}
pub fn close_work(
    enrollment: &Enrollment,
    poll: &Arc<VerifiedPoll>,
    setup: &Arc<VerifiedSetupAggregate>,
    opening: &SignedOpening,
    position: usize,
) -> CloseWork {
    CloseWork::new(
        owner(enrollment, poll, setup, opening, position),
        poll.clone(),
        setup.clone(),
    )
    .unwrap()
}
/// Delivers one held submission and its complete body to a close work.
pub fn deliver(
    work: &mut CloseWork,
    credential: &mut Credential,
    submission: &Submission,
    hashed: &mut usize,
) {
    work.command(credential, 3, 0, &control(submission))
        .unwrap();
    *hashed += read_chunks(&submission.body, |bytes| {
        work.command(credential, 4, 0, bytes).unwrap();
    });
    work.command(credential, 5, 0, &[]).unwrap();
}
/// Signs the prepared body after the root would have committed it and coins.
pub fn sign(
    work: &mut CloseWork,
    credential: &mut Credential,
    body: &[u8],
) -> Result<Vec<u8>, Error> {
    let input = [body, crate::random::<32>().as_slice()].concat();
    work.command(credential, 8, 0, &input)
}
pub fn now_milliseconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
/// The organizer signs its intent; every participant authenticates and locks it.
pub fn open(
    works: &mut [CloseWork],
    enrollments: &mut [Enrollment],
    close_time: u64,
) -> (Vec<u8>, Vec<u8>) {
    let body = works[0]
        .command(
            &mut enrollments[0].credential,
            1,
            0,
            &close_time.to_le_bytes(),
        )
        .unwrap();
    let signature = sign(&mut works[0], &mut enrollments[0].credential, &body).unwrap();
    let intent = packet(&body, &signature);
    for (work, enrollment) in works.iter_mut().zip(enrollments.iter_mut()) {
        work.command(&mut enrollment.credential, 2, 0, &intent)
            .unwrap();
    }
    (body, signature)
}
/// A participant's response from its held submissions.
pub fn respond(
    work: &mut CloseWork,
    credential: &mut Credential,
    held: &[&Submission],
    hashed: &mut usize,
) -> Vec<u8> {
    for submission in held {
        deliver(work, credential, submission, hashed);
    }
    let body = work.command(credential, 6, 0, &[]).unwrap();
    let signature = sign(work, credential, &body).unwrap();
    // One response per participant.
    let again = work.command(credential, 6, 0, &[]).unwrap();
    assert!(matches!(
        sign(work, credential, &again),
        Err(Error::Consumed)
    ));
    packet(&body, &signature)
}
fn split(packet: &[u8]) -> (&[u8], &[u8]) {
    let length = u32::from_le_bytes(packet[..4].try_into().unwrap()) as usize;
    (&packet[4..4 + length], &packet[4 + length..])
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
fn control(submission: &Submission) -> Vec<u8> {
    [
        submission.envelope.bytes().as_slice(),
        &submission.signature,
    ]
    .concat()
}
/// Delivers every other response in arrival order after the listed envelopes
/// the organizer lacks, without their bodies.
fn gather(
    work: &mut CloseWork,
    credential: &mut Credential,
    listed: &[&Submission],
    arrivals: &[&Vec<u8>],
) {
    for submission in listed {
        work.command(credential, 12, 0, &control(submission))
            .unwrap();
    }
    for response in arrivals {
        work.command(credential, 7, 0, response).unwrap();
    }
}
/// The organizer's own response, once `q-1` other responses are ready, and
/// its proposal. It needs only the bodies of usable slots, which it holds.
fn conclude(work: &mut CloseWork, credential: &mut Credential) -> (Vec<u8>, Vec<u8>) {
    let body = work.command(credential, 6, 0, &[]).unwrap();
    let signature = sign(work, credential, &body).unwrap();
    let own = packet(&body, &signature);
    // One response per participant.
    let again = work.command(credential, 6, 0, &[]).unwrap();
    assert!(matches!(
        sign(work, credential, &again),
        Err(Error::Consumed)
    ));
    work.command(credential, 7, 0, &own).unwrap();
    let body = work.command(credential, 9, 0, &[]).unwrap();
    let signature = sign(work, credential, &body).unwrap();
    (own, packet(&body, &signature))
}
/// The organizer authenticates the other responses and then signs its own
/// response and the proposal.
pub fn organize(
    work: &mut CloseWork,
    credential: &mut Credential,
    listed: &[&Submission],
    arrivals: &[&Vec<u8>],
) -> (Vec<u8>, Vec<u8>) {
    gather(work, credential, listed, arrivals);
    conclude(work, credential)
}
/// Writes the public close records and the index of every listed submission.
pub fn write_records(
    directory: &Path,
    output: &Path,
    intent: &[u8],
    responses: &[Vec<u8>],
    proposal: &[u8],
    listed: &[&Submission],
) {
    std::fs::create_dir(directory).unwrap();
    crate::write(directory.join("intent.bin"), intent);
    for (position, response) in responses.iter().enumerate() {
        crate::write(directory.join(format!("response-{position}.bin")), response);
    }
    crate::write(directory.join("proposal.bin"), proposal);
    let mut index = String::new();
    for (ordinal, submission) in listed.iter().enumerate() {
        let name = format!("submission-{ordinal}.bin");
        crate::write(
            directory.join(&name),
            &[
                submission.envelope.bytes().as_slice(),
                &submission.signature,
            ]
            .concat(),
        );
        let body = submission.body.strip_prefix(output).unwrap();
        index.push_str(&format!(
            "{name} {}\n",
            body.to_str().unwrap().replace('\\', "/")
        ));
    }
    crate::write(directory.join("submissions.txt"), index.as_bytes());
}

/// Credentials restored from sealed capsules. Participant three belongs to the
/// fixed corrupt set {1, 2, 3}; forking its own signing state models permitted
/// corruption, not honest recovery. The organizer's restored credential stays
/// locked and only replays its completed messages.
pub struct Restored {
    pub equivocations: [Credential; 3],
    pub corrupt: Credential,
    pub organizer: Credential,
}

/// The result case. The organizer proposes responses 0 to 6. Corrupt
/// participant 3 equivocates into a conflicting slot and signs a late
/// envelope. The organizer holds only the late one, which its intent lock
/// discards, and lists both on-time envelopes from other responses without
/// their bodies. The relay delivers honest voter 9's ballot only to 7, 8 and
/// itself, so it is omitted within the bound of `f`. Returns the barrier and
/// the late fork.
pub fn run(
    output: &Path,
    poll: Arc<VerifiedPoll>,
    setup: Arc<VerifiedSetupAggregate>,
    enrollments: &mut [Enrollment],
    openings: &[SignedOpening],
    submissions: &[Option<Submission>],
    restored: Restored,
) -> (VerifiedCloseBarrier, Credential) {
    let began = Instant::now();
    let count = enrollments.len();
    assert_eq!(count, 10);
    let context = CloseContext::new(poll.clone(), setup.clone()).unwrap();
    let roster = setup.inventory().proposal();
    let mut hashed = 0;
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
    // Corrupt participant 3 signs two on-time envelopes over one body, then
    // a late one, each from its own fork.
    let Restored {
        equivocations: [mut first, mut second, mut late_fork],
        corrupt: mut restored,
        organizer: mut organizer_restored,
    } = restored;
    let base = submissions[0].as_ref().unwrap();
    let corrupt_owner = owner_of(&first, &poll, &setup, &openings[3], 3);
    let equivocate = |fork: &mut Credential, time: u64| {
        let envelope = BallotEnvelope::new(
            poll.identity(),
            setup.inventory().identity(),
            3,
            time,
            base.envelope.body_length(),
            *base.envelope.body_identity(),
        )
        .unwrap();
        let signature = fork
            .sign_retained_ballot_envelope(&corrupt_owner, &envelope, *crate::random::<32>())
            .unwrap();
        Submission {
            envelope,
            signature,
            body: base.body.clone(),
        }
    };
    let equivocation_a = equivocate(&mut first, now_milliseconds());
    let equivocation_b = equivocate(&mut second, now_milliseconds() + 1);
    assert_ne!(
        equivocation_a.envelope.identity(),
        equivocation_b.envelope.identity()
    );
    let close_time = now_milliseconds() + 2;
    // The late envelope reaches the organizer and participant 4 before the
    // intent; their locks discard its body and refuse it afterwards.
    let late = equivocate(&mut late_fork, close_time + 1);
    for position in [0, 4] {
        deliver(
            &mut works[position],
            &mut enrollments[position].credential,
            &late,
            &mut hashed,
        );
    }
    // A slot holds at most two bodies: a third is refused before transfer.
    for submission in [&equivocation_a, &equivocation_b] {
        deliver(
            &mut works[3],
            &mut enrollments[3].credential,
            submission,
            &mut hashed,
        );
    }
    assert!(matches!(
        works[3].command(&mut enrollments[3].credential, 3, 0, &control(&late)),
        Err(Error::Consumed)
    ));
    // Only the organizer closes, and only once.
    let mut other = close_work(&enrollments[1], &poll, &setup, &openings[1], 1);
    let body = other
        .command(
            &mut enrollments[1].credential,
            1,
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
    let mut repeated = close_work(&enrollments[0], &poll, &setup, &openings[0], 0);
    let later = repeated
        .command(
            &mut enrollments[0].credential,
            1,
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
    let mut refused = close_work(&enrollments[4], &poll, &setup, &openings[4], 4);
    assert!(
        refused
            .command(
                &mut enrollments[4].credential,
                2,
                0,
                &packet(unsigned.body(), &intent_signature)
            )
            .is_err()
    );
    // No attempt starts after the close intent, by either signing path.
    let owner8 = owner(&enrollments[8], &poll, &setup, &openings[8], 8);
    assert!(matches!(
        enrollments[8].credential.reserve_ballot_attempt(&owner8),
        Err(Error::Consumed)
    ));
    let nonvoter = BallotEnvelope::new(
        poll.identity(),
        setup.inventory().identity(),
        8,
        close_time - 1,
        base.envelope.body_length(),
        *base.envelope.body_identity(),
    )
    .unwrap();
    assert!(matches!(
        enrollments[8]
            .credential
            .sign_ballot_envelope(roster, &nonvoter, *crate::random::<32>()),
        Err(Error::Consumed)
    ));
    for position in [0, 4] {
        assert!(matches!(
            works[position].command(&mut enrollments[position].credential, 3, 0, &control(&late)),
            Err(Error::Context)
        ));
    }
    // The relay's schedule. Everyone holds the ballots of 0, 1, 2 and 4 to 7;
    // 3's first envelope reaches 1 to 5, its second 3, 6, 7 and 8; honest
    // voter 9's ballot reaches only 7, 8 and itself.
    let common: Vec<&Submission> = [0, 1, 2, 4, 5, 6, 7]
        .iter()
        .map(|author| submissions[*author].as_ref().unwrap())
        .collect();
    let omitted = submissions[9].as_ref().unwrap();
    let mut held: Vec<Vec<&Submission>> = vec![common.clone(); count];
    // Participant 3 already holds both of its on-time envelopes.
    for position in [1, 2, 4, 5] {
        held[position].push(&equivocation_a);
    }
    for position in [6, 7, 8] {
        held[position].push(&equivocation_b);
    }
    for position in [7, 8, 9] {
        held[position].push(omitted);
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
        works[0].command(&mut enrollments[0].credential, 6, 0, &[]),
        Err(Error::Context)
    ));
    // A voter's response must list its own on-time ballot.
    let mut incomplete = close_work(&enrollments[9], &poll, &setup, &openings[9], 9);
    incomplete
        .command(&mut enrollments[9].credential, 2, 0, &intent_packet)
        .unwrap();
    for submission in &common {
        deliver(
            &mut incomplete,
            &mut enrollments[9].credential,
            submission,
            &mut hashed,
        );
    }
    let body = incomplete
        .command(&mut enrollments[9].credential, 6, 0, &[])
        .unwrap();
    assert!(matches!(
        sign(&mut incomplete, &mut enrollments[9].credential, &body),
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
    // A corrupt fork may sign a response that lists its late envelope; no
    // verifier authenticates it.
    let everything: Vec<&Submission> = common
        .iter()
        .copied()
        .chain([&equivocation_a, &equivocation_b, &late, omitted])
        .collect();
    let available: Vec<AuthenticatedBallotEnvelope> = everything
        .iter()
        .map(|submission| envelope(&setup, submission))
        .collect();
    late_fork
        .unlock_unused_purposes(registration_credentials::SigningPurpose::CloseResponse.mask())
        .unwrap();
    late_fork
        .lock_close_intent(&corrupt_owner, roster, intent.message(), &intent_signature)
        .unwrap();
    let late_listing = CloseResponseMessage::new(
        poll.identity(),
        setup.inventory().identity(),
        *intent.message().identity(),
        3,
        count,
        &[(3, late.envelope.identity())],
    )
    .unwrap();
    let late_signature = late_fork
        .sign_close_response(
            &corrupt_owner,
            roster,
            &late_listing,
            *crate::random::<32>(),
        )
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
                7,
                0,
                &packet(late_listing.body(), &late_signature)
            )
            .is_err()
    );
    // Three envelopes for one slot are refused before any signature check, as
    // is a response naming another intent.
    let mut entries = Vec::new();
    for submission in [&equivocation_a, &equivocation_b, &late] {
        entries.push((3u16, submission.envelope.identity()));
    }
    entries.sort();
    let three = CanonicalTuple::new(
        1,
        1,
        vec![
            CanonicalItem::nonempty_ascii("sealed-lattice/close-response/v1").unwrap(),
            CanonicalItem::hash512(poll.identity()),
            CanonicalItem::hash512(setup.inventory().identity()),
            CanonicalItem::hash512(*intent.message().identity()),
            CanonicalItem::unsigned16(3),
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
    let other_intent =
        CloseIntentMessage::new(poll.identity(), setup.inventory().identity(), 7).unwrap();
    let misdirected = CloseResponseMessage::new(
        poll.identity(),
        setup.inventory().identity(),
        *other_intent.identity(),
        5,
        count,
        CloseResponseMessage::parse(split(&responses[5]).0, count)
            .unwrap()
            .listed(),
    )
    .unwrap();
    assert_eq!(
        context
            .authenticate_response(&intent, misdirected.body(), &late_signature, &available)
            .err(),
        Some(CloseError::Context)
    );
    // A response stays pending until every listed envelope is available.
    let without_omitted: Vec<_> = available
        .iter()
        .filter(|value| value.envelope().position() != 9)
        .cloned()
        .collect();
    let (body, signature) = split(&responses[7]);
    assert_eq!(
        context
            .authenticate_response(&intent, body, signature, &without_omitted)
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
    // An organizer that holds no body cannot answer: every response lists a
    // slot whose one known envelope it lacks. It wants one body for each such
    // slot and none for slot 3, whose two known envelopes need no body.
    let wanted_bytes = |submissions: &[&Submission]| -> Vec<u8> {
        submissions
            .iter()
            .flat_map(|submission| {
                (submission.envelope.position() as u16)
                    .to_le_bytes()
                    .into_iter()
                    .chain(submission.envelope.identity())
            })
            .collect()
    };
    let arrivals: Vec<&Vec<u8>> = responses[1..].iter().collect();
    let mut lacking = close_work(&enrollments[0], &poll, &setup, &openings[0], 0);
    lacking
        .command(&mut enrollments[0].credential, 2, 0, &intent_packet)
        .unwrap();
    gather(
        &mut lacking,
        &mut enrollments[0].credential,
        &everything,
        &arrivals,
    );
    let mut all_wanted = common.clone();
    all_wanted.push(omitted);
    assert_eq!(
        lacking
            .command(&mut enrollments[0].credential, 13, 0, &[])
            .unwrap(),
        wanted_bytes(&all_wanted)
    );
    for operation in [6, 9] {
        assert!(matches!(
            lacking.command(&mut enrollments[0].credential, operation, 0, &[]),
            Err(Error::Context)
        ));
    }
    // The organizer lacks both of 3's on-time envelopes and voter 9's ballot.
    // Only 9's body is wanted, and six other responses are ready without it,
    // so the organizer answers and proposes its own response and the first
    // six others.
    gather(
        &mut works[0],
        &mut enrollments[0].credential,
        &[&equivocation_a, &equivocation_b, omitted],
        &arrivals,
    );
    assert_eq!(
        works[0]
            .command(&mut enrollments[0].credential, 13, 0, &[])
            .unwrap(),
        wanted_bytes(&[omitted])
    );
    let (own, proposal) = conclude(&mut works[0], &mut enrollments[0].credential);
    responses[0] = own;
    let again = works[0]
        .command(&mut enrollments[0].credential, 9, 0, &[])
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
    // organizer lists both of 3's on-time envelopes without their bodies.
    assert!(
        listings
            .iter()
            .all(|listing| !listing.listed().contains(&(3, late.envelope.identity())))
    );
    assert_eq!(listings[4].listed().len(), common.len() + 1);
    assert_eq!(listings[3].listed().len(), common.len() + 2);
    assert_eq!(listings[9].listed().len(), common.len() + 1);
    assert_eq!(listings[0].listed().len(), common.len() + 2);
    for submission in [&equivocation_a, &equivocation_b] {
        assert!(
            listings[0]
                .listed()
                .contains(&(3, submission.envelope.identity()))
        );
    }
    let authenticated = authenticate_responses(&context, &intent, &responses, &available);
    let (proposal_body, proposal_signature) = split(&proposal);
    // Only the usable slots' bodies are fetched and hashed; the conflicting
    // envelopes of slot 3 need none.
    let named = registration_credentials::close_signing::CloseProposalMessage::parse(
        proposal_body,
        count,
        0,
    )
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
    let without_six: Vec<_> = authenticated
        .iter()
        .filter(|response| response.message().responder() != 6)
        .cloned()
        .collect();
    assert_eq!(
        context
            .verify_proposal(
                intent.clone(),
                proposal_body,
                proposal_signature,
                &without_six,
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
    assert_eq!(responders, (0..close_quorum(count)).collect::<Vec<_>>());
    for (author, slot) in barrier.slots().iter().enumerate() {
        match (author, slot) {
            (0 | 1 | 2 | 4 | 5 | 6 | 7, ClosedSlot::Usable(body)) => assert_eq!(
                body.authentication().envelope().bytes(),
                submissions[author].as_ref().unwrap().envelope.bytes()
            ),
            (3, ClosedSlot::Conflicting(identities)) => {
                let mut expected = vec![
                    equivocation_a.envelope.identity(),
                    equivocation_b.envelope.identity(),
                ];
                expected.sort();
                assert_eq!(identities, &expected);
            }
            (8 | 9, ClosedSlot::Absent) => {}
            _ => panic!("Unexpected close slot {author}"),
        }
    }
    // A restored fork replays its completed response only after relocking
    // its intent, and signs nothing new while its purpose stays locked.
    let restored_owner = owner_of(&restored, &poll, &setup, &openings[3], 3);
    let (response_body, response_signature) = split(&responses[3]);
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
        restored.sign_close_response(&restored_owner, roster, &response, *crate::random::<32>()),
        Err(Error::Consumed)
    ));
    // The restored organizer replays its intent, response and proposal.
    let organizer_owner = owner_of(&organizer_restored, &poll, &setup, &openings[0], 0);
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
        organizer_restored.sign_close_proposal(
            &organizer_owner,
            roster,
            &proposal_message,
            *crate::random::<32>()
        ),
        Err(Error::Consumed)
    ));
    let directory = output.join("close");
    let listed: Vec<&Submission> = everything
        .iter()
        .copied()
        .filter(|submission| submission.envelope.identity() != late.envelope.identity())
        .collect();
    write_records(
        &directory,
        output,
        &intent_packet,
        &responses,
        &proposal,
        &listed,
    );
    crate::write(
        directory.join("late-response.bin"),
        &packet(late_listing.body(), &late_signature),
    );
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
