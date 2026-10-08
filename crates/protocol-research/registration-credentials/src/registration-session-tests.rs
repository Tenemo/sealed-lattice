use super::*;
use crate::{
    Credential,
    foundation::{
        StabilizedDisplayText,
        manifest::{Manifest, OptionDefinition},
        normalize_username,
    },
    poll::{PollDraft, SignedPoll, verify_poll},
};

// The sessions open where the job runs.
static SESSION_COUNT: Job = Job {
    kind: 0x06ff,
    run: session_count,
};
fn session_count(_: &[u8]) -> Vec<u8> {
    SESSIONS.with(|sessions| (sessions.borrow().len() as u32).to_le_bytes().to_vec())
}
// The sessions open where each helper, or without helpers this thread,
// runs its jobs, after the jobs submitted before.
fn open_sessions() -> usize {
    (0..parallel_work::helpers().max(1))
        .map(|helper| {
            let output = submit(&SESSION_COUNT, Some(helper), &[], 4).wait();
            u32::from_le_bytes(output[..].try_into().unwrap()) as usize
        })
        .sum()
}

/// A signed poll and the header of a registration of it with the runtime,
/// whose key nothing produced.
pub(crate) fn keyless_record(runtime: [u8; 64]) -> (SignedPoll, Vec<u8>) {
    let text = |value: &str| StabilizedDisplayText::from_ingress_utf8(value.as_bytes()).unwrap();
    let options = (0..2)
        .map(|index| {
            OptionDefinition::new(
                index,
                format!("option-{index}"),
                text(&format!("Option {index}")),
            )
            .unwrap()
        })
        .collect();
    let draft = PollDraft::new(Manifest::new(text("Question"), options).unwrap(), 2, 3).unwrap();
    let mut organizer = Credential::from_seed([1; 32]);
    let packet = organizer.create_poll(draft, [4; 64], [5; 32]).unwrap();
    let header = RegistrationHeader {
        username: normalize_username(b"Participant").unwrap(),
        poll: packet.identity,
        runtime,
        signing_public: *organizer.signing_public(),
        recipient_key_hash: [0; 64],

        fhe_key_commitments: vec![[7; 64]],
    }
    .encode()
    .unwrap();
    (packet, header)
}

// A header of another runtime or with extra bytes is refused before any
// session opens. A dropped session and a finished one leave no state,
// and a key that does not match its header's hash refuses the session
// when it finishes, with the verifier's refusal.
#[test]
fn sessions_refuse_as_the_verifier_does_and_leave_no_state() {
    let (packet, header) = keyless_record([4; 64]);
    let poll = verify_poll(packet.identity, [4; 64], &packet.body, &packet.signature).unwrap();
    let signature = [0; SIGNATURE_BYTES];
    let (_, foreign) = keyless_record([9; 64]);
    assert!(matches!(
        RegistrationSession::open(&poll, 0, &foreign, &signature),
        Err(Error::Context)
    ));
    let extended = [header.as_slice(), &[0]].concat();
    assert!(matches!(
        RegistrationSession::open(&poll, 0, &extended, &signature),
        Err(Error::Shape)
    ));
    assert!(matches!(
        RegistrationSession::open(&poll, 0, &header, &signature[1..]),
        Err(Error::Shape)
    ));
    let mut session = RegistrationSession::open(&poll, 0, &header, &signature).unwrap();
    assert!(matches!(
        session.push_key(&vec![0; CHUNK_LIMIT + 1]),
        Err(Error::Shape)
    ));
    assert!(matches!(session.finish(), Err(Error::Consumed)));
    let mut session = RegistrationSession::open(&poll, 0, &header, &signature).unwrap();
    for part in vec![0; KEY_BYTES].chunks(CHUNK_LIMIT) {
        session.push_key(part).unwrap();
    }
    assert!(matches!(session.push_key(&[0]), Err(Error::Shape)));
    drop(session);
    let mut session = RegistrationSession::open(&poll, 0, &header, &signature).unwrap();
    for part in vec![0; KEY_BYTES].chunks(CHUNK_LIMIT) {
        session.push_key(part).unwrap();
    }
    session.finish_key().unwrap();
    assert!(matches!(session.finish_key(), Err(Error::Shape)));
    drop(session);
    let mut session = RegistrationSession::open(&poll, 0, &header, &signature).unwrap();
    for part in vec![0; KEY_BYTES].chunks(CHUNK_LIMIT) {
        session.push_key(part).unwrap();
    }
    session.finish_key().unwrap();
    let pending = session.finish().unwrap();
    assert_eq!(open_sessions(), 0);
    assert!(matches!(pending.wait(), Err(Error::Shape)));
}
