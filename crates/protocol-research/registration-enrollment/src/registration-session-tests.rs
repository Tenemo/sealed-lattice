//! Registration sessions against the registration verifier on a real
//! registration: the same verified record however the bytes are divided or
//! interleaved, and the verifier's own refusal of changed bytes.
use crate::Enrollment;
use registration_credentials::{
    Error,
    foundation::{
        StabilizedDisplayText,
        ceremony::{Manifest, OptionDefinition},
    },
    poll::{PollDraft, VerifiedPoll, verify_poll},
    registration::{RegistrationVerifier, VerifiedRegistration, session::RegistrationSession},
};

const CHUNK: usize = 1 << 20;

#[derive(Clone)]
struct Record {
    header: Vec<u8>,
    signature: Vec<u8>,
    key: Vec<u8>,
    proof: Vec<u8>,
}

// A poll and its creator's registration.
fn registration() -> (VerifiedPoll, Record) {
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
    let draft = PollDraft::new(Manifest::new(text("Question"), options).unwrap(), 2).unwrap();
    let runtime = [7; 64];
    let mut parts: [Vec<u8>; 4] = Default::default();
    let (packet, _) = Enrollment::create_creator(
        draft,
        runtime,
        b"Creator",
        &[1; 32],
        &[2; 32],
        |kind, offset, bytes| {
            if let Some(part) = parts.get_mut(kind as usize) {
                assert_eq!(offset, part.len());
                part.extend_from_slice(bytes);
            }
        },
    )
    .unwrap();
    let poll = verify_poll(packet.identity, runtime, &packet.body, &packet.signature).unwrap();
    let [key, proof, header, signature] = parts;
    (
        poll,
        Record {
            header,
            signature,
            key,
            proof,
        },
    )
}

fn direct(poll: &VerifiedPoll, record: &Record) -> Result<VerifiedRegistration, Error> {
    let mut verifier = RegistrationVerifier::new(poll, &record.header, &record.signature)?;
    for part in record.key.chunks(CHUNK) {
        verifier.push_key(part)?;
    }
    verifier.finish_key()?;
    for part in record.proof.chunks(CHUNK) {
        verifier.push_proof(part)?;
    }
    verifier.finish()
}

// A session of the record, streamed in parts of the division.
fn streamed(
    poll: &VerifiedPoll,
    record: &Record,
    division: usize,
) -> Result<VerifiedRegistration, Error> {
    let mut session = RegistrationSession::open(poll, 0, &record.header, &record.signature)?;
    for part in record.key.chunks(division) {
        session.push_key(part)?;
    }
    session.finish_key()?;
    for part in record.proof.chunks(division) {
        session.push_proof(part)?;
    }
    session.finish()?.wait()
}

fn same(left: &VerifiedRegistration, right: &VerifiedRegistration) -> bool {
    left.body_digest() == right.body_digest()
        && left.proof_hash() == right.proof_hash()
        && left.public_key() == right.public_key()
        && left.header().encode().unwrap() == right.header().encode().unwrap()
}

#[test]
fn sessions_verify_and_refuse_a_registration_as_its_verifier_does() {
    let (poll, record) = registration();
    let expected = direct(&poll, &record).unwrap();
    for division in [CHUNK, 65_543, 4_099] {
        assert!(same(
            &streamed(&poll, &record, division).unwrap(),
            &expected
        ));
    }
    // Two sessions whose steps interleave keep their own states.
    let mut sessions = [0, 1].map(|shard| {
        RegistrationSession::open(&poll, shard, &record.header, &record.signature).unwrap()
    });
    for part in record.key.chunks(CHUNK) {
        for session in &mut sessions {
            session.push_key(part).unwrap();
        }
    }
    for session in &mut sessions {
        session.finish_key().unwrap();
    }
    for part in record.proof.chunks(333_331) {
        for session in &mut sessions {
            session.push_proof(part).unwrap();
        }
    }
    for session in sessions {
        assert!(same(&session.finish().unwrap().wait().unwrap(), &expected));
    }
    // A changed proof, proof header, key or signature and a short proof are
    // refused with the verifier's refusal.
    let changed = |change: fn(&mut Record)| {
        let mut record = record.clone();
        change(&mut record);
        record
    };
    for record in [
        changed(|record| {
            let middle = record.proof.len() / 2;
            record.proof[middle] ^= 1;
        }),
        changed(|record| record.proof[10] ^= 1),
        changed(|record| {
            record.proof.pop();
        }),
        changed(|record| record.key[5] ^= 1),
        changed(|record| record.signature[0] ^= 1),
    ] {
        let refusal = |result: Result<VerifiedRegistration, Error>| {
            format!("{:?}", result.err().expect("A refusal"))
        };
        assert_eq!(
            refusal(streamed(&poll, &record, 65_543)),
            refusal(direct(&poll, &record))
        );
    }
}
