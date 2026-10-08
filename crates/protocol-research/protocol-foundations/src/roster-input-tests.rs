use super::*;
use crate::registration::CHUNK_LIMIT;
use crate::registration::{KEY_BYTES, session::tests::keyless_record};
use crate::{
    BodyDigest, Credential,
    foundation::{
        RegistrationHeader, StabilizedDisplayText,
        manifest::{Manifest, OptionDefinition},
        normalize_username,
    },
    poll::{PollDraft, SignedPoll},
    registration::RegistrationVerifier,
};
use parallel_work::ProtocolHash;

// One record is open for each helper, or one without helpers. Each
// candidate opens once, every step names an open record, and no failed
// proof becomes a positive record or poisons other positions.
#[test]
fn records_open_within_the_limit_and_the_roster_waits_for_every_verdict() {
    let (packet, header) = keyless_record([4; 64]);
    let input = [
        packet.identity.as_slice(),
        &[4; 64],
        &3u16.to_le_bytes(),
        &(packet.body.len() as u32).to_le_bytes(),
        &packet.body,
        &packet.signature,
    ]
    .concat();
    // The poll admits at most three participants, so a roster of four
    // is refused before any record opens.
    let above = [&input[..128], &4u16.to_le_bytes(), &input[130..]].concat();
    assert!(matches!(
        RosterInputVerifier::new(&above),
        Err(Error::Context)
    ));
    let mut roster = RosterInputVerifier::new(&input).unwrap();
    let record = |position: u16| {
        [
            position.to_le_bytes().as_slice(),
            &[11; 64],
            &(header.len() as u32).to_le_bytes(),
            &header,
            &[0; SIGNATURE_BYTES],
        ]
        .concat()
    };
    let key = vec![0; KEY_BYTES];
    roster.begin_record(&record(0)).unwrap();
    assert!(matches!(roster.push_key(1, &key[..1]), Err(Error::Shape)));
    assert!(matches!(roster.finish(), Err(Error::Shape)));
    let opened = open_record_limit().min(3) as u16;
    for position in 1..opened {
        roster.begin_record(&record(position)).unwrap();
    }
    if opened < 3 {
        assert!(matches!(
            roster.begin_record(&record(opened)),
            Err(Error::Shape)
        ));
    }
    for position in 0..3 {
        if position >= opened {
            roster.begin_record(&record(position)).unwrap();
        }
        for part in key.chunks(CHUNK_LIMIT) {
            roster.push_key(position.into(), part).unwrap();
        }
        roster.finish_key(position.into()).unwrap();
        assert!(roster.finish_record(position.into()).is_err());
        assert!(matches!(
            roster.begin_record(&record(position)),
            Err(Error::Shape)
        ));
        assert!(matches!(
            roster.finish_record(position.into()),
            Err(Error::Shape)
        ));
        roster.discard_record(position.into()).unwrap();
        let mut other_identity = record(position);
        other_identity[2] ^= 1;
        assert!(matches!(
            roster.begin_record(&other_identity),
            Err(Error::Context)
        ));
        roster.begin_record(&record(position)).unwrap();
        roster.discard_record(position.into()).unwrap();
    }
    assert!(matches!(roster.begin_record(&record(3)), Err(Error::Shape)));
    assert!(matches!(roster.finish(), Err(Error::Shape)));
    assert!(matches!(roster.finish(), Err(Error::Shape)));
}

struct Ceremony {
    packet: SignedPoll,
    poll: VerifiedPoll,
    headers: Vec<Vec<u8>>,
    signatures: Vec<[u8; SIGNATURE_BYTES]>,
    keys: Vec<Vec<u8>>,
    proposal: RosterProposal,
}

// An organizer and two members, each with a distinct key whose hash its
// signed header names, and the proposal of their records as the
// registration verifier accepts them.
fn ceremony() -> Ceremony {
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
    let mut credentials: Vec<Credential> = (0..3u8)
        .map(|seed| Credential::from_seed([seed + 1; 32]))
        .collect();
    let runtime = [4; 64];
    let packet = credentials[0].create_poll(draft, runtime, [5; 32]).unwrap();
    let poll = verify_poll(packet.identity, runtime, &packet.body, &packet.signature).unwrap();
    let keys: Vec<Vec<u8>> = (0..3u8)
        .map(|seed| {
            (0..KEY_BYTES / 21)
                .flat_map(|index| {
                    let mut value = [0; 21];
                    value[1] = (index as u8) ^ seed;
                    value
                })
                .collect()
        })
        .collect();
    let mut headers = Vec::new();
    let mut signatures = Vec::new();
    let mut records = Vec::new();
    for (position, credential) in credentials.iter_mut().enumerate() {
        let header = RegistrationHeader {
            username: normalize_username(format!("Participant {position}").as_bytes()).unwrap(),
            poll: poll.identity(),
            signing_public: *credential.signing_public(),
            recipient_key_hash: ProtocolHash::digest(&keys[position]),
            fhe_key_commitments: vec![
                [7; 64];
                crate::source_binding::fhe_key_families(&poll).len()
            ],
        }
        .encode()
        .unwrap();
        let body = BodyDigest::from_header(&header, poll.identity()).unwrap();
        let signature = credential.sign_registration(body).unwrap();
        let mut verifier = RegistrationVerifier::new(&poll, &header, &signature).unwrap();
        for part in keys[position].chunks(CHUNK_LIMIT) {
            verifier.push_key(part).unwrap();
        }
        verifier.finish_key().unwrap();
        records.push(Arc::new(verifier.finish().unwrap()));
        headers.push(header);
        signatures.push(signature);
    }
    let proposal = RosterProposal::new(&poll, records).unwrap();
    Ceremony {
        packet,
        poll,
        headers,
        signatures,
        keys,
        proposal,
    }
}

fn begin_input(ceremony: &Ceremony) -> Vec<u8> {
    [
        ceremony.packet.identity.as_slice(),
        &ceremony.poll.runtime(),
        &3u16.to_le_bytes(),
        &(ceremony.packet.body.len() as u32).to_le_bytes(),
        &ceremony.packet.body,
        &ceremony.packet.signature,
    ]
    .concat()
}

// The begin input of a position under the body identity the proposal lists
// there, with the header and signature of the record served for it.
fn record_input(ceremony: &Ceremony, position: usize, served: usize) -> Vec<u8> {
    let header = &ceremony.headers[served];
    [
        (position as u16).to_le_bytes().as_slice(),
        &ceremony.proposal.records()[position].body_digest(),
        &(header.len() as u32).to_le_bytes(),
        header,
        &ceremony.signatures[served],
    ]
    .concat()
}

// Streams the record served for a position and its key, as the host does.
fn stream_record(
    verifier: &mut RosterInputVerifier,
    ceremony: &Ceremony,
    position: usize,
    served: usize,
) -> Result<(), Error> {
    verifier.begin_record(&record_input(ceremony, position, served))?;
    for part in ceremony.keys[served].chunks(CHUNK_LIMIT) {
        verifier.push_key(position, part)?;
    }
    verifier.finish_key(position)?;
    verifier.finish_record(position)
}

// The roster verifier builds the proposal of the signed records that the
// registration verifier accepts, record for record, and builds it again on
// request.
#[test]
fn rosters_build_the_proposal_of_their_signed_records() {
    let ceremony = ceremony();
    let mut verifier = RosterInputVerifier::new(&begin_input(&ceremony)).unwrap();
    for position in 0..3 {
        stream_record(&mut verifier, &ceremony, position, position).unwrap();
    }
    let proposal = verifier.finish().unwrap();
    assert_eq!(proposal.identity(), ceremony.proposal.identity());
    assert_eq!(proposal.body(), ceremony.proposal.body());
    for (left, right) in proposal.records().iter().zip(ceremony.proposal.records()) {
        assert_eq!(
            left.header().encode().unwrap(),
            right.header().encode().unwrap()
        );
        assert_eq!(left.body_digest(), right.body_digest());
        assert_eq!(left.public_key(), right.public_key());
    }
    assert_eq!(
        verifier.finish().unwrap().identity(),
        ceremony.proposal.identity()
    );
}

// Each position takes only a record with the body identity that its first
// begin requested. Another position's valid record, a changed signature, a
// key its header does not name and an interrupted delivery each lose only
// their candidate, and no verified position is replaced.
#[test]
fn records_bind_their_requested_identity_and_retries_keep_verified_positions() {
    let ceremony = ceremony();
    let mut verifier = RosterInputVerifier::new(&begin_input(&ceremony)).unwrap();
    stream_record(&mut verifier, &ceremony, 0, 0).unwrap();
    stream_record(&mut verifier, &ceremony, 2, 2).unwrap();
    assert!(matches!(verifier.discard_record(0), Err(Error::Consumed)));
    assert!(matches!(
        verifier.begin_record(&record_input(&ceremony, 0, 0)),
        Err(Error::Shape)
    ));
    assert!(matches!(
        stream_record(&mut verifier, &ceremony, 1, 2),
        Err(Error::Context)
    ));
    verifier.discard_record(1).unwrap();
    let mut other_identity = record_input(&ceremony, 1, 1);
    other_identity[2] ^= 1;
    assert!(matches!(
        verifier.begin_record(&other_identity),
        Err(Error::Context)
    ));
    let mut changed_signature = record_input(&ceremony, 1, 1);
    changed_signature[70 + ceremony.headers[1].len()] ^= 1;
    verifier.begin_record(&changed_signature).unwrap();
    for part in ceremony.keys[1].chunks(CHUNK_LIMIT) {
        verifier.push_key(1, part).unwrap();
    }
    verifier.finish_key(1).unwrap();
    assert!(matches!(verifier.finish_record(1), Err(Error::Crypto)));
    verifier.discard_record(1).unwrap();
    verifier
        .begin_record(&record_input(&ceremony, 1, 1))
        .unwrap();
    for part in ceremony.keys[2].chunks(CHUNK_LIMIT) {
        verifier.push_key(1, part).unwrap();
    }
    verifier.finish_key(1).unwrap();
    assert!(matches!(verifier.finish_record(1), Err(Error::Shape)));
    assert!(matches!(verifier.finish(), Err(Error::Shape)));
    verifier.discard_record(1).unwrap();
    // A transport interruption after a complete key is cancellation, not
    // permission to install a record from incomplete delivery.
    verifier
        .begin_record(&record_input(&ceremony, 1, 1))
        .unwrap();
    for part in ceremony.keys[1].chunks(CHUNK_LIMIT) {
        verifier.push_key(1, part).unwrap();
    }
    verifier.finish_key(1).unwrap();
    verifier.discard_record(1).unwrap();
    assert!(matches!(verifier.finish_record(1), Err(Error::Shape)));
    stream_record(&mut verifier, &ceremony, 1, 1).unwrap();
    let proposal = verifier.finish().unwrap();
    assert_eq!(proposal.body(), ceremony.proposal.body());
    assert_eq!(proposal.identity(), ceremony.proposal.identity());
    assert!(matches!(verifier.discard_record(1), Err(Error::Consumed)));
    assert_eq!(verifier.finish().unwrap().identity(), proposal.identity());
}
