use super::*;
use crate::registration::CHUNK_LIMIT;
use crate::{
    foundation::{
        RegistrationHeader, StabilizedDisplayText,
        manifest::{Manifest, OptionDefinition},
        normalize_username,
    },
    poll::{PollDraft, SignedPoll, verify_poll},
    registration::KEY_BYTES,
    roster_input::RosterInputVerifier,
};
use parallel_work::ProtocolHash;
use std::sync::Arc;

struct Ceremony {
    packet: SignedPoll,
    poll: VerifiedPoll,
    credentials: Vec<Credential>,
    headers: Vec<Vec<u8>>,
    keys: Vec<Vec<u8>>,
    proposal: RosterProposal,
}

// An organizer and two members, each with a distinct key whose hash its
// header names, in a proposal of the records the verifier would accept.
fn ceremony(runtime: [u8; 64]) -> Ceremony {
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
    let mut records = Vec::new();
    for (position, credential) in credentials.iter_mut().enumerate() {
        let header = RegistrationHeader {
            username: normalize_username(format!("Participant {position}").as_bytes()).unwrap(),
            poll: poll.identity(),
            runtime,
            signing_public: *credential.signing_public(),
            recipient_key_hash: ProtocolHash::digest(&keys[position]),

            fhe_key_commitments: vec![
                [7; 64];
                crate::source_binding::fhe_key_families(&poll).len()
            ],
        };
        let header = header.encode().unwrap();
        let body =
            crate::BodyDigest::from_header(&header, poll.identity(), poll.runtime()).unwrap();
        let signature = credential.sign_registration(body).unwrap();
        let mut verifier =
            crate::registration::RegistrationVerifier::new(&poll, &header, &signature).unwrap();
        for part in keys[position].chunks(CHUNK_LIMIT) {
            verifier.push_key(part).unwrap();
        }
        verifier.finish_key().unwrap();
        records.push(Arc::new(verifier.finish().unwrap()));
        headers.push(header);
    }
    let proposal = RosterProposal::new(&poll, records).unwrap();
    Ceremony {
        packet,
        poll,
        credentials,
        headers,
        keys,
        proposal,
    }
}

fn begin_input(ceremony: &Ceremony, count: u16) -> Vec<u8> {
    [
        ceremony.packet.identity.as_slice(),
        &ceremony.poll.runtime(),
        &count.to_le_bytes(),
        &(ceremony.packet.body.len() as u32).to_le_bytes(),
        &ceremony.packet.body,
        &ceremony.packet.signature,
    ]
    .concat()
}

fn header_input(position: u16, header: &[u8]) -> Vec<u8> {
    let identity = RegistrationHeader::decode_prefix(header)
        .and_then(|(header, _)| crate::BodyDigest::new(header))
        .map(|body| body.bytes())
        .unwrap_or([0; 64]);
    [
        position.to_le_bytes().as_slice(),
        &identity,
        &(header.len() as u32).to_le_bytes(),
        header,
    ]
    .concat()
}

// Streams each record's header and key into the verifier, as the host
// does, and finishes the roster.
fn restore(
    verifier: &mut RosterInputVerifier,
    headers: &[Vec<u8>],
    keys: &[Vec<u8>],
) -> Result<RosterProposal, Error> {
    for (position, (header, key)) in headers.iter().zip(keys).enumerate() {
        verifier.begin_record(&header_input(position as u16, header))?;
        for part in key.chunks(CHUNK_LIMIT) {
            verifier.push_key(position, part)?;
        }
        verifier.finish_key(position)?;
        verifier.finish_record(position)?;
    }
    verifier.finish()
}

// The restored proposal is the retained one, record for record, from
// the published headers and keys alone.
#[test]
fn retained_rosters_restore_the_verified_proposal() {
    let ceremony = ceremony([4; 64]);
    for credential in &ceremony.credentials {
        let retained = credential
            .retain_roster(&ceremony.poll, &ceremony.proposal)
            .unwrap();
        assert_eq!(retained.len(), retained_roster_bytes(3));
        let mut verifier =
            RosterInputVerifier::retained(&begin_input(&ceremony, 3), credential, &retained)
                .unwrap();
        assert!(verifier.is_retained());
        let restored = restore(&mut verifier, &ceremony.headers, &ceremony.keys).unwrap();
        assert_eq!(restored.identity(), ceremony.proposal.identity());
        assert_eq!(restored.body(), ceremony.proposal.body());
        for (left, right) in restored.records().iter().zip(ceremony.proposal.records()) {
            assert_eq!(
                left.header().encode().unwrap(),
                right.header().encode().unwrap()
            );
            assert_eq!(left.body_digest(), right.body_digest());
            assert_eq!(left.public_key(), right.public_key());
        }
        // The organizer's signature and every later consumer see the
        // same proposal again.
        assert_eq!(
            verifier.finish().unwrap().identity(),
            ceremony.proposal.identity()
        );
    }
}

// Only the credential that retained the roster, for the same poll and
// runtime and the same record count, restores its exact bytes.
#[test]
fn retained_rosters_bind_the_credential_poll_count_and_exact_bytes() {
    let ceremony = ceremony([4; 64]);
    let owner = &ceremony.credentials[1];
    let retained = owner
        .retain_roster(&ceremony.poll, &ceremony.proposal)
        .unwrap();
    let begin = begin_input(&ceremony, 3);
    let refused = |credential: &Credential, begin: &[u8], retained: &[u8]| {
        RosterInputVerifier::retained(begin, credential, retained).is_err()
    };
    assert!(!refused(owner, &begin, &retained));
    // Another signing seed.
    let other = Credential::from_seed([9; 32]);
    assert!(refused(&other, &begin, &retained));
    assert!(refused(&ceremony.credentials[2], &begin, &retained));
    // The same records under a poll of another runtime.
    let foreign = super::tests::ceremony([7; 64]);
    assert!(refused(owner, &begin_input(&foreign, 3), &retained));
    // A roster of another size.
    assert!(refused(owner, &begin_input(&ceremony, 4), &retained));
    // Every changed, missing or extra byte.
    for position in [
        0,
        4,
        67,
        68,
        70,
        70 + 64,
        70 + 3 * RECORD_BYTES - 1,
        retained.len() - 1,
    ] {
        let mut changed = retained.clone();
        changed[position] ^= 1;
        assert!(refused(owner, &begin, &changed), "{position}");
    }
    assert!(refused(owner, &begin, &retained[..retained.len() - 1]));
    assert!(refused(
        owner,
        &begin,
        &[retained.as_slice(), &[0]].concat()
    ));
}

// Each record takes exactly the header the verifier accepted, without a
// signature or proof, and exactly the key that header names; any other
// input refuses the record and the roster.
#[test]
fn restored_records_refuse_other_headers_and_keys() {
    let ceremony = ceremony([4; 64]);
    let owner = &ceremony.credentials[0];
    let retained = owner
        .retain_roster(&ceremony.poll, &ceremony.proposal)
        .unwrap();
    let verifier =
        || RosterInputVerifier::retained(&begin_input(&ceremony, 3), owner, &retained).unwrap();
    // Two records' headers exchanged.
    let mut swapped = ceremony.headers.clone();
    swapped.swap(1, 2);
    let mut keys = ceremony.keys.clone();
    keys.swap(1, 2);
    assert!(matches!(
        restore(&mut verifier(), &swapped, &keys),
        Err(Error::Context)
    ));
    // A header with its signature, as a record to verify begins.
    let mut signed = verifier();
    let with_signature = [
        header_input(0, &ceremony.headers[0]).as_slice(),
        &[0; crate::SIGNATURE_BYTES],
    ]
    .concat();
    assert!(signed.begin_record(&with_signature).is_err());
    assert!(
        signed
            .begin_record(&header_input(0, &ceremony.headers[0]))
            .is_ok()
    );
    // A key with one changed byte, a short key and an overlong one.
    let mut changed = ceremony.keys.clone();
    changed[2][KEY_BYTES / 2] ^= 1;
    assert!(restore(&mut verifier(), &ceremony.headers, &changed).is_err());
    let mut short = ceremony.keys.clone();
    short[1].pop();
    assert!(restore(&mut verifier(), &ceremony.headers, &short).is_err());
    let mut long = ceremony.keys.clone();
    long[0].push(0);
    assert!(restore(&mut verifier(), &ceremony.headers, &long).is_err());
    // A record finished before its key is refused, and a position
    // begins once.
    let mut early = verifier();
    early
        .begin_record(&header_input(1, &ceremony.headers[1]))
        .unwrap();
    assert!(early.finish_record(1).is_err());
    assert!(
        early
            .begin_record(&header_input(1, &ceremony.headers[1]))
            .is_err()
    );
    // A record missing from the stream leaves the roster unfinished.
    assert!(matches!(
        restore(&mut verifier(), &ceremony.headers[..2], &ceremony.keys[..2]),
        Err(Error::Shape)
    ));
}

#[test]
fn candidate_retry_preserves_retained_predecessors_and_verified_positions() {
    let ceremony = ceremony([4; 64]);
    let owner = &ceremony.credentials[0];
    let retained = owner
        .retain_roster(&ceremony.poll, &ceremony.proposal)
        .unwrap();
    let mut verifier =
        RosterInputVerifier::retained(&begin_input(&ceremony, 3), owner, &retained).unwrap();
    let complete = |verifier: &mut RosterInputVerifier, position: usize| {
        verifier
            .begin_record(&header_input(position as u16, &ceremony.headers[position]))
            .unwrap();
        for chunk in ceremony.keys[position].chunks(CHUNK_LIMIT) {
            verifier.push_key(position, chunk).unwrap();
        }
        verifier.finish_key(position).unwrap();
        verifier.finish_record(position).unwrap();
    };
    complete(&mut verifier, 0);
    complete(&mut verifier, 2);
    assert!(matches!(verifier.discard_record(0), Err(Error::Consumed)));
    assert!(
        verifier
            .begin_record(&header_input(0, &ceremony.headers[1]))
            .is_err()
    );

    // An early malformed begin never consumes the original expected ID.
    assert!(verifier.begin_record(&[1, 0]).is_err());
    verifier.discard_record(1).unwrap();
    let mut wrong_identity = header_input(1, &ceremony.headers[1]);
    wrong_identity[2] ^= 1;
    assert!(matches!(
        verifier.begin_record(&wrong_identity),
        Err(Error::Context)
    ));
    verifier.discard_record(1).unwrap();
    // A wrong header and wrong key each lose only their candidate.
    assert!(matches!(
        verifier.begin_record(&header_input(1, &ceremony.headers[2])),
        Err(Error::Context)
    ));
    verifier.discard_record(1).unwrap();
    verifier
        .begin_record(&header_input(1, &ceremony.headers[1]))
        .unwrap();
    for chunk in ceremony.keys[2].chunks(CHUNK_LIMIT) {
        verifier.push_key(1, chunk).unwrap();
    }
    assert!(verifier.finish_key(1).is_err());
    assert!(verifier.finish_record(1).is_err());
    assert!(verifier.finish().is_err());
    verifier.discard_record(1).unwrap();
    // A transport interruption after a complete key is cancellation,
    // not permission to install a record from incomplete delivery.
    verifier
        .begin_record(&header_input(1, &ceremony.headers[1]))
        .unwrap();
    for chunk in ceremony.keys[1].chunks(CHUNK_LIMIT) {
        verifier.push_key(1, chunk).unwrap();
    }
    verifier.finish_key(1).unwrap();
    verifier.discard_record(1).unwrap();
    assert!(verifier.finish_record(1).is_err());
    complete(&mut verifier, 1);
    let proposal = verifier.finish().unwrap();
    assert_eq!(proposal.body(), ceremony.proposal.body());
    assert_eq!(proposal.identity(), ceremony.proposal.identity());
    assert!(verifier.discard_record(1).is_err());
    assert_eq!(verifier.finish().unwrap().identity(), proposal.identity());
}

// A tagged roster whose identity is not its records' proposal restores
// nothing: the verifier checks the proposal it builds, not the tag alone.
#[test]
fn restored_proposals_must_have_the_retained_identity() {
    let ceremony = ceremony([4; 64]);
    let owner = &ceremony.credentials[0];
    let retained = owner
        .retain_roster(&ceremony.poll, &ceremony.proposal)
        .unwrap();
    let mut body = retained[..retained.len() - RETAINED_TAG_BYTES].to_vec();
    body[4] ^= 1;
    let tag = owner.retained_tag(LABEL, &ceremony.poll, &body);
    let forged = [body.as_slice(), &tag].concat();
    let mut verifier =
        RosterInputVerifier::retained(&begin_input(&ceremony, 3), owner, &forged).unwrap();
    assert!(matches!(
        restore(&mut verifier, &ceremony.headers, &ceremony.keys),
        Err(Error::Context)
    ));
    assert!(matches!(verifier.finish(), Err(Error::Consumed)));
}
