//! The enrollment input parses on real polls and a real registration: each
//! accepts its exact layout and refuses changed, short and trailing bytes.
use super::{joiner_input, organizer_input, restore_input};
use crate::{
    Enrollment, Error,
    registration_fixture::{RUNTIME, Record, registration},
};
use protocol_foundations::{
    BodyDigest, SIGNATURE_BYTES, foundation::RegistrationHeader, poll::MAXIMUM_POLL_BYTES,
    poll::VerifiedPoll,
};

fn text(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend((value.len() as u32).to_le_bytes());
    bytes.extend(value);
}

// The organizer input of a two-option poll with a result length of one and
// at most ten participants.
fn organizer_bytes(username: &[u8]) -> Vec<u8> {
    let mut bytes = RUNTIME.to_vec();
    bytes.extend(1u16.to_le_bytes());
    bytes.extend(10u16.to_le_bytes());
    text(&mut bytes, b"Question");
    bytes.extend(2u16.to_le_bytes());
    text(&mut bytes, b"Option 0");
    text(&mut bytes, b"Option 1");
    text(&mut bytes, username);
    bytes
}

#[test]
fn organizer_input_becomes_the_poll_it_describes() {
    let bytes = organizer_bytes(b"Organizer");
    let input = organizer_input(&bytes).unwrap();
    assert_eq!(input.runtime, RUNTIME);
    assert_eq!(&bytes[input.username.clone()], b"Organizer");
    let (packet, _, _) = Enrollment::create_organizer(
        input.draft,
        input.runtime,
        &bytes[input.username],
        |_, _, _| {},
    )
    .unwrap();
    let poll = protocol_foundations::poll::verify_poll(
        packet.identity,
        RUNTIME,
        &packet.body,
        &packet.signature,
    )
    .unwrap();
    let manifest = poll.manifest();
    assert_eq!(poll.top_count(), 1);
    assert_eq!(poll.maximum_participants(), 10);
    assert_eq!(manifest.display_title().as_str(), "Question");
    let labels: Vec<_> = manifest
        .options()
        .iter()
        .map(|option| (option.option_identifier(), option.display_label().as_str()))
        .collect();
    assert_eq!(labels, [("option-0", "Option 0"), ("option-1", "Option 1")]);
}

#[test]
fn organizer_input_refuses_changed_layouts() {
    let valid = organizer_bytes(b"Organizer");
    let mut trailing = valid.clone();
    trailing.push(0);
    let mut oversized = valid.clone();
    oversized[68..72].copy_from_slice(&(MAXIMUM_POLL_BYTES as u32 + 1).to_le_bytes());
    for (case, bytes) in [
        ("trailing byte", trailing),
        ("short username", valid[..valid.len() - 1].to_vec()),
        ("empty username", organizer_bytes(b"")),
        ("long username", organizer_bytes(&[b'a'; 513])),
        ("username that is not text", organizer_bytes(b"\xff")),
        ("question past the poll bound", oversized),
        ("missing option count", valid[..81].to_vec()),
    ] {
        assert!(organizer_input(&bytes).is_none(), "{case}");
    }
}

// The joiner input of the fixture's signed poll and the username.
fn joiner_bytes(packet: &protocol_foundations::poll::SignedPoll, username: &[u8]) -> Vec<u8> {
    let mut bytes = [packet.identity, RUNTIME].concat();
    text(&mut bytes, &packet.body);
    bytes.extend(packet.signature);
    text(&mut bytes, username);
    bytes
}

#[test]
fn joiner_input_verifies_the_signed_poll() {
    let (packet, poll, _, _) = registration();
    let bytes = joiner_bytes(&packet, b"Joiner");
    let input = joiner_input(&bytes).unwrap();
    assert_eq!(input.poll.identity(), poll.identity());
    assert_eq!(&bytes[input.username], b"Joiner");

    let signature = 132 + packet.body.len();
    let mut forged = bytes.clone();
    forged[signature] ^= 1;
    let mut other_runtime = bytes.clone();
    other_runtime[64] ^= 1;
    let mut trailing = bytes.clone();
    trailing.push(0);
    let mut beyond = bytes.clone();
    beyond[128..132].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
    for (case, bytes) in [
        ("changed signature", forged),
        ("other runtime", other_runtime),
        ("trailing byte", trailing),
        ("short username", bytes[..bytes.len() - 1].to_vec()),
        ("long username", joiner_bytes(&packet, &[b'a'; 513])),
        ("definition past the input", beyond),
        (
            "missing signature",
            bytes[..signature + SIGNATURE_BYTES - 1].to_vec(),
        ),
    ] {
        assert!(joiner_input(&bytes).is_none(), "{case}");
    }
}

// The retained records of the fixture's registration as an unprepared
// restore reads them, with no purpose shown unused.
fn restore_bytes(poll: &VerifiedPoll, record: &Record) -> Vec<u8> {
    let body_digest = BodyDigest::from_header(&record.header, poll.identity())
        .unwrap()
        .bytes();
    let mut bytes = poll.identity().to_vec();
    text(&mut bytes, &record.header);
    bytes.extend(body_digest);
    bytes.extend(&*record.data_keys);
    bytes.extend(&record.key);
    for capsule in &record.capsules {
        bytes.extend(capsule);
    }
    bytes.extend(0u16.to_le_bytes());
    bytes
}

fn restored(poll: &VerifiedPoll, bytes: &[u8]) -> Option<Result<Enrollment, Error>> {
    Some(restore_input(bytes, false)?.enrollment(poll))
}

#[test]
fn restore_input_reopens_the_retained_credential() {
    let (_, poll, record, original) = registration();
    let bytes = restore_bytes(&poll, &record);
    let input = restore_input(&bytes, false).unwrap();
    assert_eq!(input.header_bytes, record.header);
    assert_eq!(input.public_key, record.key);
    assert_eq!(input.unused, 0);
    let enrollment = input.enrollment(&poll).unwrap();
    assert_eq!(
        enrollment.credential.signing_public(),
        original.credential.signing_public()
    );
    assert_eq!(enrollment.key.public_key(), original.key.public_key());
    assert!(!enrollment.sources_retired());
}

#[test]
fn restore_input_refuses_changed_layouts() {
    let (_, poll, record, _) = registration();
    let valid = restore_bytes(&poll, &record);
    let header_end = 68 + record.header.len();
    let mut long_header = valid.clone();
    long_header[64..68]
        .copy_from_slice(&(RegistrationHeader::maximum_bytes() as u32 + 1).to_le_bytes());
    let mut other_poll = valid.clone();
    other_poll[0] ^= 1;
    let mut padded_header = valid[..header_end].to_vec();
    padded_header[64..68].copy_from_slice(&(record.header.len() as u32 + 1).to_le_bytes());
    padded_header.push(0);
    padded_header.extend(&valid[header_end..]);
    for (case, bytes) in [
        ("header past its bound", long_header),
        ("header of another poll", other_poll),
        ("header followed by a byte", padded_header),
        ("missing public key", valid[..header_end + 64 + 96].to_vec()),
    ] {
        assert!(restore_input(&bytes, false).is_none(), "{case}");
    }

    let unused = valid.len() - 2;
    let short_sources = [&valid[..unused - 1], &valid[unused..]].concat();
    let long_sources = [&valid[..unused], &[0], &valid[unused..]].concat();
    let mut other_digest = valid.clone();
    other_digest[header_end] ^= 1;
    let mut changed_capsule = valid.clone();
    changed_capsule[unused - 1] ^= 1;
    for (case, bytes) in [
        ("short source capsule", short_sources),
        ("long source capsule", long_sources),
    ] {
        assert!(
            matches!(restored(&poll, &bytes), Some(Err(Error::Shape))),
            "{case}"
        );
    }
    for (case, bytes) in [
        ("other body digest", other_digest),
        ("changed source capsule", changed_capsule),
    ] {
        assert!(
            matches!(restored(&poll, &bytes), Some(Err(Error::State))),
            "{case}"
        );
    }
}

#[test]
fn prepared_restore_reads_the_retained_setup_after_its_length() {
    let (_, poll, record, _) = registration();
    let valid = restore_bytes(&poll, &record);
    // The prepared layout holds two capsule keys and a framed setup in
    // place of the sources' key and capsule.
    let restored = |frame: &[u8]| {
        let keys = 68 + record.header.len() + 64;
        let capsules = keys + 96 + record.key.len();
        let sources = capsules + record.capsules[0].len() + record.capsules[1].len();
        let bytes = [
            &valid[..keys + 64],
            &valid[keys + 96..sources],
            frame,
            &valid[valid.len() - 2..],
        ]
        .concat();
        restore_input(&bytes, true).map(|input| input.enrollment(&poll))
    };
    // Each setup is longer than its tag, so only the frame check refuses it
    // as malformed.
    for (case, frame) in [
        (
            "frame longer than its setup",
            [&101u32.to_le_bytes()[..], &[0; 100]].concat(),
        ),
        (
            "frame shorter than its setup",
            [&99u32.to_le_bytes()[..], &[0; 100]].concat(),
        ),
        ("no frame length", vec![0; 3]),
    ] {
        assert!(
            matches!(restored(&frame), Some(Err(Error::Shape))),
            "{case}"
        );
    }
    // A complete frame reaches the retained setup's own tag check.
    let frame = [&100u32.to_le_bytes()[..], &[0; 100]].concat();
    assert!(matches!(restored(&frame), Some(Err(Error::State))));
}
