//! A real poll and its organizer's registration, which the registration
//! tests verify.
use crate::Enrollment;
use protocol_foundations::{
    foundation::{
        StabilizedDisplayText,
        manifest::{Manifest, OptionDefinition},
    },
    poll::{PollDraft, SignedPoll, VerifiedPoll, verify_poll},
};

/// The runtime the fixture's poll names.
pub(crate) const RUNTIME: [u8; 64] = [7; 64];

#[derive(Clone)]
pub(crate) struct Record {
    pub(crate) header: Vec<u8>,
    pub(crate) signature: Vec<u8>,
    pub(crate) key: Vec<u8>,
}

// A two-option poll, its signed packet and its organizer's registration.
pub(crate) fn registration() -> (SignedPoll, VerifiedPoll, Record, Enrollment) {
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
    let draft = PollDraft::new(Manifest::new(text("Question"), options).unwrap(), 2, 10).unwrap();
    let mut parts: [Vec<u8>; 3] = Default::default();
    let (packet, enrollment, _) =
        Enrollment::create_organizer(draft, RUNTIME, b"Organizer", |kind, offset, bytes| {
            if let Some(part) = parts.get_mut(kind as usize) {
                assert_eq!(offset, part.len());
                part.extend_from_slice(bytes);
            }
        })
        .unwrap();
    let poll = verify_poll(packet.identity, RUNTIME, &packet.body, &packet.signature).unwrap();
    let [key, header, signature] = parts;
    (
        packet,
        poll,
        Record {
            header,
            signature,
            key,
        },
        enrollment,
    )
}
