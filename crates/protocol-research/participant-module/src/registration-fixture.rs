//! A real poll and its organizer's registration, which the registration
//! tests verify.
use crate::{DataKeys, Enrollment, data_kind};
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
    pub(crate) sources: Vec<u8>,
    // The capsules of the recipient key, the credential and the sources, and
    // their keys in the same order.
    pub(crate) capsules: [Vec<u8>; 3],
    pub(crate) data_keys: DataKeys,
}

// A two-option poll, its signed packet and its organizer's registration.
pub(crate) fn registration() -> (SignedPoll, VerifiedPoll, Record, Enrollment) {
    registration_with_dimensions(10, 2)
}
pub(crate) fn registration_with_dimensions(
    maximum: u16,
    option_count: u16,
) -> (SignedPoll, VerifiedPoll, Record, Enrollment) {
    let text = |value: &str| StabilizedDisplayText::from_ingress_utf8(value.as_bytes()).unwrap();
    let options = (0..option_count)
        .map(|index| {
            OptionDefinition::new(
                index,
                format!("option-{index}"),
                text(&format!("Option {index}")),
            )
            .unwrap()
        })
        .collect();
    let draft = PollDraft::new(
        Manifest::new(text("Question"), options).unwrap(),
        2,
        maximum,
    )
    .unwrap();
    let mut parts: [Vec<u8>; 14] = Default::default();
    let (packet, enrollment, data_keys) =
        Enrollment::create_organizer(draft, RUNTIME, b"Organizer", |kind, offset, bytes| {
            let part = &mut parts[kind as usize];
            assert_eq!(offset, part.len());
            part.extend_from_slice(bytes);
        })
        .unwrap();
    let poll = verify_poll(packet.identity, RUNTIME, &packet.body, &packet.signature).unwrap();
    let mut part = |kind: u32| std::mem::take(&mut parts[kind as usize]);
    let record = Record {
        header: part(data_kind::HEADER),
        signature: part(data_kind::SIGNATURE),
        key: part(data_kind::PUBLIC_KEY),
        sources: part(data_kind::SOURCE_CIPHERTEXTS),
        capsules: [
            part(data_kind::RECIPIENT_CAPSULE),
            part(data_kind::SIGNING_CAPSULE),
            part(data_kind::SOURCE_CAPSULE),
        ],
        data_keys,
    };
    (packet, poll, record, enrollment)
}

impl Record {
    pub(crate) fn verified(
        &self,
        poll: &VerifiedPoll,
    ) -> protocol_foundations::registration::VerifiedRegistration {
        let mut verifier = protocol_foundations::registration::RegistrationVerifier::new(
            poll,
            &self.header,
            &self.signature,
        )
        .unwrap();
        for bytes in self.key.chunks(1 << 20) {
            verifier.push_key(bytes).unwrap();
        }
        verifier.finish_key().unwrap();
        for bytes in self.sources.chunks(65_537) {
            verifier.push_sources(bytes).unwrap();
        }
        verifier.finish().unwrap()
    }
}
