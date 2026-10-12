//! The enrollment inputs the host writes: the organizer's poll draft and a
//! joiner's signed poll, each followed by the username, and the retained
//! records a restore reopens. Each parse refuses a frame past its bound, a
//! username the module would not normalize and bytes after the last field.
use crate::{Enrollment, Error};
use protocol_foundations::{
    SEALED_SIGNING_SEED_BYTES, SIGNATURE_BYTES,
    foundation::{
        RegistrationHeader, StabilizedDisplayText,
        manifest::{Manifest, OptionDefinition},
        normalize_username,
    },
    poll::{MAXIMUM_POLL_BYTES, PollDraft, VerifiedPoll, verify_poll},
    registration::KEY_BYTES,
};
use setup_witness::registration::SEALED_KEY_BYTES;
use std::ops::Range;

/// The bytes after a four-byte length at an offset, as their range, when the
/// input holds them and they fit a poll definition.
fn framed(input: &[u8], offset: usize) -> Option<Range<usize>> {
    let start = offset.checked_add(4)?;
    let length = u32::from_le_bytes(input.get(offset..start)?.try_into().ok()?) as usize;
    if length > MAXIMUM_POLL_BYTES {
        return None;
    }
    let end = start.checked_add(length)?;
    (end <= input.len()).then_some(start..end)
}

/// The username after a four-byte length at an offset, as its range, when it
/// ends the input and normalizes.
fn final_username(input: &[u8], offset: usize) -> Option<Range<usize>> {
    let start = offset.checked_add(4)?;
    let length = u32::from_le_bytes(input.get(offset..start)?.try_into().ok()?) as usize;
    if input.len().checked_sub(start)? != length {
        return None;
    }
    normalize_username(&input[start..]).ok()?;
    Some(start..input.len())
}

pub(crate) struct OrganizerInput {
    pub(crate) draft: PollDraft,
    pub(crate) runtime: [u8; 64],
    pub(crate) username: Range<usize>,
}

/// The organizer input is the runtime, the result length, the participant
/// maximum, the question, the option count, each option's label in order and
/// the username, each text after its four-byte length. The question and
/// labels become the poll's manifest under the module's own normalization,
/// option `i` named `option-i`, and the poll definition bounds them all.
pub(crate) fn organizer_input(input: &[u8]) -> Option<OrganizerInput> {
    let runtime = input.get(..64)?.try_into().ok()?;
    let top_count = u16::from_le_bytes(input.get(64..66)?.try_into().ok()?);
    let maximum_participants = u16::from_le_bytes(input.get(66..68)?.try_into().ok()?);
    let question = framed(input, 68)?;
    let mut offset = question.end + 2;
    let option_count = u16::from_le_bytes(input.get(question.end..offset)?.try_into().ok()?);
    let question = StabilizedDisplayText::from_ingress_utf8(&input[question]).ok()?;
    // An option index past the supported count is refused, which bounds
    // this loop.
    let mut options = Vec::new();
    for index in 0..option_count {
        let label = framed(input, offset)?;
        offset = label.end;
        options.push(
            OptionDefinition::new(
                index,
                format!("option-{index}"),
                StabilizedDisplayText::from_ingress_utf8(&input[label]).ok()?,
            )
            .ok()?,
        );
    }
    let manifest = Manifest::new(question, options).ok()?;
    let draft = PollDraft::new(manifest, top_count, maximum_participants).ok()?;
    Some(OrganizerInput {
        draft,
        runtime,
        username: final_username(input, offset)?,
    })
}

pub(crate) struct JoinerInput {
    pub(crate) poll: VerifiedPoll,
    pub(crate) username: Range<usize>,
}

/// The joiner input is the poll's identity and runtime, its definition after
/// a four-byte length and its signature, then the username after its
/// four-byte length.
pub(crate) fn joiner_input(input: &[u8]) -> Option<JoinerInput> {
    let definition = framed(input, 128)?;
    let signature = definition.end..definition.end.checked_add(SIGNATURE_BYTES)?;
    let username = final_username(input, signature.end)?;
    let poll = verify_poll(
        input[..64].try_into().ok()?,
        input[64..128].try_into().ok()?,
        &input[definition],
        input.get(signature)?,
    )
    .ok()?;
    Some(JoinerInput { poll, username })
}

/// A retained credential as a restore reads it: the poll's identity, the
/// registration header after its four-byte length, the body digest, the
/// capsule keys, the recipient public key, the recipient key's and the
/// credential's capsules, then the source capsule or, for a prepared restore,
/// the retained setup after its four-byte length, and last the purposes the
/// participant root shows unused.
pub(crate) struct RestoreInput<'a> {
    prepared: bool,
    pub(crate) header: RegistrationHeader,
    pub(crate) header_bytes: &'a [u8],
    pub(crate) body_digest: [u8; 64],
    data_keys: &'a [u8],
    pub(crate) public_key: &'a [u8],
    capsules: [&'a [u8]; 2],
    sources: &'a [u8],
    pub(crate) unused: u16,
}

/// A prepared restore holds the capsule keys of the recipient key and the
/// credential; any other restore also the sources' key.
pub(crate) fn restore_input(input: &[u8], prepared: bool) -> Option<RestoreInput<'_>> {
    let header_length = u32::from_le_bytes(input.get(64..68)?.try_into().ok()?) as usize;
    if header_length > RegistrationHeader::maximum_bytes() {
        return None;
    }
    let header_bytes = input.get(68..68 + header_length)?;
    let (header, consumed) = RegistrationHeader::decode_prefix(header_bytes).ok()?;
    if consumed != header_length || header.poll.as_slice() != &input[..64] {
        return None;
    }
    let (body_digest, rest) = input[68 + header_length..].split_first_chunk::<64>()?;
    let (data_keys, rest) = rest.split_at_checked(if prepared { 64 } else { 96 })?;
    let (public_key, rest) = rest.split_at_checked(KEY_BYTES)?;
    let (recipient_capsule, rest) = rest.split_at_checked(SEALED_KEY_BYTES)?;
    let (signing_capsule, rest) = rest.split_at_checked(SEALED_SIGNING_SEED_BYTES)?;
    let (sources, unused) = rest.split_last_chunk::<2>()?;
    Some(RestoreInput {
        prepared,
        header,
        header_bytes,
        body_digest: *body_digest,
        data_keys,
        public_key,
        capsules: [recipient_capsule, signing_capsule],
        sources,
        unused: u16::from_le_bytes(*unused),
    })
}

impl RestoreInput<'_> {
    /// Reopens the retained credential under the signed poll it names.
    pub(crate) fn enrollment(&self, poll: &VerifiedPoll) -> Result<Enrollment, Error> {
        let [recipient_capsule, signing_capsule] = self.capsules;
        if self.prepared {
            let (length, setup) = self.sources.split_first_chunk::<4>().ok_or(Error::Shape)?;
            if u32::from_le_bytes(*length) as usize != setup.len() {
                return Err(Error::Shape);
            }
            Enrollment::restore_prepared(
                poll,
                &self.header,
                self.public_key,
                self.body_digest,
                self.data_keys.try_into().unwrap(),
                [recipient_capsule, signing_capsule, setup],
            )
        } else {
            if self.sources.len() != crate::fhe_sources::capsule_bytes(poll) {
                return Err(Error::Shape);
            }
            Enrollment::restore(
                poll,
                &self.header,
                self.public_key,
                self.body_digest,
                self.data_keys.try_into().unwrap(),
                [recipient_capsule, signing_capsule, self.sources],
            )
        }
    }
}

#[cfg(test)]
#[path = "enrollment-input-tests.rs"]
mod tests;
