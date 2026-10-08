use parallel_work::ProtocolHash;
use registration_credentials::{
    BodyDigest, Credential,
    foundation::{RegistrationHeader, normalize_username},
};
use setup_witness::registration::RegistrationKey;

use std::io::{self, Write};
use zeroize::Zeroizing;

pub mod ballot;
#[path = "close-work.rs"]
pub mod close_work;
#[path = "custody-identity.rs"]
pub mod custody_identity;
#[path = "fhe-sources.rs"]
mod fhe_sources;
#[path = "finality-work.rs"]
pub mod finality_work;
#[cfg(test)]
#[path = "helper-jobs-tests.rs"]
mod helper_jobs_tests;
#[path = "memory-plan.rs"]
pub mod memory_plan;
#[path = "offer-signing.rs"]
pub mod offer_signing;
#[cfg(any(target_arch = "wasm32", test))]
#[path = "operation-random.rs"]
mod operation_random;
#[path = "participant-bounds.rs"]
pub mod participant_bounds;
#[cfg(test)]
#[path = "registration-session-tests.rs"]
mod registration_session_tests;
#[path = "release-work.rs"]
pub mod release_work;

#[cfg(target_arch = "wasm32")]
mod browser;
#[cfg(target_arch = "wasm32")]
#[path = "own-verification.rs"]
mod own_verification;
#[cfg(target_arch = "wasm32")]
#[path = "parallel-browser.rs"]
mod parallel_browser;

/// Every job a helper instance runs. Every proof crate proves with the one
/// shared engine, so its jobs serve every proof kind.
pub static HELPER_JOBS: [&[&parallel_work::Job]; 7] = [
    &parallel_work::JOBS,
    &registration_credentials::JOBS,
    &word_proof::jobs::JOBS,
    &setup_stream_kernel::JOBS,
    &setup_witness::JOBS,
    &rns_arithmetic_probe::JOBS,
    &evaluation_target::JOBS,
];

#[cfg(target_arch = "wasm32")]
#[global_allocator]
static ALLOCATOR: parallel_work::scalar_allocator::ScalarAllocator =
    parallel_work::scalar_allocator::ScalarAllocator::new();

pub struct Enrollment {
    pub key: RegistrationKey,
    pub credential: Credential,
    sources: Option<fhe_sources::Sources>,
}
#[derive(Debug)]
pub enum Error {
    Shape,
    State,
}

fn random<const N: usize>() -> Zeroizing<[u8; N]> {
    let mut bytes = Zeroizing::new([0; N]);
    parallel_work::random::fresh(bytes.as_mut());
    bytes
}
struct RecordWriter<'a, F: FnMut(u32, usize, &[u8])> {
    kind: u32,
    offset: usize,
    buffer: Vec<u8>,
    output: &'a mut F,
}
impl<'a, F: FnMut(u32, usize, &[u8])> RecordWriter<'a, F> {
    fn new(kind: u32, output: &'a mut F) -> Self {
        Self {
            kind,
            offset: 0,
            buffer: Vec::with_capacity(1 << 20),
            output,
        }
    }
    fn send(&mut self) {
        if !self.buffer.is_empty() {
            (self.output)(self.kind, self.offset, &self.buffer);
            self.offset += self.buffer.len();
            self.buffer.clear();
        }
    }
}
impl<F: FnMut(u32, usize, &[u8])> Write for RecordWriter<'_, F> {
    fn write(&mut self, mut bytes: &[u8]) -> io::Result<usize> {
        let length = bytes.len();
        while !bytes.is_empty() {
            let count = bytes.len().min((1 << 20) - self.buffer.len());
            self.buffer.extend(&bytes[..count]);
            bytes = &bytes[count..];
            if self.buffer.len() == 1 << 20 {
                self.send();
            }
        }
        Ok(length)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.send();
        Ok(())
    }
}
pub fn key_associated(body_digest: [u8; 64]) -> Vec<u8> {
    [
        b"sealed-lattice/recipient-key-custody/v1".as_slice(),
        &body_digest,
    ]
    .concat()
}

impl Enrollment {
    pub fn create_creator(
        draft: registration_credentials::poll::PollDraft,
        runtime: [u8; 64],
        username: &[u8],
        recipient_data_key: &[u8; 32],
        credential_data_key: &[u8; 32],
        source_data_key: &[u8; 32],
        output: impl FnMut(u32, usize, &[u8]),
    ) -> Result<(registration_credentials::poll::SignedPoll, Self), Error> {
        normalize_username(username).map_err(|_| Error::Shape)?;
        if !distinct_data_keys(recipient_data_key, credential_data_key, source_data_key) {
            return Err(Error::Shape);
        }
        let mut credential = fresh_credential();
        let nonce = random::<32>();
        let packet = credential
            .create_poll(draft, runtime, *nonce)
            .map_err(|_| Error::State)?;
        let verified = registration_credentials::poll::verify_poll(
            packet.identity,
            runtime,
            &packet.body,
            &packet.signature,
        )
        .map_err(|_| Error::State)?;
        let enrollment = Self::create_with_credential(
            &verified,
            username,
            recipient_data_key,
            credential_data_key,
            source_data_key,
            credential,
            output,
        )?;
        if enrollment.credential.signing_public() != verified.organizer() {
            return Err(Error::State);
        }
        Ok((packet, enrollment))
    }
    pub fn create_for_poll(
        poll: &registration_credentials::poll::VerifiedPoll,
        username: &[u8],
        recipient_data_key: &[u8; 32],
        credential_data_key: &[u8; 32],
        source_data_key: &[u8; 32],
        output: impl FnMut(u32, usize, &[u8]),
    ) -> Result<Self, Error> {
        normalize_username(username).map_err(|_| Error::Shape)?;
        if !distinct_data_keys(recipient_data_key, credential_data_key, source_data_key) {
            return Err(Error::Shape);
        }
        Self::create_with_credential(
            poll,
            username,
            recipient_data_key,
            credential_data_key,
            source_data_key,
            fresh_credential(),
            output,
        )
    }
    fn create_with_credential(
        verified_poll: &registration_credentials::poll::VerifiedPoll,
        username: &[u8],
        recipient_data_key: &[u8; 32],
        credential_data_key: &[u8; 32],
        source_data_key: &[u8; 32],
        mut credential: Credential,
        mut output: impl FnMut(u32, usize, &[u8]),
    ) -> Result<Self, Error> {
        let username = normalize_username(username).map_err(|_| Error::Shape)?;
        let poll = verified_poll.identity();
        let runtime = verified_poll.runtime();
        let mut sources = fhe_sources::Sources::create(verified_poll, &credential)?;
        let mut key = RegistrationKey::new();
        key.validate_retained().map_err(|_| Error::State)?;
        let public = key.public_key_bytes();
        let key_hash = ProtocolHash::digest(&public);
        let mut key_output = RecordWriter::new(0, &mut output);
        key_output.write_all(&public).unwrap();
        key_output.flush().unwrap();
        drop(key_output);
        let header = RegistrationHeader {
            username,
            poll,
            runtime,
            signing_public: *credential.signing_public(),
            recipient_key_hash: key_hash,
            fhe_key_commitments: sources.commitments().to_vec(),
        }
        .encode()
        .map_err(|_| Error::Shape)?;
        let body = BodyDigest::from_header(&header, poll, runtime).map_err(|_| Error::State)?;
        let body_digest = body.bytes();
        let sealed_sources = sources.seal(body_digest, source_data_key)?;
        let signature = credential
            .sign_registration(body)
            .map_err(|_| Error::State)?;
        let sealed_key = key
            .seal_retained(recipient_data_key, &key_associated(body_digest))
            .map_err(|_| Error::State)?;
        let sealed_credential = credential
            .seal_complete(credential_data_key)
            .map_err(|_| Error::State)?;
        for (kind, bytes) in [
            (1, header.as_slice()),
            (2, signature.as_slice()),
            (3, sealed_key.as_slice()),
            (4, sealed_credential.as_slice()),
            (13, sealed_sources.as_slice()),
        ] {
            output(kind, 0, bytes);
        }
        Ok(Self {
            key,
            credential,
            sources: Some(sources),
        })
    }
    /// Reconstructs only this enrollment's original source for the selected family.
    pub fn contribution_source(
        &self,
        profile: supported_profile::Profile,
    ) -> Result<setup_witness::fhe_key_source::FheKeySource, Error> {
        self.sources.as_ref().ok_or(Error::State)?.source(profile)
    }
    pub fn contribution_header(
        &self,
        profile: supported_profile::Profile,
        proof_length: usize,
    ) -> Result<[u8; registration_credentials::contribution_body::BODY_HEADER_BYTES], Error> {
        self.sources
            .as_ref()
            .ok_or(Error::State)?
            .body_header(profile, proof_length)
    }
    /// Retires the seed material that could reconstruct contribution secrets.
    /// The participant root owns authentication and durable retirement first.
    pub fn retire_sources(&mut self) {
        self.sources = None;
        self.credential.retire_preparation();
    }
    pub fn sources_retired(&self) -> bool {
        self.sources.is_none()
    }
    pub fn check(&self) -> bool {
        self.key.validate_retained().is_ok() && self.credential.check_retained()
    }
    pub fn restore(
        poll: &registration_credentials::poll::VerifiedPoll,
        header: &RegistrationHeader,
        public_bytes: &[u8],
        body_digest: [u8; 64],
        data_keys: &[u8; 96],
        records: [&[u8]; 3],
    ) -> Result<Self, Error> {
        if !distinct_data_keys(
            data_keys[..32].try_into().unwrap(),
            data_keys[32..64].try_into().unwrap(),
            data_keys[64..].try_into().unwrap(),
        ) {
            return Err(Error::Shape);
        }
        let mut result = Self::restore_base(
            poll,
            header,
            public_bytes,
            body_digest,
            data_keys[..64].try_into().unwrap(),
            [records[0], records[1]],
        )?;
        result.sources = Some(fhe_sources::Sources::open(
            poll,
            &result.credential,
            &header.fhe_key_commitments,
            body_digest,
            data_keys[64..].try_into().unwrap(),
            records[2],
        )?);
        Ok(result)
    }

    /// Restores only after authenticating this original participant's saved
    /// setup result. This does not restore a public setup capability.
    pub fn restore_prepared(
        poll: &registration_credentials::poll::VerifiedPoll,
        header: &RegistrationHeader,
        public_bytes: &[u8],
        body_digest: [u8; 64],
        data_keys: &[u8; 64],
        records: [&[u8]; 3],
    ) -> Result<Self, Error> {
        let mut result = Self::restore_base(
            poll,
            header,
            public_bytes,
            body_digest,
            data_keys,
            [records[0], records[1]],
        )?;
        let tag_start = records[2]
            .len()
            .checked_sub(registration_credentials::RETAINED_TAG_BYTES)
            .ok_or(Error::Shape)?;
        let (reference, tag) = records[2].split_at(tag_start);
        result
            .credential
            .check_retained_setup_tag(poll, reference, tag)
            .map_err(|_| Error::State)?;
        result.credential.retire_preparation();
        Ok(result)
    }

    fn restore_base(
        poll: &registration_credentials::poll::VerifiedPoll,
        header: &RegistrationHeader,
        public_bytes: &[u8],
        body_digest: [u8; 64],
        data_keys: &[u8; 64],
        records: [&[u8]; 2],
    ) -> Result<Self, Error> {
        use num_bigint::{BigInt, Sign};
        if poll.identity() != header.poll
            || poll.runtime() != header.runtime
            || data_keys[..32] == data_keys[32..]
            || public_bytes.len() != 65536 * 21
            || ProtocolHash::digest(public_bytes) != header.recipient_key_hash
        {
            return Err(Error::Shape);
        }
        let modulus = BigInt::from_bytes_le(Sign::Plus, supported_profile::share_modulus());
        let half = modulus >> 1usize;
        let mut public = Vec::with_capacity(65536);
        for bytes in public_bytes.chunks_exact(21) {
            let value = BigInt::from_bytes_le(Sign::Plus, &bytes[1..]);
            if bytes[0] > 1 || value > half || (bytes[0] == 1 && value == BigInt::from(0)) {
                return Err(Error::Shape);
            }
            public.push(if bytes[0] == 1 { -value } else { value });
        }
        let credential = Credential::open_complete(
            header.signing_public,
            body_digest,
            data_keys[32..].try_into().unwrap(),
            records[1],
        )
        .map_err(|_| Error::State)?;
        let key = RegistrationKey::open_retained(
            public,
            data_keys[..32].try_into().unwrap(),
            &key_associated(body_digest),
            records[0],
        )
        .map_err(|_| Error::State)?;
        Ok(Self {
            key,
            credential,
            sources: None,
        })
    }
}

fn fresh_credential() -> Credential {
    Credential::from_seed(*random::<32>())
}

fn distinct_data_keys(recipient: &[u8; 32], credential: &[u8; 32], source: &[u8; 32]) -> bool {
    recipient != credential && recipient != source && credential != source
}
