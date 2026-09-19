use registration_credentials::{
    BodyHasher, Credential,
    foundation::{RegistrationHeader, normalize_username},
};
use registration_proof::{proof::RegistrationProof, statement};
use setup_witness::registration::RegistrationKey;
use sha3::{Digest, Sha3_512};
use std::io::{self, Write};
use zeroize::Zeroizing;

pub mod ballot;
#[path = "contribution-signing.rs"]
pub mod contribution_signing;
#[path = "finality-work.rs"]
pub mod finality_work;
#[path = "publication-work.rs"]
pub mod publication_work;
#[path = "release-work.rs"]
pub mod release_work;

#[cfg(target_arch = "wasm32")]
mod browser;

pub struct Enrollment {
    pub key: RegistrationKey,
    pub credential: Credential,
}
#[derive(Debug)]
pub enum Error {
    Shape,
    State,
}

fn random<const N: usize>() -> Zeroizing<[u8; N]> {
    let mut bytes = Zeroizing::new([0; N]);
    #[cfg(not(target_arch = "wasm32"))]
    getrandom::fill(bytes.as_mut()).unwrap();
    #[cfg(target_arch = "wasm32")]
    {
        #[link(wasm_import_module = "enrollment")]
        unsafe extern "C" {
            fn fill_random(pointer: *mut u8, length: usize) -> u32;
        }
        assert_eq!(unsafe { fill_random(bytes.as_mut_ptr(), N) }, 0);
    }
    bytes
}
struct RecordWriter<'a, F: FnMut(u32, usize, &[u8])> {
    kind: u32,
    offset: usize,
    buffer: Vec<u8>,
    hash: Sha3_512,
    output: &'a mut F,
}
impl<'a, F: FnMut(u32, usize, &[u8])> RecordWriter<'a, F> {
    fn new(kind: u32, output: &'a mut F) -> Self {
        Self {
            kind,
            offset: 0,
            buffer: Vec::with_capacity(1 << 20),
            hash: Sha3_512::new(),
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
        self.hash.update(bytes);
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
struct BodyWriter {
    body: BodyHasher,
    hash: Sha3_512,
    length: usize,
}
impl Write for BodyWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        for chunk in bytes.chunks(1 << 20) {
            self.body
                .absorb(chunk)
                .map_err(|_| io::Error::other("Registration body changed."))?;
        }
        self.hash.update(bytes);
        self.length += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub fn key_associated(
    role: &[u8],
    runtime: [u8; 64],
    key_hash: [u8; 64],
    proof_hash: [u8; 64],
) -> Vec<u8> {
    let mut bytes = Vec::from(b"RCC1".as_slice());
    bytes.extend((role.len() as u32).to_le_bytes());
    bytes.extend(role);
    bytes.extend(runtime);
    bytes.extend(key_hash);
    bytes.extend(proof_hash);
    bytes
}

impl Enrollment {
    pub fn create_creator(
        draft: registration_credentials::poll::PollDraft,
        runtime: [u8; 64],
        username: &[u8],
        recipient_data_key: &[u8; 32],
        credential_data_key: &[u8; 32],
        output: impl FnMut(u32, usize, &[u8]),
    ) -> Result<(registration_credentials::poll::SignedPoll, Self), Error> {
        normalize_username(username).map_err(|_| Error::Shape)?;
        if recipient_data_key == credential_data_key {
            return Err(Error::Shape);
        }
        let mut credential = fresh_credential();
        let nonce = random::<32>();
        let coins = random::<32>();
        let packet = credential
            .create_poll(draft, runtime, *nonce, *coins)
            .map_err(|_| Error::State)?;
        let verified = registration_credentials::poll::verify_poll(
            packet.identity,
            runtime,
            &packet.body,
            &packet.signature,
        )
        .map_err(|_| Error::State)?;
        let enrollment = Self::create_with_credential(
            verified.identity(),
            runtime,
            username,
            recipient_data_key,
            credential_data_key,
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
        output: impl FnMut(u32, usize, &[u8]),
    ) -> Result<Self, Error> {
        normalize_username(username).map_err(|_| Error::Shape)?;
        if recipient_data_key == credential_data_key {
            return Err(Error::Shape);
        }
        Self::create_with_credential(
            poll.identity(),
            poll.runtime(),
            username,
            recipient_data_key,
            credential_data_key,
            fresh_credential(),
            output,
        )
    }
    fn create_with_credential(
        poll: [u8; 64],
        runtime: [u8; 64],
        username: &[u8],
        recipient_data_key: &[u8; 32],
        credential_data_key: &[u8; 32],
        mut credential: Credential,
        mut output: impl FnMut(u32, usize, &[u8]),
    ) -> Result<Self, Error> {
        let username = normalize_username(username).map_err(|_| Error::Shape)?;
        let role = credential.proof_role(poll, runtime);
        let proof = RegistrationProof::create(&role, false, false);
        proof.check_retained_key().map_err(|_| Error::State)?;
        let public = proof.public_key_bytes();
        let key_hash = Sha3_512::digest(&public).into();
        let mut key_output = RecordWriter::new(0, &mut output);
        key_output.write_all(&public).unwrap();
        key_output.flush().unwrap();
        drop(key_output);
        let mut proof_output = RecordWriter::new(1, &mut output);
        proof.write(&mut proof_output);
        proof_output.flush().unwrap();
        let length = proof_output.offset;
        let proof_hash: [u8; 64] = proof_output.hash.clone().finalize().into();
        drop(proof_output);
        let header = RegistrationHeader {
            username,
            poll,
            runtime,
            signing_public: *credential.signing_public(),
            mailbox_public: *credential.mailbox_public(),
            recipient_key_hash: key_hash,
            proof_length: length,
        }
        .encode()
        .map_err(|_| Error::Shape)?;
        let (body, consumed) =
            BodyHasher::from_header(&header, poll, runtime).map_err(|_| Error::State)?;
        if consumed != header.len() {
            return Err(Error::State);
        }
        let mut body_output = BodyWriter {
            body,
            hash: Sha3_512::new(),
            length: 0,
        };
        proof.write(&mut body_output);
        if body_output.length != length
            || <[u8; 64]>::from(body_output.hash.finalize()) != proof_hash
        {
            return Err(Error::State);
        }
        let body = body_output.body.finish().map_err(|_| Error::State)?;
        let coins = random::<32>();
        let signature = credential
            .sign_registration(body, *coins)
            .map_err(|_| Error::State)?;
        let mut key = proof.into_key();
        let sealed_key = key
            .seal_retained(
                recipient_data_key,
                &key_associated(&role, runtime, key_hash, proof_hash),
            )
            .map_err(|_| Error::State)?;
        let sealed_credential = credential
            .seal_complete(credential_data_key)
            .map_err(|_| Error::State)?;
        for (kind, bytes) in [
            (2, header.as_slice()),
            (3, signature.as_slice()),
            (4, sealed_key.as_slice()),
            (5, sealed_credential.as_slice()),
        ] {
            output(kind, 0, bytes);
        }
        Ok(Self { key, credential })
    }
    pub fn check(&self) -> bool {
        self.key.validate_retained().is_ok() && self.credential.check_retained()
    }
    pub fn restore(
        header: &RegistrationHeader,
        public_bytes: &[u8],
        proof_hash: [u8; 64],
        body_digest: [u8; 64],
        data_keys: &[u8; 64],
        recipient_capsule: &[u8],
        signing_capsule: &[u8],
    ) -> Result<Self, Error> {
        use num_bigint::{BigInt, Sign};
        if public_bytes.len() != 65536 * 21
            || <[u8; 64]>::from(Sha3_512::digest(public_bytes)) != header.recipient_key_hash
        {
            return Err(Error::Shape);
        }
        let modulus = BigInt::from_bytes_le(Sign::Plus, &statement::header()[8..]);
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
            header.mailbox_public,
            body_digest,
            data_keys[32..].try_into().unwrap(),
            signing_capsule,
        )
        .map_err(|_| Error::State)?;
        let role = credential.proof_role(header.poll, header.runtime);
        let key = RegistrationKey::open_retained(
            public,
            data_keys[..32].try_into().unwrap(),
            &key_associated(&role, header.runtime, header.recipient_key_hash, proof_hash),
            recipient_capsule,
        )
        .map_err(|_| Error::State)?;
        Ok(Self { key, credential })
    }
}

fn fresh_credential() -> Credential {
    let seeds = random::<96>();
    Credential::from_seeds(
        seeds[..32].try_into().unwrap(),
        seeds[32..64].try_into().unwrap(),
        seeds[64..].try_into().unwrap(),
    )
}
