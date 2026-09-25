use num_bigint::{BigInt, Sign};
use num_traits::{Signed, Zero};
use registration_credentials::{
    registration::{KEY_BYTES, VerifiedRegistration},
    roster::{RosterProposal, contribution_role_from_context},
};
use setup_witness::{
    PolynomialOutput,
    contribution::{Contribution, common_polynomial},
};
use stateful_sha3::{Digest, Sha3_512};
use std::{cell::RefCell, sync::Arc};
use supported_profile::{DEGREE, Profile, relation::setup_relation, share_modulus};
use word_proof::{
    bridge::{Prover, first_checkpoint},
    transcript::context_hasher,
};
use zeroize::Zeroize;

const CHUNK: usize = 1 << 20;
/// The input buffer: one polynomial chunk, or one checkpoint import context.
const INPUT_BYTES: usize = 1_572_864;
struct PublicOutput {
    profile: Profile,
    hash: Sha3_512,
    context: Sha3_512,
    next: usize,
    total: usize,
    offset: usize,
    buffer: Vec<u8>,
}
impl PublicOutput {
    fn new(profile: Profile, role: &[u8]) -> Self {
        let mut output = Self {
            profile,
            hash: Sha3_512::new(),
            context: context_hasher(&setup_relation(profile), role),
            next: 0,
            total: 0,
            offset: 0,
            buffer: Vec::with_capacity(CHUNK),
        };
        output.append(&profile.setup_statement_header());
        output.flush();
        output.next = 1;
        output.offset = 0;
        output
    }
    fn append(&mut self, mut bytes: &[u8]) {
        self.total += bytes.len();
        while !bytes.is_empty() {
            let count = bytes.len().min(CHUNK - self.buffer.len());
            self.buffer.extend_from_slice(&bytes[..count]);
            bytes = &bytes[count..];
            if self.buffer.len() == CHUNK {
                self.flush();
            }
        }
    }
    fn flush(&mut self) {
        if self.buffer.is_empty() {
            return;
        }
        self.hash.update(&self.buffer);
        self.context.update(&self.buffer);
        #[link(wasm_import_module = "contribution")]
        unsafe extern "C" {
            fn public_chunk(object: u32, offset: u32, pointer: *const u8, length: usize) -> u32;
        }
        // Only canonical public polynomial/header bytes cross this callback.
        assert_eq!(
            unsafe {
                public_chunk(
                    self.next as u32,
                    self.offset as u32,
                    self.buffer.as_ptr(),
                    self.buffer.len(),
                )
            },
            0
        );
        self.offset += self.buffer.len();
        self.buffer.clear();
    }
}
impl PolynomialOutput for PublicOutput {
    fn polynomial(&mut self, values: &[BigInt], modulus: &BigInt, width: usize) {
        // Object zero is the header and object i + 1 setup polynomial i.
        assert!(self.next > 0);
        let family = self.profile.setup_family(self.next - 1).unwrap();
        assert_eq!(values.len(), self.profile.family_degree(family));
        assert_eq!(width, self.profile.family_magnitude_bytes(family));
        let half = modulus >> 1usize;
        let mut encoded = vec![0u8; 1 + width];
        for value in values {
            assert!(value.abs() <= half);
            let (sign, magnitude) = value.to_bytes_le();
            assert!(magnitude.len() <= width);
            encoded.fill(0);
            encoded[0] = u8::from(sign == Sign::Minus);
            encoded[1..1 + magnitude.len()].copy_from_slice(&magnitude);
            self.append(&encoded);
        }
        self.flush();
        self.next += 1;
        self.offset = 0;
    }
}
struct Work {
    profile: Profile,
    role: Vec<u8>,
    registrations: Vec<Arc<VerifiedRegistration>>,
    retained_keys: Vec<Vec<u8>>,
    input_hashes: Vec<[u8; 64]>,
    generator: Option<Contribution>,
    proof: Option<Prover>,
    public: Option<PublicOutput>,
    next_gadget: usize,
    shares_started: bool,
    next_recipient: usize,
}
impl Work {
    fn new(proposal: &RosterProposal, position: usize) -> Result<Self, ()> {
        let profile = proposal.profile();
        let role = proposal.contribution_role(position).map_err(|_| ())?;
        Ok(Self {
            profile,
            registrations: proposal.records().to_vec(),
            retained_keys: Vec::new(),
            input_hashes: proposal
                .records()
                .iter()
                .map(|record| record.header().recipient_key_hash)
                .collect(),
            generator: Some(Contribution::new(profile)),
            proof: None,
            public: Some(PublicOutput::new(profile, &role)),
            role,
            next_gadget: 0,
            shares_started: false,
            next_recipient: 0,
        })
    }
    fn restore(
        proof: Prover,
        retained_keys: Vec<Vec<u8>>,
        input_hashes: Vec<[u8; 64]>,
    ) -> Result<Self, ()> {
        let profile = proof.profile();
        if retained_keys.len() != profile.participants()
            || input_hashes.len() != profile.participants()
        {
            return Err(());
        }
        let role = proof.role().to_vec();
        Ok(Self {
            profile,
            role,
            retained_keys,
            input_hashes,
            registrations: Vec::new(),
            generator: None,
            proof: Some(proof),
            public: None,
            next_gadget: profile.gadget_length(),
            shares_started: true,
            next_recipient: profile.participants(),
        })
    }
    fn generate(&mut self) -> Result<(), ()> {
        if self.proof.is_some() {
            return Err(());
        }
        let profile = self.profile;
        let public = self.public.as_mut().ok_or(())?;
        let generator = self.generator.as_mut().ok_or(())?;
        if self.next_gadget < profile.gadget_length() {
            generator.gadget(self.next_gadget, public).map_err(|_| ())?;
            self.next_gadget += 1;
        } else if !self.shares_started {
            generator.begin_shares(public).map_err(|_| ())?;
            self.shares_started = true;
        } else if self.next_recipient < self.registrations.len() {
            self.generate_recipient()?;
        } else if self.next_recipient == profile.participants() {
            generator.finish(public).map_err(|_| ())?;
            if public.total != profile.setup_statement_length()
                || public.next != profile.setup_polynomials() + 1
            {
                return Err(());
            }
            let columns = self
                .generator
                .take()
                .unwrap()
                .into_columns()
                .map_err(|_| ())?;
            let public = self.public.take().ok_or(())?;
            self.proof = Some(
                Prover::from_generated(
                    profile,
                    &self.role,
                    public.hash.finalize().into(),
                    public.context.finalize().into(),
                    profile.setup_statement_header(),
                    columns,
                )
                .map_err(|_| ())?,
            );
        } else {
            return Err(());
        }
        Ok(())
    }
    fn generate_recipient(&mut self) -> Result<(), ()> {
        let index = self.next_recipient;
        let record = self.registrations.get(index).ok_or(())?;
        let key = record.public_key();
        if !self.shares_started || self.proof.is_some() {
            return Err(());
        }
        if <[u8; 64]>::from(Sha3_512::digest(key)) != record.header().recipient_key_hash {
            return Err(());
        }
        let half = BigInt::from_bytes_le(Sign::Plus, share_modulus()) >> 1usize;
        let mut values = Vec::with_capacity(DEGREE);
        for coefficient in key.chunks_exact(1 + share_modulus().len()) {
            let magnitude = BigInt::from_bytes_le(Sign::Plus, &coefficient[1..]);
            if coefficient[0] > 1
                || magnitude > half
                || (coefficient[0] == 1 && magnitude.is_zero())
            {
                return Err(());
            }
            values.push(if coefficient[0] == 1 {
                -magnitude
            } else {
                magnitude
            });
        }
        self.generator
            .as_mut()
            .ok_or(())?
            .share(index, &values, self.public.as_mut().ok_or(())?)
            .map_err(|_| ())?;
        self.next_recipient += 1;
        Ok(())
    }
    fn consume_predecessor(&mut self, index: usize) -> Result<(), ()> {
        let profile = self.profile;
        let proof = self.proof.as_mut().ok_or(())?;
        let mut unused_output = Vec::new();
        proof
            .advance(8, index, &[], &mut unused_output)
            .map_err(|_| ())?;
        if let Some(recipient) = (0..self.input_hashes.len())
            .find(|recipient| profile.recipient_key_polynomial(*recipient) == index)
        {
            let key = if self.registrations.is_empty() {
                self.retained_keys[recipient].as_slice()
            } else {
                self.registrations[recipient].public_key()
            };
            for bytes in key.chunks(CHUNK) {
                proof
                    .advance(9, 0, bytes, &mut unused_output)
                    .map_err(|_| ())?;
            }
            return proof
                .advance(10, 0, &[], &mut unused_output)
                .map_err(|_| ());
        }
        let values = common_polynomial(profile, index).map_err(|_| ())?;
        let width = profile.family_magnitude_bytes(profile.setup_family(index).ok_or(())?);
        let mut encoded = vec![0u8; 1 + width];
        let mut buffer = Vec::with_capacity(CHUNK);
        for value in values {
            let (sign, magnitude) = value.to_bytes_le();
            if magnitude.len() > width {
                return Err(());
            }
            encoded.fill(0);
            encoded[0] = u8::from(sign == Sign::Minus);
            encoded[1..1 + magnitude.len()].copy_from_slice(&magnitude);
            let mut remaining = encoded.as_slice();
            while !remaining.is_empty() {
                let count = remaining.len().min(CHUNK - buffer.len());
                buffer.extend_from_slice(&remaining[..count]);
                remaining = &remaining[count..];
                if buffer.len() == CHUNK {
                    proof
                        .advance(9, 0, &buffer, &mut unused_output)
                        .map_err(|_| ())?;
                    buffer.clear();
                }
            }
        }
        if !buffer.is_empty() {
            proof
                .advance(9, 0, &buffer, &mut unused_output)
                .map_err(|_| ())?;
        }
        proof
            .advance(10, 0, &[], &mut unused_output)
            .map_err(|_| ())
    }
    fn phase(&self) -> u32 {
        if let Some(proof) = &self.proof {
            100 + proof.phase_code()
        } else if self.next_gadget < self.profile.gadget_length() || !self.shares_started {
            1
        } else if self.next_recipient < self.profile.participants() {
            2
        } else {
            3
        }
    }
}
struct Session {
    input: Vec<u8>,
    output: Vec<u8>,
    work: Option<Work>,
    stopped: bool,
    checkpoint_export: Option<first_checkpoint::Export>,
    checkpoint_import: Option<first_checkpoint::Import>,
    restore_keys: Vec<Option<Vec<u8>>>,
}
thread_local! { static SESSION: RefCell<Session> = RefCell::new(Session { input: vec![0; INPUT_BYTES], output: Vec::new(), work: None, stopped: false, checkpoint_export: None, checkpoint_import: None, restore_keys: Vec::new() }); }
/// Initializes an embedded prover from the owning verifier's immutable proposal.
/// The participant worker persists its one-shot intent before invoking this.
pub fn begin_verified(
    proposal: &RosterProposal,
    position: usize,
) -> Result<(), registration_credentials::Error> {
    use registration_credentials::Error;
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        if state.stopped
            || state.work.is_some()
            || state.checkpoint_import.is_some()
            || state.checkpoint_export.is_some()
        {
            return Err(Error::Consumed);
        }
        let work = Work::new(proposal, position).map_err(|_| Error::Context)?;
        state.output.clear();
        state.work = Some(work);
        Ok(())
    })
}
pub fn input_pointer() -> usize {
    SESSION.with(|state| state.borrow_mut().input.as_mut_ptr() as usize)
}
/// The input buffer's length; the host never writes more.
pub fn input_capacity() -> usize {
    INPUT_BYTES
}

/// Records of the checkpoint being imported, or else of the running proof's
/// checkpoint.
pub fn checkpoint_records() -> usize {
    SESSION.with(|state| {
        let state = state.borrow();
        state
            .checkpoint_import
            .as_ref()
            .map(first_checkpoint::Import::relation)
            .or_else(|| {
                state
                    .work
                    .as_ref()
                    .and_then(|work| work.proof.as_ref())
                    .map(Prover::relation)
            })
            .map_or(0, first_checkpoint::record_count)
    })
}

pub fn checkpoint_command(operation: u32, position: usize, length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        if state.stopped || (operation != 4 && position != 0) {
            return 1;
        }
        state.output.clear();
        let Session {
            input,
            output,
            work,
            checkpoint_export,
            checkpoint_import,
            restore_keys,
            stopped,
        } = &mut *state;
        let result = (|| {
            let bytes = input.get(..length).ok_or(())?;
            match operation {
                1 if length == 0 && checkpoint_export.is_none() && checkpoint_import.is_none() => {
                    let proof = work
                        .as_ref()
                        .and_then(|work| work.proof.as_ref())
                        .ok_or(())?;
                    let export = first_checkpoint::Export::begin_with_inputs(
                        proof,
                        &work.as_ref().ok_or(())?.input_hashes,
                    )
                    .map_err(|_| ())?;
                    *output = export.header();
                    *checkpoint_export = Some(export);
                }
                2 if length == 32 => {
                    let key = zeroize::Zeroizing::new(<[u8; 32]>::try_from(bytes).unwrap());
                    let proof = work
                        .as_ref()
                        .and_then(|work| work.proof.as_ref())
                        .ok_or(())?;
                    *output = checkpoint_export
                        .as_mut()
                        .ok_or(())?
                        .seal(proof, &key)
                        .map_err(|_| ())?;
                }
                3 if length == 0 => {
                    if !checkpoint_export.as_ref().ok_or(())?.complete() {
                        return Err(());
                    }
                    *checkpoint_export = None;
                }
                4 if work.is_none()
                    && checkpoint_export.is_none()
                    && checkpoint_import.is_none() =>
                {
                    if bytes.len() < 192 {
                        return Err(());
                    }
                    let poll = bytes[..64].try_into().unwrap();
                    let runtime = bytes[64..128].try_into().unwrap();
                    let proposal = bytes[128..192].try_into().unwrap();
                    let role = contribution_role_from_context(poll, runtime, proposal, position)
                        .map_err(|_| ())?;
                    let import = first_checkpoint::Import::begin(&bytes[192..]).map_err(|_| ())?;
                    let participants = import.profile().participants();
                    if import.role() != role
                        || position >= participants
                        || import.input_hashes().len() != participants
                    {
                        return Err(());
                    }
                    *checkpoint_import = Some(import);
                    *restore_keys = vec![None; participants];
                }
                5 if (48..=32 + first_checkpoint::RECORD_BYTES + 16).contains(&length) => {
                    let key = zeroize::Zeroizing::new(<[u8; 32]>::try_from(&bytes[..32]).unwrap());
                    checkpoint_import
                        .as_mut()
                        .ok_or(())?
                        .open(&key, &bytes[32..])
                        .map_err(|_| ())?;
                }
                6 if length == 0 => {
                    if !checkpoint_import.as_ref().ok_or(())?.complete()
                        || restore_keys.iter().any(Option::is_none)
                    {
                        return Err(());
                    }
                    let import = checkpoint_import.take().unwrap();
                    let input_hashes = import.input_hashes().to_vec();
                    let proof = import.finish().map_err(|_| ())?;
                    let keys = std::mem::take(restore_keys)
                        .into_iter()
                        .map(Option::unwrap)
                        .collect();
                    *work = Some(Work::restore(proof, keys, input_hashes)?);
                }
                _ => return Err(()),
            }
            Ok(())
        })();
        let consumed = length.min(input.len());
        input[..consumed].zeroize();
        if result.is_err()
            && (operation == 5 || (operation == 6 && work.is_none() && checkpoint_import.is_none()))
        {
            *checkpoint_import = None;
            restore_keys.clear();
            *stopped = true;
        }
        u32::from(result.is_err())
    })
}
pub fn output_pointer() -> usize {
    SESSION.with(|state| state.borrow().output.as_ptr() as usize)
}
pub fn output_length() -> usize {
    SESSION.with(|state| state.borrow().output.len())
}
pub fn phase() -> u32 {
    SESSION.with(|state| state.borrow().work.as_ref().map_or(0, Work::phase))
}
pub fn command(operation: u32, argument: usize, length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        if state.checkpoint_export.is_some() || state.checkpoint_import.is_some() {
            return 1;
        }
        if !matches!(operation, 2 | 7..=11 | 14) || length > CHUNK {
            return 1;
        }
        state.output.clear();
        let Session {
            input,
            output,
            work,
            stopped,
            ..
        } = &mut *state;
        let result = (|| {
            if *stopped {
                return Err(());
            }
            let bytes = input.get(..length).ok_or(())?;
            let work = work.as_mut().ok_or(())?;
            match operation {
                2 if length == 0 && argument == 0 => work.generate(),
                14 if length == 0 => work.consume_predecessor(argument),
                7..=11 => work
                    .proof
                    .as_mut()
                    .ok_or(())?
                    .advance(operation, argument, bytes, output)
                    .map_err(|_| ()),
                _ => Err(()),
            }
        })();
        if result.is_err() {
            *work = None;
            *stopped = true;
            input.zeroize();
            output.clear();
        }
        u32::from(result.is_err())
    })
}
pub fn checkpoint_key(position: usize, length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        if state.stopped
            || state.work.is_some()
            || length != KEY_BYTES
            || position >= state.restore_keys.len()
            || state.restore_keys[position].is_some()
        {
            return 1;
        }
        let Some(import) = state.checkpoint_import.as_ref() else {
            return 1;
        };
        let Some(expected) = import.input_hashes().get(position) else {
            return 1;
        };
        let Some(bytes) = state.input.get(..length) else {
            return 1;
        };
        if <[u8; 64]>::from(Sha3_512::digest(bytes)) != *expected {
            return 1;
        }
        let key = bytes.to_vec();
        state.restore_keys[position] = Some(key);
        0
    })
}
