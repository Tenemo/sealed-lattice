use num_bigint::{BigInt, Sign};
use num_traits::{Signed, Zero};
use registration_credentials::{
    registration::VerifiedRegistration,
    roster::{RosterProposal, contribution_role_from_context},
    roster_input::RosterInputVerifier,
};
use setup_witness::{
    PolynomialOutput,
    contribution::{Contribution, statement_header},
};
use stateful_sha3::{Digest, Sha3_512};
use std::{cell::RefCell, sync::Arc};
use word_proof::{
    bridge::{Prover, first_checkpoint},
    transcript::{context_hasher, statement_length},
};
use zeroize::Zeroize;

const CHUNK: usize = 1 << 20;
struct PublicOutput {
    hash: Sha3_512,
    context: Sha3_512,
    next: usize,
    total: usize,
    offset: usize,
    buffer: Vec<u8>,
}
impl PublicOutput {
    fn new(role: &[u8]) -> Self {
        let mut output = Self {
            hash: Sha3_512::new(),
            context: context_hasher(role),
            next: 0,
            total: 0,
            offset: 0,
            buffer: Vec::with_capacity(CHUNK),
        };
        output.append(&statement_header());
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
        let (degree, expected_width) = if self.next <= 42 {
            (65536, 108)
        } else if self.next <= 73 {
            (65536, 20)
        } else {
            (4096, 5)
        };
        assert!(self.next > 0 && self.next <= 75);
        assert_eq!(values.len(), degree);
        assert_eq!(width, expected_width);
        let half = modulus >> 1usize;
        for value in values {
            assert!(value.abs() <= half);
            let (sign, magnitude) = value.to_bytes_le();
            assert!(magnitude.len() <= width);
            let mut encoded = [0u8; 109];
            encoded[0] = u8::from(sign == Sign::Minus);
            encoded[1..1 + magnitude.len()].copy_from_slice(&magnitude);
            self.append(&encoded[..width + 1]);
        }
        self.flush();
        self.next += 1;
        self.offset = 0;
    }
}
struct Work {
    role: Vec<u8>,
    registrations: Vec<Arc<VerifiedRegistration>>,
    retained_keys: Vec<Vec<u8>>,
    input_hashes: Vec<[u8; 64]>,
    proposal_identity: [u8; 64],
    generator: Option<Contribution>,
    proof: Option<Prover>,
    public: Option<PublicOutput>,
    next_gadget: usize,
    shares_started: bool,
    next_recipient: usize,
}
impl Work {
    fn new(proposal: &RosterProposal, position: usize) -> Result<Self, ()> {
        let role = proposal.contribution_role(position).map_err(|_| ())?;
        Ok(Self {
            registrations: proposal.records().to_vec(),
            retained_keys: Vec::new(),
            input_hashes: proposal
                .records()
                .iter()
                .map(|record| record.header().recipient_key_hash)
                .collect(),
            proposal_identity: proposal.identity(),
            generator: Some(Contribution::new()),
            proof: None,
            public: Some(PublicOutput::new(&role)),
            role,
            next_gadget: 0,
            shares_started: false,
            next_recipient: 0,
        })
    }
    fn restore(
        proof: Prover,
        proposal_identity: [u8; 64],
        retained_keys: Vec<Vec<u8>>,
        input_hashes: Vec<[u8; 64]>,
    ) -> Result<Self, ()> {
        if retained_keys.len() != 10 || input_hashes.len() != 10 {
            return Err(());
        }
        let role = proof.role().to_vec();
        Ok(Self {
            role,
            proposal_identity,
            retained_keys,
            input_hashes,
            registrations: Vec::new(),
            generator: None,
            proof: Some(proof),
            public: None,
            next_gadget: 6,
            shares_started: true,
            next_recipient: 10,
        })
    }
    fn generate(&mut self) -> Result<(), ()> {
        if self.proof.is_some() {
            return Err(());
        }
        let public = self.public.as_mut().ok_or(())?;
        let generator = self.generator.as_mut().ok_or(())?;
        if self.next_gadget < 6 {
            generator.gadget(self.next_gadget, public).map_err(|_| ())?;
            self.next_gadget += 1;
        } else if !self.shares_started {
            generator.begin_shares(public).map_err(|_| ())?;
            self.shares_started = true;
        } else if self.next_recipient < self.registrations.len() {
            self.generate_recipient()?;
        } else if self.next_recipient == 10 {
            generator.finish(public).map_err(|_| ())?;
            if public.total != statement_length() || public.next != 76 {
                return Err(());
            }
            let witness = self
                .generator
                .take()
                .unwrap()
                .into_witness()
                .map_err(|_| ())?;
            let public = self.public.take().ok_or(())?;
            self.proof = Some(
                Prover::from_generated(
                    &self.role,
                    public.hash.finalize().into(),
                    public.context.finalize().into(),
                    statement_header(),
                    witness.into_columns(),
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
        let header = statement_header();
        let half = BigInt::from_bytes_le(Sign::Plus, &header[120..140]) >> 1usize;
        let mut values = Vec::with_capacity(65536);
        for coefficient in key.chunks_exact(21) {
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
        let proof = self.proof.as_mut().ok_or(())?;
        let mut unused_output = Vec::new();
        proof
            .advance(8, index, &[], &mut unused_output)
            .map_err(|_| ())?;
        if let Some(recipient) = index
            .checked_sub(7 * self.next_gadget + 1)
            .filter(|value| value.is_multiple_of(3))
            .map(|value| value / 3)
            .filter(|value| *value < self.input_hashes.len())
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
        let values = setup_witness::contribution::common_polynomial(index).map_err(|_| ())?;
        let width = if index < 42 {
            108
        } else if index == 42 {
            20
        } else {
            5
        };
        let mut buffer = Vec::with_capacity(CHUNK);
        for value in values {
            let (sign, magnitude) = value.to_bytes_le();
            if magnitude.len() > width {
                return Err(());
            }
            let mut encoded = [0u8; 109];
            encoded[0] = u8::from(sign == Sign::Minus);
            encoded[1..1 + magnitude.len()].copy_from_slice(&magnitude);
            let mut remaining = &encoded[..width + 1];
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
        } else if self.next_gadget < 6 || !self.shares_started {
            1
        } else if self.next_recipient < 10 {
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
    roster: Option<RosterInputVerifier>,
    proposal: Option<RosterProposal>,
    stopped: bool,
    checkpoint_export: Option<first_checkpoint::Export>,
    checkpoint_import: Option<first_checkpoint::Import>,
    restore_proposal: Option<[u8; 64]>,
    restore_keys: Vec<Option<Vec<u8>>>,
}
thread_local! { static SESSION: RefCell<Session> = RefCell::new(Session { input: vec![0; 1_572_864], output: Vec::new(), work: None, roster: None, proposal: None, stopped: false, checkpoint_export: None, checkpoint_import: None, restore_proposal: None, restore_keys: Vec::new() }); }
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
#[cfg_attr(feature = "bridge", unsafe(no_mangle))]
pub extern "C" fn input_pointer() -> usize {
    SESSION.with(|state| state.borrow_mut().input.as_mut_ptr() as usize)
}
#[cfg_attr(feature = "bridge", unsafe(no_mangle))]
pub extern "C" fn roster_begin(length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        if state.stopped || state.work.is_some() || state.checkpoint_import.is_some() {
            return 1;
        }
        let Some(input) = state.input.get(..length) else {
            return 1;
        };
        let Ok(roster) = RosterInputVerifier::new(input) else {
            return 1;
        };
        state.roster = Some(roster);
        state.proposal = None;
        0
    })
}
fn roster_advance(operation: u32, length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        if state.stopped
            || state.work.is_some()
            || state.proposal.is_some()
            || state.checkpoint_import.is_some()
        {
            return 1;
        }
        let Session { input, roster, .. } = &mut *state;
        let Some(bytes) = input.get(..length) else {
            return 1;
        };
        let Some(roster) = roster.as_mut() else {
            return 1;
        };
        let result = match operation {
            0 => roster.begin_record(bytes),
            1 => roster.push_key(bytes),
            2 => roster.finish_key(),
            3 => roster.push_proof(bytes),
            4 => roster.finish_record(),
            _ => unreachable!(),
        };
        u32::from(result.is_err())
    })
}

#[cfg_attr(feature = "bridge", unsafe(no_mangle))]
pub extern "C" fn checkpoint_records() -> usize {
    first_checkpoint::record_count()
}

#[cfg_attr(feature = "bridge", unsafe(no_mangle))]
pub extern "C" fn checkpoint_command(operation: u32, position: usize, length: usize) -> u32 {
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
            restore_proposal,
            restore_keys,
            stopped,
            ..
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
                    if import.role() != role || import.input_hashes().len() != 10 {
                        return Err(());
                    }
                    *checkpoint_import = Some(import);
                    *restore_proposal = Some(proposal);
                    *restore_keys = vec![None; 10];
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
                        || restore_keys.len() != 10
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
                    *work = Some(Work::restore(
                        proof,
                        restore_proposal.take().ok_or(())?,
                        keys,
                        input_hashes,
                    )?);
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
            *restore_proposal = None;
            restore_keys.clear();
            *stopped = true;
        }
        u32::from(result.is_err())
    })
}
#[cfg_attr(feature = "bridge", unsafe(no_mangle))]
pub extern "C" fn roster_record_begin(length: usize) -> u32 {
    roster_advance(0, length)
}
#[cfg_attr(feature = "bridge", unsafe(no_mangle))]
pub extern "C" fn roster_record_key(length: usize) -> u32 {
    roster_advance(1, length)
}
#[cfg_attr(feature = "bridge", unsafe(no_mangle))]
pub extern "C" fn roster_record_key_finish() -> u32 {
    roster_advance(2, 0)
}
#[cfg_attr(feature = "bridge", unsafe(no_mangle))]
pub extern "C" fn roster_record_proof(length: usize) -> u32 {
    roster_advance(3, length)
}
#[cfg_attr(feature = "bridge", unsafe(no_mangle))]
pub extern "C" fn roster_record_finish() -> u32 {
    roster_advance(4, 0)
}
#[cfg_attr(feature = "bridge", unsafe(no_mangle))]
pub extern "C" fn roster_finish() -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        if state.stopped
            || state.work.is_some()
            || state.proposal.is_some()
            || state.checkpoint_import.is_some()
        {
            return 0;
        }
        let Some(roster) = state.roster.as_ref() else {
            return 0;
        };
        let Ok(proposal) = roster.finish() else {
            return 0;
        };
        state.proposal = Some(proposal);
        state.roster = None;
        1
    })
}
#[cfg_attr(feature = "bridge", unsafe(no_mangle))]
pub extern "C" fn proposal_identity_pointer() -> usize {
    SESSION.with(|state| {
        let state = state.borrow();
        state.work.as_ref().map_or_else(
            || {
                state
                    .proposal
                    .as_ref()
                    .map_or(0, |proposal| proposal.identity_bytes().as_ptr() as usize)
            },
            |work| work.proposal_identity.as_ptr() as usize,
        )
    })
}

#[cfg_attr(feature = "bridge", unsafe(no_mangle))]
pub extern "C" fn contribution_role_pointer() -> usize {
    SESSION.with(|state| {
        state
            .borrow()
            .work
            .as_ref()
            .map_or(0, |work| work.role.as_ptr() as usize)
    })
}
#[cfg_attr(feature = "bridge", unsafe(no_mangle))]
pub extern "C" fn contribution_role_length() -> usize {
    SESSION.with(|state| {
        state
            .borrow()
            .work
            .as_ref()
            .map_or(0, |work| work.role.len())
    })
}
#[cfg_attr(feature = "bridge", unsafe(no_mangle))]
pub extern "C" fn output_pointer() -> usize {
    SESSION.with(|state| state.borrow().output.as_ptr() as usize)
}
#[cfg_attr(feature = "bridge", unsafe(no_mangle))]
pub extern "C" fn output_length() -> usize {
    SESSION.with(|state| state.borrow().output.len())
}
#[cfg_attr(feature = "bridge", unsafe(no_mangle))]
pub extern "C" fn phase() -> u32 {
    SESSION.with(|state| state.borrow().work.as_ref().map_or(0, Work::phase))
}
#[cfg_attr(feature = "bridge", unsafe(no_mangle))]
pub extern "C" fn recipient_index() -> usize {
    SESSION.with(|state| {
        state
            .borrow()
            .work
            .as_ref()
            .map_or(0, |work| work.next_recipient)
    })
}
#[cfg_attr(feature = "bridge", unsafe(no_mangle))]
pub extern "C" fn command(operation: u32, argument: usize, length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        if state.checkpoint_export.is_some() || state.checkpoint_import.is_some() {
            return 1;
        }
        if !matches!(operation, 1 | 2 | 7..=11 | 14) || length > CHUNK {
            return 1;
        }
        if operation == 1 {
            if state.stopped || state.work.is_some() || length != 0 {
                return 1;
            }
            let Some(proposal) = state.proposal.as_ref() else {
                return 1;
            };
            let Ok(work) = Work::new(proposal, argument) else {
                return 1;
            };
            state.output.clear();
            state.work = Some(work);
            return 0;
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
#[cfg_attr(feature = "bridge", unsafe(no_mangle))]
pub extern "C" fn checkpoint_key(position: usize, length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        if state.stopped
            || state.work.is_some()
            || length != 65536 * 21
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
