//! The participant's contribution proof: its generation from the verified
//! proposal, its proof rounds and its sealed checkpoints.
use num_bigint::{BigInt, Sign};
use num_traits::Zero;
use parallel_work::ProtocolHash;
use parallel_work::{HashStream, Sponge, sealing};
use protocol_foundations::{
    registration::{KEY_BYTES, VerifiedRegistration},
    roster::{RetainedContributionContext, RosterProposal},
};
use setup_witness::{
    PolynomialOutput,
    contribution::{Contribution, common_records},
};

use std::sync::Arc;
use supported_profile::{DEGREE, Profile, relation::setup_relation, share_modulus};
use word_proof::{
    bridge::{Prover, first_checkpoint},
    transcript::context_stream,
};
use zeroize::Zeroize;

const CHUNK: usize = 1 << 20;
/// The input buffer: one polynomial chunk, one checkpoint import context,
/// or one checkpoint record with its key.
pub const CONTRIBUTION_INPUT_BYTES: usize = 1_572_864;
const _: () = assert!(
    sealing::KEY_BYTES + first_checkpoint::RECORD_BYTES + sealing::TAG_BYTES
        <= CONTRIBUTION_INPUT_BYTES
);
/// A refused contribution step.
#[derive(Debug)]
pub struct Refused;
/// The host's receipt of one chunk of a public setup object at an
/// offset: object zero is the statement header and object i + 1 setup
/// polynomial i.
pub type PublicChunk = fn(object: usize, offset: usize, bytes: &[u8]);
struct PublicOutput {
    profile: Profile,
    // The statement's digest and context, which helpers hash when there are
    // helpers.
    hash: HashStream,
    context: HashStream,
    next: usize,
    total: usize,
    offset: usize,
    buffer: Vec<u8>,
    public_chunk: PublicChunk,
}
impl PublicOutput {
    fn new(profile: Profile, role: &[u8], public_chunk: PublicChunk) -> Self {
        let mut output = Self {
            profile,
            hash: HashStream::new(Sponge::ProtocolHash),
            context: context_stream(&setup_relation(profile), role),
            next: 0,
            total: 0,
            offset: 0,
            buffer: Vec::with_capacity(CHUNK),
            public_chunk,
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
        // Only canonical public polynomial/header bytes cross this callback.
        (self.public_chunk)(self.next, self.offset, &self.buffer);
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
            assert!(value.magnitude() <= half.magnitude());
            setup_witness::encode_coefficient(value, &mut encoded);
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
    fn new(
        proposal: &RosterProposal,
        position: usize,
        source: setup_witness::fhe_key_source::FheKeySource,
        public_chunk: PublicChunk,
    ) -> Result<Self, ()> {
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
            generator: Some(Contribution::from_source(profile, source).map_err(|_| ())?),
            proof: None,
            public: Some(PublicOutput::new(profile, &role, public_chunk)),
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
            generator.finish().map_err(|_| ())?;
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
                    public.hash.finish(),
                    public.context.finish(),
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
        if ProtocolHash::digest(key) != record.header().recipient_key_hash {
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
        for chunk in common_records(profile, index)
            .map_err(|_| ())?
            .chunks(CHUNK)
        {
            proof
                .advance(9, 0, chunk, &mut unused_output)
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
/// The participant's contribution proof, from the verified proposal or
/// from an imported checkpoint. A failed proof step, a checkpoint record that
/// does not open and the retirement each stop it.
pub struct ContributionSession {
    input: Vec<u8>,
    output: Vec<u8>,
    work: Option<Work>,
    stopped: bool,
    checkpoint_export: Option<first_checkpoint::Export>,
    checkpoint_import: Option<first_checkpoint::Import>,
    restore_keys: Vec<Option<Vec<u8>>>,
    public_chunk: PublicChunk,
}
impl ContributionSession {
    pub fn new(public_chunk: PublicChunk) -> Self {
        Self {
            input: vec![0; CONTRIBUTION_INPUT_BYTES],
            output: Vec::new(),
            work: None,
            stopped: false,
            checkpoint_export: None,
            checkpoint_import: None,
            restore_keys: Vec::new(),
            public_chunk,
        }
    }
    /// Initializes an embedded prover from the owning verifier's immutable proposal.
    /// The participant worker persists its one-shot intent before invoking this.
    pub fn begin_verified(
        &mut self,
        proposal: &RosterProposal,
        position: usize,
        source: setup_witness::fhe_key_source::FheKeySource,
    ) -> Result<(), protocol_foundations::Error> {
        use protocol_foundations::Error;
        if self.stopped
            || self.work.is_some()
            || self.checkpoint_import.is_some()
            || self.checkpoint_export.is_some()
        {
            return Err(Error::Consumed);
        }
        let work =
            Work::new(proposal, position, source, self.public_chunk).map_err(|_| Error::Context)?;
        self.output.clear();
        self.work = Some(work);
        Ok(())
    }
    pub fn input(&mut self) -> &mut [u8] {
        &mut self.input
    }
    /// Records of the checkpoint being imported, or else of the running proof's
    /// checkpoint.
    pub fn checkpoint_records(&self) -> usize {
        self.checkpoint_import
            .as_ref()
            .map(first_checkpoint::Import::relation)
            .or_else(|| {
                self.work
                    .as_ref()
                    .and_then(|work| work.proof.as_ref())
                    .map(Prover::relation)
            })
            .map_or(0, first_checkpoint::record_count)
    }
    pub fn checkpoint_command(
        &mut self,
        operation: u32,
        position: usize,
        length: usize,
        retained: &RetainedContributionContext,
    ) -> Result<(), Refused> {
        if self.stopped || (operation != 4 && position != 0) {
            return Err(Refused);
        }
        // The previous output may hold a checkpoint record's key.
        self.output.zeroize();
        let Self {
            input,
            output,
            work,
            checkpoint_export,
            checkpoint_import,
            restore_keys,
            stopped,
            ..
        } = self;
        let result = (|| {
            let bytes = input.get(..length).ok_or(())?;
            match operation {
                1 if length == 0 && checkpoint_export.is_none() && checkpoint_import.is_none() => {
                    let work = work.as_mut().ok_or(())?;
                    let export = first_checkpoint::Export::begin_with_inputs(
                        work.proof.as_mut().ok_or(())?,
                        &work.input_hashes,
                    )
                    .map_err(|_| ())?;
                    *output = export.header();
                    *checkpoint_export = Some(export);
                }
                // The record follows the fresh key it is sealed under.
                2 if length == 0 => {
                    let proof = work
                        .as_mut()
                        .and_then(|work| work.proof.as_mut())
                        .ok_or(())?;
                    let sealed = checkpoint_export
                        .as_mut()
                        .ok_or(())?
                        .seal(proof)
                        .map_err(|_| ())?;
                    *output = [sealed.key.as_slice(), &sealed.bytes].concat();
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
                    let import =
                        crate::import_checkpoint(retained, position, bytes).map_err(|_| ())?;
                    let participants = import.profile().participants();
                    *checkpoint_import = Some(import);
                    *restore_keys = vec![None; participants];
                }
                5 if (sealing::KEY_BYTES + sealing::TAG_BYTES
                    ..=sealing::KEY_BYTES
                        + first_checkpoint::RECORD_BYTES
                        + sealing::TAG_BYTES)
                    .contains(&length) =>
                {
                    let key = zeroize::Zeroizing::new(
                        <[u8; sealing::KEY_BYTES]>::try_from(&bytes[..sealing::KEY_BYTES]).unwrap(),
                    );
                    checkpoint_import
                        .as_mut()
                        .ok_or(())?
                        .open(&key, &bytes[sealing::KEY_BYTES..])
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
        result.map_err(|()| Refused)
    }
    pub fn output(&self) -> &[u8] {
        &self.output
    }
    pub fn phase(&self) -> u32 {
        self.work.as_ref().map_or(0, Work::phase)
    }
    /// Drops the completed private source/proof state after the enrollment owner
    /// has verified setup and the participant root has retired its dependencies.
    pub fn retire(&mut self) {
        self.work = None;
        self.checkpoint_export = None;
        self.checkpoint_import = None;
        self.restore_keys.clear();
        self.input.zeroize();
        self.output.zeroize();
        self.output.clear();
        self.stopped = true;
    }
    pub fn command(
        &mut self,
        operation: u32,
        argument: usize,
        length: usize,
    ) -> Result<(), Refused> {
        if self.checkpoint_export.is_some() || self.checkpoint_import.is_some() {
            return Err(Refused);
        }
        if !matches!(operation, 2 | 7..=11 | 14) || length > CHUNK {
            return Err(Refused);
        }
        self.output.clear();
        let Self {
            input,
            output,
            work,
            stopped,
            ..
        } = self;
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
        result.map_err(|()| Refused)
    }
    pub fn checkpoint_key(&mut self, position: usize, length: usize) -> Result<(), Refused> {
        if self.stopped
            || self.work.is_some()
            || length != KEY_BYTES
            || position >= self.restore_keys.len()
            || self.restore_keys[position].is_some()
        {
            return Err(Refused);
        }
        let Some(import) = self.checkpoint_import.as_ref() else {
            return Err(Refused);
        };
        let Some(expected) = import.input_hashes().get(position) else {
            return Err(Refused);
        };
        let Some(bytes) = self.input.get(..length) else {
            return Err(Refused);
        };
        if ProtocolHash::digest(bytes) != *expected {
            return Err(Refused);
        }
        let key = bytes.to_vec();
        self.restore_keys[position] = Some(key);
        Ok(())
    }
}
