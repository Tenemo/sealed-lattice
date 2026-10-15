//! The participant's contribution proof: its generation from the verified
//! proposal, its proof rounds and its sealed checkpoints.
use num_bigint::BigInt;
use parallel_work::ProtocolHash;
use parallel_work::{HashStream, Sponge, sealing};
use protocol_foundations::{
    registration::{KEY_BYTES, VerifiedRegistration},
    roster::{RetainedContributionContext, RosterProposal},
};
use setup_witness::{
    PolynomialOutput, contribution::common_records, encrypted_source::LinkedContribution,
};

use statement_stream::coefficient::{self, CenteredCodec};
use statement_stream::committed_polynomial::CommittedPolynomial;
use std::sync::Arc;
use supported_profile::{Profile, share_modulus, source_linked::relation as setup_relation};
use word_proof::public_oracle::PublicOracleBuilder;
use word_proof::setup_prover::{ProverStep, SetupProver, first_oracle_checkpoint};
use zeroize::Zeroize;

const CHUNK: usize = 1 << 20;
/// The input buffer: one polynomial chunk, one checkpoint import context,
/// or one checkpoint record with its key.
pub const CONTRIBUTION_INPUT_BYTES: usize = 1_572_864;
const _: () = assert!(
    sealing::KEY_BYTES + first_oracle_checkpoint::RECORD_BYTES + sealing::TAG_BYTES
        <= CONTRIBUTION_INPUT_BYTES
);
/// The refusal of a contribution step.
#[derive(Debug)]
pub struct Refusal;
protocol_foundations::operation_codes! {
    /// The contribution proof's commands.
    pub enum ProverOperation {
        Generate = 2,
        Step = 7,
        BeginPolynomial = 8,
        PushPolynomial = 9,
        FinishPolynomial = 10,
        NextOutput = 11,
        ConsumePredecessor = 14,
    }
}
impl ProverOperation {
    // The prover step that the command runs, when it runs one.
    fn prover_step(self) -> Option<ProverStep> {
        match self {
            Self::Step => Some(ProverStep::Step),
            Self::BeginPolynomial => Some(ProverStep::BeginPolynomial),
            Self::PushPolynomial => Some(ProverStep::PushPolynomial),
            Self::FinishPolynomial => Some(ProverStep::FinishPolynomial),
            Self::NextOutput => Some(ProverStep::NextOutput),
            Self::Generate | Self::ConsumePredecessor => None,
        }
    }
}
protocol_foundations::operation_codes! {
    /// The contribution checkpoint's commands.
    enum CheckpointOperation {
        ExportHeader = 1,
        Seal = 2,
        Complete = 3,
        Import = 4,
        Open = 5,
        Finish = 6,
    }
}
/// The host's receipt of one chunk of a public setup object at an
/// offset: object zero is the statement header and object i + 1 setup
/// polynomial i.
pub type PublicChunk = Box<dyn FnMut(usize, usize, &[u8])>;

/// Opens only the public checkpoint header under the original owner's
/// retained context. The importer still authenticates every sealed record
/// and recipient key before restoring the unfinished proof.
pub fn import_checkpoint(
    context: &RetainedContributionContext,
    position: usize,
    bytes: &[u8],
) -> Result<first_oracle_checkpoint::Import, word_proof::setup_prover::Refusal> {
    use word_proof::setup_prover::Refusal as ProverRefusal;
    let prefix = bytes.get(..128).ok_or(ProverRefusal::Operation)?;
    let import = first_oracle_checkpoint::Import::begin(&bytes[128..])?;
    let expected = context
        .checkpoint_role(prefix, position, import.profile())
        .map_err(|_| ProverRefusal::Operation)?;
    if import.role() != expected {
        return Err(ProverRefusal::Operation);
    }
    Ok(import)
}

/// The longest checkpoint header of a profile's contribution and each of its
/// sealed checkpoint records' lengths, in record order.
pub fn checkpoint_layout(profile: Profile) -> (usize, Vec<usize>) {
    (
        first_oracle_checkpoint::maximum_header_bytes(profile),
        first_oracle_checkpoint::record_lengths(&setup_relation(profile)),
    )
}

struct PublicOutput {
    profile: Profile,
    // The statement's digest, which a helper hashes when there are helpers.
    hash: HashStream,
    next: usize,
    total: usize,
    offset: usize,
    buffer: Vec<u8>,
    public_chunk: PublicChunk,
    oracle: PublicOracleBuilder,
}
impl PublicOutput {
    fn new(profile: Profile, role: &[u8], public_chunk: PublicChunk) -> Self {
        let mut output = Self {
            profile,
            hash: HashStream::new(Sponge::ProtocolHash),
            next: 0,
            total: 0,
            offset: 0,
            buffer: Vec::with_capacity(CHUNK),
            public_chunk,
            oracle: PublicOracleBuilder::new(role, profile.committed_columns())
                .expect("The verified contribution role and profile fit the oracle"),
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
        if self.next == 0
            || !self
                .profile
                .committed_polynomials()
                .contains(&(self.next - 1))
        {
            self.hash.update(&self.buffer);
        }
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
        let mut committed = self
            .profile
            .committed_polynomials()
            .contains(&(self.next - 1))
            .then(|| CommittedPolynomial::new(self.profile));
        for value in values {
            assert!(value.magnitude() <= half.magnitude());
            coefficient::encode(value, &mut encoded);
            if let Some(committed) = &mut committed {
                committed
                    .push(&encoded)
                    .expect("Generated FHE coefficients are canonical");
            }
            self.append(&encoded);
        }
        self.flush();
        if let Some(committed) = committed {
            for column in committed
                .finish()
                .expect("The generator emits one complete polynomial")
            {
                self.oracle
                    .column(&column)
                    .expect("Generated columns have the profile's degree");
            }
        }
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
    generator: Option<LinkedContribution>,
    proof: Option<SetupProver>,
    public: Option<PublicOutput>,
    next_gadget: usize,
    shares_started: bool,
    next_recipient: usize,
}
impl Work {
    fn new(
        proposal: &RosterProposal,
        position: usize,
        source: LinkedContribution,
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
            generator: Some(source),
            proof: None,
            public: None,
            role,
            next_gadget: 0,
            shares_started: false,
            next_recipient: 0,
        })
    }
    fn restore(
        proof: SetupProver,
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
            for record in generator.public().records().map_err(|_| ())? {
                public.append(&record);
                public.flush();
                public.next += 1;
                public.offset = 0;
            }
            let columns = self
                .generator
                .take()
                .unwrap()
                .into_columns()
                .map_err(|_| ())?;
            let mut public = self.public.take().ok_or(())?;
            let public_root = public.oracle.finish().map_err(|_| ())?.root();
            public.hash.update(&public_root);
            self.proof = Some(
                SetupProver::from_generated(
                    profile,
                    &self.role,
                    public.hash.finish(),
                    public_root,
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
        if !self.shares_started || self.proof.is_some() {
            return Err(());
        }
        let values = recipient_key_values(record);
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
            .advance(ProverStep::BeginPolynomial, index, &[], &mut unused_output)
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
                    .advance(ProverStep::PushPolynomial, 0, bytes, &mut unused_output)
                    .map_err(|_| ())?;
            }
            return proof
                .advance(ProverStep::FinishPolynomial, 0, &[], &mut unused_output)
                .map_err(|_| ());
        }
        for chunk in common_records(profile, index)
            .map_err(|_| ())?
            .chunks(CHUNK)
        {
            proof
                .advance(ProverStep::PushPolynomial, 0, chunk, &mut unused_output)
                .map_err(|_| ())?;
        }
        proof
            .advance(ProverStep::FinishPolynomial, 0, &[], &mut unused_output)
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
/// The share coefficients of a roster member's recipient key, whose committed
/// hash and canonical coefficients its registration's verifier checked.
pub fn recipient_key_values(record: &VerifiedRegistration) -> Vec<BigInt> {
    CenteredCodec::new(share_modulus())
        .decode_all(record.public_key())
        .expect("A verified recipient key is canonical.")
}
/// The participant's contribution proof, from the verified proposal or
/// from an imported checkpoint. A failed proof step, a checkpoint record that
/// does not open and the retirement each stop it.
pub struct ContributionSession {
    input: Vec<u8>,
    output: Vec<u8>,
    work: Option<Work>,
    stopped: bool,
    checkpoint_export: Option<first_oracle_checkpoint::Export>,
    checkpoint_import: Option<first_oracle_checkpoint::Import>,
    restore_keys: Vec<Option<Vec<u8>>>,
    // The receiver of the public setup objects, until generation begins.
    public_chunk: Option<PublicChunk>,
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
            public_chunk: Some(public_chunk),
        }
    }
    /// Initializes an embedded prover from the owning verifier's immutable proposal.
    /// The participant worker persists its one-shot intent before invoking this.
    pub fn begin_verified(
        &mut self,
        proposal: &RosterProposal,
        position: usize,
        source: LinkedContribution,
    ) -> Result<(), protocol_foundations::Refusal> {
        use protocol_foundations::Refusal as FoundationRefusal;
        if self.stopped
            || self.work.is_some()
            || self.public_chunk.is_none()
            || self.checkpoint_import.is_some()
            || self.checkpoint_export.is_some()
        {
            return Err(FoundationRefusal::Consumed);
        }
        let mut work =
            Work::new(proposal, position, source).map_err(|_| FoundationRefusal::Context)?;
        let public_chunk = self
            .public_chunk
            .take()
            .ok_or(FoundationRefusal::Consumed)?;
        work.public = Some(PublicOutput::new(work.profile, &work.role, public_chunk));
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
            .map(first_oracle_checkpoint::Import::relation)
            .or_else(|| {
                self.work
                    .as_ref()
                    .and_then(|work| work.proof.as_ref())
                    .map(SetupProver::relation)
            })
            .map_or(0, first_oracle_checkpoint::record_count)
    }
    pub fn checkpoint_command(
        &mut self,
        operation: u32,
        position: usize,
        length: usize,
        retained: &RetainedContributionContext,
    ) -> Result<(), Refusal> {
        let operation = CheckpointOperation::from_code(operation);
        if self.stopped || (operation != Some(CheckpointOperation::Import) && position != 0) {
            return Err(Refusal);
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
                Some(CheckpointOperation::ExportHeader)
                    if length == 0
                        && checkpoint_export.is_none()
                        && checkpoint_import.is_none() =>
                {
                    let work = work.as_mut().ok_or(())?;
                    let export = first_oracle_checkpoint::Export::begin_with_inputs(
                        work.proof.as_mut().ok_or(())?,
                        &work.input_hashes,
                    )
                    .map_err(|_| ())?;
                    *output = export.header();
                    *checkpoint_export = Some(export);
                }
                // The record follows the fresh key it is sealed under.
                Some(CheckpointOperation::Seal) if length == 0 => {
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
                Some(CheckpointOperation::Complete) if length == 0 => {
                    if !checkpoint_export.as_ref().ok_or(())?.complete() {
                        return Err(());
                    }
                    *checkpoint_export = None;
                }
                Some(CheckpointOperation::Import)
                    if work.is_none()
                        && checkpoint_export.is_none()
                        && checkpoint_import.is_none() =>
                {
                    let import = import_checkpoint(retained, position, bytes).map_err(|_| ())?;
                    let participants = import.profile().participants();
                    *checkpoint_import = Some(import);
                    *restore_keys = vec![None; participants];
                }
                Some(CheckpointOperation::Open)
                    if (sealing::KEY_BYTES + sealing::TAG_BYTES
                        ..=sealing::KEY_BYTES
                            + first_oracle_checkpoint::RECORD_BYTES
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
                Some(CheckpointOperation::Finish) if length == 0 => {
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
            && (operation == Some(CheckpointOperation::Open)
                || (operation == Some(CheckpointOperation::Finish)
                    && work.is_none()
                    && checkpoint_import.is_none()))
        {
            *checkpoint_import = None;
            restore_keys.clear();
            *stopped = true;
        }
        result.map_err(|()| Refusal)
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
    pub fn command(&mut self, code: u32, argument: usize, length: usize) -> Result<(), Refusal> {
        self.advance(
            ProverOperation::from_code(code).ok_or(Refusal)?,
            argument,
            length,
        )
    }
    /// Runs a proof command over the first `length` input bytes. A command
    /// that fails once it runs stops the session.
    pub fn advance(
        &mut self,
        operation: ProverOperation,
        argument: usize,
        length: usize,
    ) -> Result<(), Refusal> {
        if self.checkpoint_export.is_some() || self.checkpoint_import.is_some() {
            return Err(Refusal);
        }
        if length > CHUNK {
            return Err(Refusal);
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
                ProverOperation::Generate if length == 0 && argument == 0 => work.generate(),
                ProverOperation::ConsumePredecessor if length == 0 => {
                    work.consume_predecessor(argument)
                }
                operation => {
                    let step = operation.prover_step().ok_or(())?;
                    work.proof
                        .as_mut()
                        .ok_or(())?
                        .advance(step, argument, bytes, output)
                        .map_err(|_| ())
                }
            }
        })();
        if result.is_err() {
            *work = None;
            *stopped = true;
            input.zeroize();
            output.clear();
        }
        result.map_err(|()| Refusal)
    }
    pub fn checkpoint_key(&mut self, position: usize, length: usize) -> Result<(), Refusal> {
        if self.stopped
            || self.work.is_some()
            || length != KEY_BYTES
            || position >= self.restore_keys.len()
            || self.restore_keys[position].is_some()
        {
            return Err(Refusal);
        }
        let Some(import) = self.checkpoint_import.as_ref() else {
            return Err(Refusal);
        };
        let Some(expected) = import.input_hashes().get(position) else {
            return Err(Refusal);
        };
        let Some(bytes) = self.input.get(..length) else {
            return Err(Refusal);
        };
        if ProtocolHash::digest(bytes) != *expected {
            return Err(Refusal);
        }
        let key = bytes.to_vec();
        self.restore_keys[position] = Some(key);
        Ok(())
    }
}
