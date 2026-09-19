use crate::{
    combination,
    field::{self, Element},
    fri::{self, Fri},
    linear::{Challenges, LinearOracle, PreparedPolynomial},
    oracles::{FirstOracle, SecondOracle, Witness},
    parameters::*,
    transcript::{self, Transcript},
};
#[cfg(feature = "bridge")]
use setup_stream_kernel::SetupStatementStream;
use setup_stream_kernel::{PolynomialStream, prover_operator_plan};
use stateful_sha3::{Digest, Sha3_512};
#[cfg(feature = "bridge")]
use std::cell::RefCell;
use std::collections::{BTreeSet, VecDeque};
#[cfg(feature = "bridge")]
use zeroize::Zeroize;
use zeroize::Zeroizing;

#[path = "first-checkpoint.rs"]
pub mod first_checkpoint;

const CHUNK: usize = 1 << 20;
#[derive(Clone, Copy, PartialEq)]
enum Phase {
    #[cfg(feature = "bridge")]
    Witness,
    #[cfg(feature = "bridge")]
    Statement,
    FirstInitialize,
    FirstColumn(usize),
    SecondInitialize,
    SecondColumn(usize),
    Polynomials,
    Linear,
    Combination,
    Output,
    Done,
}
pub struct Prover {
    role: Vec<u8>,
    expected: [u8; 64],
    phase: Phase,
    #[cfg(feature = "bridge")]
    witness_header: bool,
    #[cfg(feature = "bridge")]
    witness_bytes: usize,
    #[cfg(feature = "bridge")]
    low_byte: Option<u8>,
    #[cfg(feature = "bridge")]
    columns: Vec<Vec<u16>>,
    witness: Option<Witness>,
    #[cfg(feature = "bridge")]
    statement: Option<SetupStatementStream>,
    #[cfg(feature = "bridge")]
    context: Sha3_512,
    statement_header: Vec<u8>,
    transcript: Option<Transcript>,
    first: Option<FirstOracle>,
    second: Option<SecondOracle>,
    inverses: Vec<Element>,
    common: Vec<bool>,
    polynomial: Option<PolynomialStream>,
    polynomials: Vec<PreparedPolynomial>,
    second_pass_hash: Sha3_512,
    linear: Option<LinearOracle>,
    folding: Option<Fri>,
    output_stage: usize,
    output_started: bool,
    openings: VecDeque<Vec<u8>>,
    known: BTreeSet<usize>,
}
impl Prover {
    pub fn role(&self) -> &[u8] {
        &self.role
    }
    pub fn from_generated(
        role: &[u8],
        statement_digest: [u8; 64],
        context: [u8; 64],
        header: Vec<u8>,
        columns: Vec<Vec<u16>>,
    ) -> Result<Self, Error> {
        let mut columns = Zeroizing::new(columns);
        if role.is_empty() || role.len() > 1024 || header.len() != 145 {
            return Err(Error::GeneratedInput);
        }
        let mut control = Vec::from((role.len() as u32).to_le_bytes());
        control.extend(role);
        control.extend(statement_digest);
        let mut prover = Self::new(&control).map_err(|_| Error::GeneratedInput)?;
        prover.witness = Some(
            Witness::from_columns(statement_digest, std::mem::take(&mut *columns))
                .map_err(|_| Error::GeneratedInput)?,
        );
        prover.statement_header = header;
        let mut transcript = Transcript::new(role, context);
        transcript.next();
        prover.transcript = Some(transcript);
        prover.phase = Phase::FirstInitialize;
        Ok(prover)
    }
    pub fn advance(
        &mut self,
        operation: u32,
        argument: usize,
        bytes: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<(), Error> {
        if bytes.len() > CHUNK
            || (operation != 8 && argument != 0)
            || (operation != 9 && !bytes.is_empty())
        {
            return Err(Error::Operation);
        }
        match operation {
            7 => self.step(),
            8 => self.begin_polynomial(argument),
            9 => self.push_polynomial(bytes),
            10 => self.finish_polynomial(),
            11 => self.next_output(output),
            _ => Err(()),
        }
        .map_err(|_| Error::Operation)
    }
    fn new(bytes: &[u8]) -> Result<Self, ()> {
        assert!(std::mem::size_of::<Sha3_512>() <= 512);
        if bytes.len() < 4 {
            return Err(());
        }
        let length = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
        if length == 0 || length > 1024 || bytes.len() != 4 + length + 64 {
            return Err(());
        }
        let role = bytes[4..4 + length].to_vec();
        let expected = bytes[4 + length..].try_into().unwrap();
        #[cfg(feature = "bridge")]
        let context = transcript::context_hasher(&role);
        Ok(Self {
            role,
            expected,
            #[cfg(feature = "bridge")]
            phase: Phase::Witness,
            #[cfg(not(feature = "bridge"))]
            phase: Phase::FirstInitialize,
            #[cfg(feature = "bridge")]
            witness_header: false,
            #[cfg(feature = "bridge")]
            witness_bytes: 0,
            #[cfg(feature = "bridge")]
            low_byte: None,
            #[cfg(feature = "bridge")]
            columns: Vec::new(),
            witness: None,
            #[cfg(feature = "bridge")]
            statement: None,
            #[cfg(feature = "bridge")]
            context,
            statement_header: Vec::new(),
            transcript: None,
            first: None,
            second: None,
            inverses: Vec::new(),
            common: Vec::new(),
            polynomial: None,
            polynomials: Vec::new(),
            second_pass_hash: Sha3_512::new(),
            linear: None,
            folding: None,
            output_stage: 0,
            output_started: false,
            openings: VecDeque::new(),
            known: BTreeSet::new(),
        })
    }
    #[cfg(feature = "bridge")]
    fn witness_header(&mut self, bytes: &[u8]) -> Result<(), ()> {
        if self.phase != Phase::Witness
            || self.witness_header
            || bytes.len() != 80
            || &bytes[..4] != b"SFW1"
            || bytes[16..] != self.expected
        {
            return Err(());
        }
        for (index, value) in [SYSTEMATIC, WORDS, BOOLEANS].iter().enumerate() {
            if u32::from_le_bytes(bytes[4 + 4 * index..8 + 4 * index].try_into().unwrap()) as usize
                != *value
            {
                return Err(());
            }
        }
        self.witness_header = true;
        Ok(())
    }
    #[cfg(feature = "bridge")]
    fn push_witness(&mut self, bytes: &[u8]) -> Result<(), ()> {
        if self.phase != Phase::Witness
            || !self.witness_header
            || bytes.len() > 2 * COLUMNS * SYSTEMATIC - self.witness_bytes
        {
            return Err(());
        }
        self.witness_bytes += bytes.len();
        for byte in bytes {
            if let Some(low) = self.low_byte.take() {
                if self
                    .columns
                    .last()
                    .is_none_or(|column| column.len() == SYSTEMATIC)
                {
                    self.columns.push(Vec::with_capacity(SYSTEMATIC));
                }
                self.columns
                    .last_mut()
                    .unwrap()
                    .push(u16::from_le_bytes([low, *byte]));
            } else {
                self.low_byte = Some(*byte);
            }
        }
        Ok(())
    }
    #[cfg(feature = "bridge")]
    fn finish_witness(&mut self) -> Result<(), ()> {
        if self.phase != Phase::Witness
            || !self.witness_header
            || self.low_byte.is_some()
            || self.witness_bytes != 2 * COLUMNS * SYSTEMATIC
        {
            return Err(());
        }
        self.witness = Some(
            Witness::from_columns(self.expected, std::mem::take(&mut self.columns))
                .map_err(|_| ())?,
        );
        self.statement =
            Some(SetupStatementStream::new(self.expected, field::ZERO, &[0]).map_err(|_| ())?);
        self.phase = Phase::Statement;
        Ok(())
    }
    #[cfg(feature = "bridge")]
    fn push_statement(&mut self, bytes: &[u8]) -> Result<(), ()> {
        if self.phase != Phase::Statement {
            return Err(());
        }
        let header = bytes.len().min(145 - self.statement_header.len());
        self.statement_header.extend_from_slice(&bytes[..header]);
        self.context.update(bytes);
        self.statement
            .as_mut()
            .ok_or(())?
            .push(bytes)
            .map_err(|_| ())
    }
    #[cfg(feature = "bridge")]
    fn finish_statement(&mut self) -> Result<(), ()> {
        if self.phase != Phase::Statement {
            return Err(());
        }
        self.statement.take().ok_or(())?.finish().map_err(|_| ())?;
        self.transcript = Some(Transcript::new(
            &self.role,
            self.context.clone().finalize().into(),
        ));
        self.transcript.as_mut().unwrap().next();
        self.phase = Phase::FirstInitialize;
        Ok(())
    }
    fn begin_polynomial(&mut self, index: usize) -> Result<(), ()> {
        if self.phase != Phase::Polynomials
            || self.polynomial.is_some()
            || index != self.polynomials.len()
            || index >= 75
        {
            return Err(());
        }
        let family = if index < 42 {
            0
        } else if index < 73 {
            1
        } else {
            2
        };
        let alpha = transcript::challenge(&self.transcript.as_ref().unwrap().message, 0, false);
        self.polynomial = Some(PolynomialStream::new(family, alpha).map_err(|_| ())?);
        Ok(())
    }
    fn push_polynomial(&mut self, bytes: &[u8]) -> Result<(), ()> {
        if self.phase != Phase::Polynomials {
            return Err(());
        }
        self.polynomial
            .as_mut()
            .ok_or(())?
            .push(bytes)
            .map_err(|_| ())?;
        self.second_pass_hash.update(bytes);
        Ok(())
    }
    fn finish_polynomial(&mut self) -> Result<(), ()> {
        if self.phase != Phase::Polynomials {
            return Err(());
        }
        let parser = self.polynomial.take().ok_or(())?;
        let prepared = if self.common[self.polynomials.len()] {
            PreparedPolynomial::Adjoint(parser.adjoint().map_err(|_| ())?)
        } else {
            PreparedPolynomial::Value(parser.finish_value().map_err(|_| ())?)
        };
        self.polynomials.push(prepared);
        if self.polynomials.len() == 75 {
            if <[u8; 64]>::from(self.second_pass_hash.clone().finalize()) != self.expected {
                return Err(());
            }
            self.phase = Phase::Linear;
        }
        Ok(())
    }
    fn step(&mut self) -> Result<(), ()> {
        let witness = self.witness.as_ref().ok_or(())?;
        let transcript = self.transcript.as_mut().ok_or(())?;
        match self.phase {
            Phase::FirstInitialize => {
                self.first = Some(FirstOracle::initialize(&self.role, false));
                self.phase = Phase::FirstColumn(0);
            }
            Phase::FirstColumn(index) => {
                let first = self.first.as_mut().unwrap();
                first.commit_column(witness, index);
                if index < COLUMNS + 1 {
                    self.phase = Phase::FirstColumn(index + 1);
                } else {
                    first.finish_commitment();
                    transcript.respond(&[&first.tree.root()]);
                    transcript.next();
                    let beta = transcript::challenge(&transcript.message, 0, true);
                    self.inverses = field::batch_inverse(
                        &(0..SYSTEMATIC)
                            .map(|index| field::subtract(beta, [index as u128, 0, 0]))
                            .collect::<Vec<_>>(),
                    );
                    self.phase = Phase::SecondInitialize;
                }
            }
            Phase::SecondInitialize => {
                self.second = Some(SecondOracle::initialize(&self.role));
                self.phase = Phase::SecondColumn(0);
            }
            Phase::SecondColumn(index) => {
                let second = self.second.as_mut().unwrap();
                second.commit_column(witness, &self.inverses, index);
                if index < LOOKUPS + 1 {
                    self.phase = Phase::SecondColumn(index + 1);
                } else {
                    second.finish_commitment();
                    transcript.respond(&[&second.tree.root(), &field::encode(second.mask_sum)]);
                    transcript.next();
                    let plan =
                        prover_operator_plan(transcript::challenge(&transcript.message, 0, false))
                            .map_err(|_| ())?;
                    self.common = plan
                        .common_columns
                        .iter()
                        .map(|columns| !columns.is_empty())
                        .collect();
                    self.second_pass_hash.update(&self.statement_header);
                    self.phase = Phase::Polynomials;
                }
            }
            Phase::Linear => {
                let challenges = Challenges {
                    alpha: transcript::challenge(&transcript.message, 0, false),
                    mask: transcript::challenge(&transcript.message, 1, false),
                };
                let linear = LinearOracle::create_prepared(
                    &self.role,
                    witness,
                    self.first.as_ref().unwrap(),
                    self.second.as_ref().unwrap(),
                    challenges,
                    false,
                    std::mem::take(&mut self.polynomials).into_iter(),
                );
                transcript.respond(&[&linear.tree.root()]);
                transcript.next();
                self.linear = Some(linear);
                self.phase = Phase::Combination;
            }
            Phase::Combination => {
                // The reciprocal table uniquely determines the earlier lookup challenge.
                let beta = field::inverse(self.inverses[0]);
                let combined = combination::polynomial(
                    witness,
                    self.first.as_ref().unwrap(),
                    self.second.as_ref().unwrap(),
                    self.linear.as_ref().unwrap(),
                    beta,
                    &self.inverses,
                    &transcript.message,
                );
                self.folding = Some(Fri::create(&self.role, combined, transcript));
                self.phase = Phase::Output;
            }
            _ => return Err(()),
        }
        Ok(())
    }
    fn next_output(&mut self, output: &mut Vec<u8>) -> Result<(), ()> {
        if self.phase != Phase::Output {
            return Err(());
        }
        let folding = self.folding.as_ref().unwrap();
        if !self.output_started {
            self.output_started = true;
            let transcript = self.transcript.as_ref().unwrap();
            output.extend(b"SWP2");
            output.extend(self.expected);
            output.extend(transcript.context);
            for root in [
                self.first.as_ref().unwrap().tree.root(),
                self.second.as_ref().unwrap().tree.root(),
                self.linear.as_ref().unwrap().tree.root(),
            ] {
                output.extend(root);
            }
            output.extend(field::encode(self.second.as_ref().unwrap().mask_sum));
            for salt in &transcript.salts {
                output.extend(salt);
            }
            for layer in &folding.layers {
                output.extend(layer.tree.root());
            }
            output.extend(field::encode(folding.terminal));
            return Ok(());
        }
        if self.output_stage == 3 + folding.layers.len() {
            self.phase = Phase::Done;
            return Ok(());
        }
        let length = if self.output_stage < 3 {
            DOMAIN
        } else {
            DOMAIN >> (self.output_stage - 2)
        };
        if self.openings.is_empty() {
            self.known.clear();
            let indices = fri::requested(&folding.queries, length);
            let rows = match self.output_stage {
                0 => self
                    .first
                    .as_ref()
                    .unwrap()
                    .openings(self.witness.as_ref().unwrap(), &indices),
                1 => self.second.as_ref().unwrap().openings(
                    self.witness.as_ref().unwrap(),
                    &self.inverses,
                    &indices,
                ),
                2 => self.linear.as_ref().unwrap().openings(&indices),
                stage => {
                    let layer = &folding.layers[stage - 3];
                    indices
                        .iter()
                        .map(|index| {
                            layer
                                .tree
                                .opening(*index, &field::encode(layer.values[*index]))
                        })
                        .collect()
                }
            };
            output.extend((rows.len() as u32).to_le_bytes());
            self.openings = rows.into();
            return Ok(());
        }
        let row = self.openings.pop_front().unwrap();
        let width = match self.output_stage {
            0 => FIRST_WIDTH,
            1 => SECOND_WIDTH,
            _ => 48,
        };
        output.extend(&row[..4 + width + 128]);
        let index = u32::from_le_bytes(row[..4].try_into().unwrap()) as usize;
        let mut node = length + index;
        let mut level = 0;
        while node > 1 && !self.known.contains(&node) {
            self.known.insert(node);
            if self.known.insert(node ^ 1) {
                output
                    .extend(&row[4 + width + 128 + 64 * level..4 + width + 128 + 64 * (level + 1)]);
            }
            node /= 2;
            level += 1;
        }
        if self.openings.is_empty() {
            match self.output_stage {
                0 => self.first = None,
                1 => {
                    self.second = None;
                    self.witness = None;
                    self.inverses.clear();
                }
                2 => self.linear = None,
                _ => {}
            }
            self.output_stage += 1;
        }
        Ok(())
    }
    pub fn phase_code(&self) -> u32 {
        match self.phase {
            #[cfg(feature = "bridge")]
            Phase::Witness => 1,
            #[cfg(feature = "bridge")]
            Phase::Statement => 2,
            Phase::FirstInitialize => 3,
            Phase::FirstColumn(_) => 4,
            Phase::SecondInitialize => 5,
            Phase::SecondColumn(_) => 6,
            Phase::Polynomials => 7,
            Phase::Linear => 8,
            Phase::Combination => 9,
            Phase::Output => 10,
            Phase::Done => 11,
        }
    }
}
#[derive(Debug)]
pub enum Error {
    GeneratedInput,
    Operation,
}
impl From<()> for Error {
    fn from(_: ()) -> Self {
        Self::Operation
    }
}
#[cfg(feature = "bridge")]
impl Drop for Prover {
    fn drop(&mut self) {
        self.columns.zeroize();
    }
}
#[cfg(feature = "bridge")]
struct Session {
    input: Vec<u8>,
    output: Vec<u8>,
    prover: Option<Prover>,
    stopped: bool,
    checkpoint_export: Option<first_checkpoint::Export>,
    checkpoint_import: Option<first_checkpoint::Import>,
}
#[cfg(feature = "bridge")]
thread_local! { static SESSION: RefCell<Session> = RefCell::new(Session { input: vec![0; CHUNK], output: Vec::new(), prover: None, stopped: false, checkpoint_export: None, checkpoint_import: None }); }
#[cfg(feature = "bridge")]
#[unsafe(no_mangle)]
pub extern "C" fn input_pointer() -> usize {
    SESSION.with(|session| session.borrow_mut().input.as_mut_ptr() as usize)
}
#[cfg(feature = "bridge")]
#[unsafe(no_mangle)]
pub extern "C" fn output_pointer() -> usize {
    SESSION.with(|session| session.borrow().output.as_ptr() as usize)
}
#[cfg(feature = "bridge")]
#[unsafe(no_mangle)]
pub extern "C" fn output_length() -> usize {
    SESSION.with(|session| session.borrow().output.len())
}
#[cfg(feature = "bridge")]
#[unsafe(no_mangle)]
pub extern "C" fn phase() -> u32 {
    SESSION.with(|session| {
        session
            .borrow()
            .prover
            .as_ref()
            .map_or(0, Prover::phase_code)
    })
}
#[cfg(feature = "bridge")]
#[unsafe(no_mangle)]
pub extern "C" fn command(operation: u32, argument: usize, length: usize) -> u32 {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        if session.checkpoint_export.is_some() || session.checkpoint_import.is_some() {
            return 1;
        }
        session.output.clear();
        let Session {
            input,
            output,
            prover,
            stopped,
            ..
        } = &mut *session;
        let result = (|| {
            if *stopped {
                return Err(());
            }
            let bytes = input.get(..length).ok_or(())?;
            if operation == 1 {
                if prover.is_some() || argument != 0 {
                    return Err(());
                }
                *prover = Some(Prover::new(bytes)?);
                return Ok(());
            }
            if operation != 8 && argument != 0 {
                return Err(());
            }
            if ![2, 3, 5, 9].contains(&operation) && length != 0 {
                return Err(());
            }
            let prover = prover.as_mut().ok_or(())?;
            match operation {
                2 => prover.witness_header(bytes),
                3 => prover.push_witness(bytes),
                4 => prover.finish_witness(),
                5 => prover.push_statement(bytes),
                6 => prover.finish_statement(),
                7 => prover.step(),
                8 => prover.begin_polynomial(argument),
                9 => prover.push_polynomial(bytes),
                10 => prover.finish_polynomial(),
                11 => prover.next_output(output),
                _ => Err(()),
            }
        })();
        if result.is_err() {
            *prover = None;
            *stopped = true;
            input.zeroize();
            output.clear();
        }
        u32::from(result.is_err())
    })
}

#[cfg(feature = "bridge")]
#[unsafe(no_mangle)]
pub extern "C" fn checkpoint_records() -> usize {
    first_checkpoint::record_count()
}

#[cfg(feature = "bridge")]
#[unsafe(no_mangle)]
pub extern "C" fn checkpoint_command(operation: u32, length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        if state.stopped {
            return 1;
        }
        state.output.clear();
        let Session {
            input,
            output,
            prover,
            checkpoint_export,
            checkpoint_import,
            stopped,
        } = &mut *state;
        let result = (|| {
            let bytes = input.get(..length).ok_or(())?;
            match operation {
                1 if length == 0 && checkpoint_export.is_none() && checkpoint_import.is_none() => {
                    let export = first_checkpoint::Export::begin(prover.as_ref().ok_or(())?)
                        .map_err(|_| ())?;
                    *output = export.header();
                    *checkpoint_export = Some(export);
                }
                2 if length == 32 => {
                    let key = Zeroizing::new(<[u8; 32]>::try_from(bytes).unwrap());
                    *output = checkpoint_export
                        .as_mut()
                        .ok_or(())?
                        .seal(prover.as_ref().ok_or(())?, &key)
                        .map_err(|_| ())?;
                }
                3 if length == 0 => {
                    if !checkpoint_export.as_ref().ok_or(())?.complete() {
                        return Err(());
                    }
                    *checkpoint_export = None;
                }
                4 if prover.is_none()
                    && checkpoint_export.is_none()
                    && checkpoint_import.is_none() =>
                {
                    *checkpoint_import =
                        Some(first_checkpoint::Import::begin(bytes).map_err(|_| ())?);
                }
                5 if (48..=32 + first_checkpoint::RECORD_BYTES + 16).contains(&length) => {
                    let key = Zeroizing::new(<[u8; 32]>::try_from(&bytes[..32]).unwrap());
                    checkpoint_import
                        .as_mut()
                        .ok_or(())?
                        .open(&key, &bytes[32..])
                        .map_err(|_| ())?;
                }
                6 if length == 0 => {
                    if !checkpoint_import.as_ref().ok_or(())?.complete() {
                        return Err(());
                    }
                    *prover = Some(checkpoint_import.take().unwrap().finish().map_err(|_| ())?);
                }
                _ => return Err(()),
            }
            Ok(())
        })();
        input[..length.min(CHUNK)].zeroize();
        if result.is_err()
            && (operation == 5
                || (operation == 6 && prover.is_none() && checkpoint_import.is_none()))
        {
            *checkpoint_import = None;
            *stopped = true;
        }
        u32::from(result.is_err())
    })
}
