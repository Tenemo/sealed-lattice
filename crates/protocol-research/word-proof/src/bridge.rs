use crate::{
    combination,
    field::{self, Element},
    fri::{self, Fri},
    linear::{Challenges, LinearOracle, PreparedPolynomial},
    oracles::{FirstOracle, SecondOracle, Witness},
    parameters::*,
    transcript::{self, Transcript},
};
use setup_stream_kernel::{PolynomialStream, prover_operator_plan, setup_polynomial_stream};
use stateful_sha3::{Digest, Sha3_512};
use std::collections::{BTreeSet, VecDeque};
use supported_profile::Profile;
use zeroize::Zeroizing;

#[path = "first-checkpoint.rs"]
pub mod first_checkpoint;

const CHUNK: usize = 1 << 20;
#[derive(Clone, Copy, PartialEq)]
enum Phase {
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
    profile: Profile,
    relation: Relation,
    role: Vec<u8>,
    expected: [u8; 64],
    phase: Phase,
    witness: Option<Witness>,
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
    pub fn profile(&self) -> Profile {
        self.profile
    }
    pub fn role(&self) -> &[u8] {
        &self.role
    }
    pub fn relation(&self) -> &Relation {
        &self.relation
    }
    /// Starts a proof of generated witness columns for the profile's setup
    /// statement, whose digest and context the generator computed while it
    /// emitted the statement.
    pub fn from_generated(
        profile: Profile,
        role: &[u8],
        statement_digest: [u8; 64],
        context: [u8; 64],
        header: Vec<u8>,
        columns: Vec<Vec<u16>>,
    ) -> Result<Self, Error> {
        let mut columns = Zeroizing::new(columns);
        if role.is_empty() || role.len() > 1024 || header != profile.setup_statement_header() {
            return Err(Error::GeneratedInput);
        }
        let mut prover = Self::new(profile, role, statement_digest);
        prover.witness = Some(
            Witness::from_columns(
                &prover.relation,
                statement_digest,
                std::mem::take(&mut *columns),
            )
            .map_err(|_| Error::GeneratedInput)?,
        );
        prover.statement_header = header;
        let mut transcript = Transcript::new(role, context, prover.relation.message_bytes());
        transcript.next();
        prover.transcript = Some(transcript);
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
    fn new(profile: Profile, role: &[u8], expected: [u8; 64]) -> Self {
        assert!(std::mem::size_of::<Sha3_512>() <= 512);
        Self {
            profile,
            relation: setup_relation(profile),
            role: role.to_vec(),
            expected,
            phase: Phase::FirstInitialize,
            witness: None,
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
        }
    }
    fn begin_polynomial(&mut self, index: usize) -> Result<(), ()> {
        if self.phase != Phase::Polynomials
            || self.polynomial.is_some()
            || index != self.polynomials.len()
            || index >= self.profile.setup_polynomials()
        {
            return Err(());
        }
        let alpha = transcript::challenge(&self.transcript.as_ref().unwrap().message, 0, false);
        self.polynomial =
            Some(setup_polynomial_stream(self.profile, index, alpha).map_err(|_| ())?);
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
        if self.polynomials.len() == self.profile.setup_polynomials() {
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
                self.first = Some(FirstOracle::initialize(&self.relation, &self.role, false));
                self.phase = Phase::FirstColumn(0);
            }
            Phase::FirstColumn(index) => {
                let first = self.first.as_mut().unwrap();
                first.commit_column(witness, index);
                if index < self.relation.columns() + 1 {
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
                self.second = Some(SecondOracle::initialize(&self.relation, &self.role));
                self.phase = Phase::SecondColumn(0);
            }
            Phase::SecondColumn(index) => {
                let second = self.second.as_mut().unwrap();
                second.commit_column(witness, &self.inverses, index);
                if index < self.relation.lookups() + 1 {
                    self.phase = Phase::SecondColumn(index + 1);
                } else {
                    second.finish_commitment();
                    transcript.respond(&[&second.tree.root(), &field::encode(second.mask_sum)]);
                    transcript.next();
                    let plan = prover_operator_plan(
                        self.profile,
                        transcript::challenge(&transcript.message, 0, false),
                    )
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
                    self.profile,
                    &self.role,
                    witness,
                    self.first.as_ref().unwrap(),
                    self.second.as_ref().unwrap(),
                    challenges,
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
                self.folding = Some(Fri::create(
                    &self.role,
                    self.relation.oracles(),
                    combined,
                    transcript,
                ));
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
            output.extend(self.relation.proof_magic);
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
            0 => self.relation.first_width(),
            1 => self.relation.second_width(),
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
