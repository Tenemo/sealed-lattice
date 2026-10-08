use crate::{
    combination,
    field::{self, Element},
    fri::{self, Fri},
    linear::{AffineSum, Challenges, LinearOracle, PreparedPolynomial},
    one_shot::write_header,
    oracles::{FirstOracle, SecondOracle, Witness},
    transcript::{self, Transcript},
    tree::Multiproof,
};
use parallel_work::ProtocolHash;
use setup_stream_kernel::{PolynomialStream, setup_polynomial_stream};
use supported_profile::{Profile, relation::*};

use std::collections::VecDeque;
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
    polynomial: Option<PolynomialStream>,
    affine: Option<AffineSum>,
    second_pass_hash: ProtocolHash,
    linear: Option<LinearOracle>,
    folding: Option<Fri>,
    output_stage: usize,
    output_started: bool,
    // The current tree's leaves and rows that its multiproof has yet to
    // write.
    rows: VecDeque<(usize, Vec<u8>)>,
    multiproof: Multiproof,
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
        assert!(std::mem::size_of::<ProtocolHash>() <= 512);
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
            polynomial: None,
            affine: None,
            second_pass_hash: ProtocolHash::new(),
            linear: None,
            folding: None,
            output_stage: 0,
            output_started: false,
            rows: VecDeque::new(),
            multiproof: Multiproof::default(),
        }
    }
    fn begin_polynomial(&mut self, index: usize) -> Result<(), ()> {
        if self.phase != Phase::Polynomials
            || self.polynomial.is_some()
            || self
                .affine
                .as_ref()
                .is_none_or(|affine| index != affine.next())
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
        let affine = self.affine.as_mut().ok_or(())?;
        let prepared = if affine.next_is_adjoint() {
            PreparedPolynomial::Adjoint(parser.adjoint().map_err(|_| ())?)
        } else {
            PreparedPolynomial::Value(parser.finish_value().map_err(|_| ())?)
        };
        affine.polynomial(
            self.witness.as_ref().ok_or(())?,
            self.first.as_ref().ok_or(())?,
            prepared,
        );
        if affine.next() == self.profile.setup_polynomials() {
            if self.second_pass_hash.clone().finalize() != self.expected {
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
                    self.affine = Some(AffineSum::begin(
                        self.profile,
                        witness,
                        self.first.as_ref().unwrap(),
                        Challenges {
                            alpha: transcript::challenge(&transcript.message, 0, false),
                            mask: transcript::challenge(&transcript.message, 1, false),
                        },
                    ));
                    self.second_pass_hash.update(&self.statement_header);
                    self.phase = Phase::Polynomials;
                }
            }
            Phase::Linear => {
                let linear = self
                    .affine
                    .take()
                    .ok_or(())?
                    .finish(&self.role, self.second.as_ref().unwrap());
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
            let second = self.second.as_ref().unwrap();
            write_header(
                output,
                &self.relation,
                &self.expected,
                self.transcript.as_ref().unwrap(),
                [
                    self.first.as_ref().unwrap().tree.root(),
                    second.tree.root(),
                    self.linear.as_ref().unwrap().tree.root(),
                ],
                second.mask_sum,
                folding,
            );
            return Ok(());
        }
        if self.output_stage == 3 + folding.layers.len() {
            self.phase = Phase::Done;
            return Ok(());
        }
        let length = if self.output_stage < 3 {
            EVALUATION_DOMAIN_SIZE
        } else {
            EVALUATION_DOMAIN_SIZE >> (self.output_stage - 2)
        };
        if self.rows.is_empty() {
            self.multiproof = Multiproof::default();
            let indices = fri::requested(&folding.queries, length);
            let multiproof = &mut self.multiproof;
            let rows = match self.output_stage {
                0 => {
                    let first = self.first.as_ref().unwrap();
                    first.tree.opened_rows(multiproof, &indices, |leaves| {
                        first.opened_rows(self.witness.as_ref().unwrap(), leaves)
                    })
                }
                1 => {
                    let second = self.second.as_ref().unwrap();
                    second.tree.opened_rows(multiproof, &indices, |leaves| {
                        second.opened_rows(self.witness.as_ref().unwrap(), &self.inverses, leaves)
                    })
                }
                2 => {
                    let linear = self.linear.as_ref().unwrap();
                    linear
                        .tree
                        .opened_rows(multiproof, &indices, |leaves| linear.opened_rows(leaves))
                }
                stage => {
                    let layer = &folding.layers[stage - 3];
                    layer
                        .tree
                        .opened_rows(multiproof, &indices, |leaves| layer.rows(leaves))
                        .into_iter()
                        .map(Vec::from)
                        .collect()
                }
            };
            output.extend((rows.len() as u32).to_le_bytes());
            self.rows = indices.into_iter().zip(rows).collect();
            return Ok(());
        }
        let (index, row) = self.rows.pop_front().unwrap();
        let tree = match self.output_stage {
            0 => &self.first.as_ref().unwrap().tree,
            1 => &self.second.as_ref().unwrap().tree,
            2 => &self.linear.as_ref().unwrap().tree,
            stage => &folding.layers[stage - 3].tree,
        };
        tree.write_record(&mut self.multiproof, index, &row, output);
        if self.rows.is_empty() {
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
