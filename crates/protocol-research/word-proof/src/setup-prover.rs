use crate::{
    combination,
    field::{self, Element},
    fri::{self, Fri},
    in_memory::write_header,
    linear::{AffineSum, Challenges, LinearOracle, PreparedPolynomial},
    oracles::{FirstOracle, SecondOracle, Witness},
    public_oracle::{self, PublicMultiproof, PublicOpenings, PublicOracle, PublicOracleBuilder},
    transcript::{self, Transcript},
    tree::Multiproof,
};
use parallel_work::ProtocolHash;
use statement_stream::{
    PolynomialStream, committed_polynomial::CommittedPolynomial,
    source_linked::polynomial as setup_polynomial_stream,
};
use supported_profile::{Profile, relation::*, source_linked::relation as setup_relation};

use std::collections::VecDeque;
use zeroize::Zeroizing;

#[path = "first-oracle-checkpoint.rs"]
pub mod first_oracle_checkpoint;

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
    PublicCombination,
    PublicOpenings,
    Output,
    Done,
}
/// A step that the prover's driver runs: one unit of the proof's work, one
/// setup polynomial's begin, chunk or finish in the polynomial phase, or
/// the proof's next output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProverStep {
    Step,
    BeginPolynomial,
    PushPolynomial,
    FinishPolynomial,
    NextOutput,
}
pub struct SetupProver {
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
    public_root: [u8; 64],
    public_point: Element,
    evaluations: Vec<Element>,
    public_polynomial: Option<CommittedPolynomial>,
    public_next: usize,
    combined: Vec<Element>,
    public_builder: Option<PublicOracleBuilder>,
    public_tree: Option<PublicOracle>,
    public_openings: Option<PublicOpenings>,
    public_rows: VecDeque<(usize, Vec<u8>)>,
    public_multiproof: PublicMultiproof,
}
impl SetupProver {
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
    /// statement, whose digest the generator computed while it emitted the
    /// statement.
    pub fn from_generated(
        profile: Profile,
        role: &[u8],
        statement_digest: [u8; 64],
        public_root: [u8; 64],
        header: Vec<u8>,
        columns: Vec<Vec<u16>>,
    ) -> Result<Self, Refusal> {
        let mut columns = Zeroizing::new(columns);
        if role.is_empty() || role.len() > 1024 || header != profile.setup_statement_header() {
            return Err(Refusal::GeneratedInput);
        }
        let mut prover = Self::new(profile, role, statement_digest, public_root);
        prover.witness = Some(
            Witness::from_columns(
                &prover.relation,
                statement_digest,
                std::mem::take(&mut *columns),
            )
            .map_err(|_| Refusal::GeneratedInput)?,
        );
        prover.statement_header = header;
        let mut transcript = Transcript::new(
            role,
            transcript::context(&prover.relation, role, &statement_digest),
            prover.relation.message_bytes(),
        );
        transcript.next();
        prover.transcript = Some(transcript);
        Ok(prover)
    }
    /// Runs one prover step: only a polynomial's begin takes an argument, its
    /// index, and only its chunks take bytes.
    pub fn advance(
        &mut self,
        step: ProverStep,
        argument: usize,
        bytes: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<(), Refusal> {
        if bytes.len() > CHUNK
            || (step != ProverStep::BeginPolynomial && argument != 0)
            || (step != ProverStep::PushPolynomial && !bytes.is_empty())
        {
            return Err(Refusal::Operation);
        }
        match step {
            ProverStep::Step => self.step(),
            ProverStep::BeginPolynomial => self.begin_polynomial(argument),
            ProverStep::PushPolynomial => self.push_polynomial(bytes),
            ProverStep::FinishPolynomial => self.finish_polynomial(),
            ProverStep::NextOutput => self.next_output(output),
        }
        .map_err(|_| Refusal::Operation)
    }
    fn new(profile: Profile, role: &[u8], expected: [u8; 64], public_root: [u8; 64]) -> Self {
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
            public_root,
            public_point: field::ZERO,
            evaluations: Vec::new(),
            public_polynomial: None,
            public_next: 0,
            combined: Vec::new(),
            public_builder: None,
            public_tree: None,
            public_openings: None,
            public_rows: VecDeque::new(),
            public_multiproof: PublicMultiproof::default(),
        }
    }
    fn begin_polynomial(&mut self, index: usize) -> Result<(), ()> {
        if matches!(self.phase, Phase::PublicCombination | Phase::PublicOpenings) {
            if self.public_polynomial.is_some()
                || self.profile.committed_polynomials().get(self.public_next) != Some(&index)
            {
                return Err(());
            }
            self.public_polynomial = Some(CommittedPolynomial::new(self.profile));
            return Ok(());
        }
        if self.phase != Phase::Polynomials
            || self.polynomial.is_some()
            || self
                .affine
                .as_ref()
                .is_none_or(|affine| index != affine.next())
            || index
                >= self.profile.setup_polynomials()
                    + supported_profile::source_linked::SOURCE_POLYNOMIALS
        {
            return Err(());
        }
        let alpha = transcript::challenge(&self.transcript.as_ref().unwrap().message, 0, true);
        if self.profile.committed_polynomials().contains(&index) {
            self.public_polynomial = Some(CommittedPolynomial::new(self.profile));
        }
        self.polynomial =
            Some(setup_polynomial_stream(self.profile, index, alpha).map_err(|_| ())?);
        Ok(())
    }
    fn push_polynomial(&mut self, bytes: &[u8]) -> Result<(), ()> {
        if let Some(public) = &mut self.public_polynomial {
            public.push(bytes).map_err(|_| ())?;
        }
        if matches!(self.phase, Phase::PublicCombination | Phase::PublicOpenings) {
            return if self.public_polynomial.is_some() {
                Ok(())
            } else {
                Err(())
            };
        }
        if self.phase != Phase::Polynomials {
            return Err(());
        }
        self.polynomial
            .as_mut()
            .ok_or(())?
            .push(bytes)
            .map_err(|_| ())?;
        if self.public_polynomial.is_none() {
            self.second_pass_hash.update(bytes);
        }
        Ok(())
    }
    fn finish_polynomial(&mut self) -> Result<(), ()> {
        if matches!(self.phase, Phase::PublicCombination | Phase::PublicOpenings) {
            return self.finish_public_polynomial();
        }
        if self.phase != Phase::Polynomials {
            return Err(());
        }
        let parser = self.polynomial.take().ok_or(())?;
        if let Some(public) = self.public_polynomial.take() {
            let alpha =
                transcript::challenge(&self.transcript.as_ref().ok_or(())?.message, 0, true);
            for column in public.finish().map_err(|_| ())? {
                self.evaluations
                    .push(public_oracle::evaluate(&column, alpha));
            }
        }
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
        if affine.next() == affine.polynomials() {
            self.second_pass_hash.update(self.public_root);
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
                self.first = Some(FirstOracle::initialize(&self.relation, &self.role));
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
                    self.public_point = transcript::challenge(&transcript.message, 0, true);
                    self.affine = Some(AffineSum::begin(
                        statement_stream::source_linked::plan(self.profile, self.public_point)
                            .unwrap(),
                        witness,
                        self.first.as_ref().unwrap(),
                        Challenges {
                            alpha: transcript::challenge(&transcript.message, 0, true),
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
                let evaluations: Vec<u8> = self
                    .evaluations
                    .iter()
                    .flat_map(|value| field::encode(*value))
                    .collect();
                transcript.respond(&[&linear.tree.root(), &evaluations]);
                transcript.next();
                self.linear = Some(linear);
                self.phase = Phase::Combination;
            }
            Phase::Combination => {
                // The reciprocal table uniquely determines the earlier lookup challenge.
                let beta = field::inverse(self.inverses[0]);
                self.combined = combination::polynomial(
                    witness,
                    self.first.as_ref().unwrap(),
                    self.second.as_ref().unwrap(),
                    self.linear.as_ref().unwrap(),
                    beta,
                    &self.inverses,
                    &transcript.message,
                );
                self.public_next = 0;
                self.public_builder = Some(
                    PublicOracleBuilder::new(&self.role, self.profile.committed_columns())
                        .map_err(|_| ())?,
                );
                self.phase = Phase::PublicCombination;
            }
            _ => return Err(()),
        }
        Ok(())
    }
    fn finish_public_polynomial(&mut self) -> Result<(), ()> {
        let columns = self
            .public_polynomial
            .take()
            .ok_or(())?
            .finish()
            .map_err(|_| ())?;
        for (limb, column) in columns.iter().enumerate() {
            if self.phase == Phase::PublicCombination {
                let ordinal = self.public_next * self.profile.fhe_limbs() + limb;
                let oracle = self.relation.word_oracles() + 2 * ordinal;
                let transcript = self.transcript.as_ref().ok_or(())?;
                let weights = std::array::from_fn(|index| {
                    transcript::challenge(&transcript.message, 2 * oracle + index, false)
                });
                // The affine round's challenge is retained independently of
                // the later combination challenge.
                public_oracle::add_combination(
                    &mut self.combined,
                    column,
                    self.public_point,
                    self.evaluations[ordinal],
                    weights,
                )
                .map_err(|_| ())?;
                self.public_builder
                    .as_mut()
                    .ok_or(())?
                    .column(column)
                    .map_err(|_| ())?;
            } else {
                self.public_openings
                    .as_mut()
                    .ok_or(())?
                    .column(column)
                    .map_err(|_| ())?;
            }
        }
        self.public_next += 1;
        if self.public_next != self.profile.committed_polynomials().len() {
            return Ok(());
        }
        self.public_next = 0;
        if self.phase == Phase::PublicCombination {
            let tree = self
                .public_builder
                .take()
                .ok_or(())?
                .finish()
                .map_err(|_| ())?;
            if tree.root() != self.public_root {
                return Err(());
            }
            self.public_tree = Some(tree);
            let folding = Fri::with_first_stage(
                &self.role,
                self.relation.oracles(),
                std::mem::take(&mut self.combined),
                self.transcript.as_mut().ok_or(())?,
                4,
            );
            let indices = fri::requested(&folding.queries, EVALUATION_DOMAIN_SIZE);
            self.public_openings = Some(
                PublicOpenings::new(&indices, self.profile.committed_columns()).map_err(|_| ())?,
            );
            self.folding = Some(folding);
            self.phase = Phase::PublicOpenings;
        } else {
            self.public_rows = self
                .public_openings
                .take()
                .ok_or(())?
                .finish()
                .map_err(|_| ())?
                .into();
            self.phase = Phase::Output;
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
            output.extend(self.public_root);
            for value in &self.evaluations {
                output.extend(field::encode(*value));
            }
            return Ok(());
        }
        if self.output_stage == 4 + folding.layers.len() {
            self.phase = Phase::Done;
            return Ok(());
        }
        if self.output_stage == 3 {
            if self.rows.is_empty() {
                output.extend((self.public_rows.len() as u32).to_le_bytes());
                self.rows = std::mem::take(&mut self.public_rows);
                return Ok(());
            }
            let (index, row) = self.rows.pop_front().ok_or(())?;
            self.public_tree
                .as_ref()
                .ok_or(())?
                .write_record(&mut self.public_multiproof, index, &row, output)
                .map_err(|_| ())?;
            if self.rows.is_empty() {
                self.public_tree = None;
                self.output_stage += 1;
            }
            return Ok(());
        }
        let length = if self.output_stage < 3 {
            EVALUATION_DOMAIN_SIZE
        } else {
            EVALUATION_DOMAIN_SIZE >> (self.output_stage - 3)
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
                    let layer = &folding.layers[stage - 4];
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
            stage => &folding.layers[stage - 4].tree,
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
            Phase::PublicCombination => 12,
            Phase::PublicOpenings => 13,
            Phase::Output => 10,
            Phase::Done => 11,
        }
    }
}
#[derive(Debug)]
pub enum Refusal {
    GeneratedInput,
    Operation,
}
impl From<()> for Refusal {
    fn from(_: ()) -> Self {
        Self::Operation
    }
}
