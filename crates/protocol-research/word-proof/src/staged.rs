//! Incremental orchestration of the unchanged word engine. Yielding between
//! calls retains the same proof randomness cursor and transcript. Only the
//! current tree's openings and one bounded serialized chunk are queued.
use crate::{
    affine::Operator,
    combination,
    field::{self, Element},
    fri::{self, Fri},
    linear_oracle::LinearOracle,
    oracles::{FirstOracle, SecondOracle, Witness},
    parameters::{DOMAIN, SYSTEMATIC},
    transcript::{self, Transcript},
    tree::{Multiproof, SALT_BYTES},
};
use parallel_work::ProtocolHash;
use std::collections::VecDeque;
use supported_profile::relation::Relation;
use zeroize::Zeroizing;

pub const OUTPUT_BYTES: usize = 1 << 20;
pub const OUTPUT_PHASE: u32 = 12;
pub const DONE_PHASE: u32 = 13;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Context,
    Stage,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    FirstInitialize,
    FirstColumn(usize),
    FirstFinish,
    Inverses,
    SecondInitialize,
    SecondColumn(usize),
    SecondFinish,
    Operator,
    Linear,
    Combination,
    Folding,
    Output,
    Done,
}
// The test-only random stream belongs to the entire prover, not a single
// call. A second prover cannot interleave draws in the same thread.
struct Replay;
impl Drop for Replay {
    fn drop(&mut self) {
        crate::random::REPLAYED.with(|state| state.set(None));
    }
}
/// The actual public operands of one bounded affine relation. The adapter
/// supplies canonical bytes and the same operator the owning verifier uses.
pub trait AffineStatement {
    /// The caller's already derived proof role. The controller captures it
    /// once before the first challenge and retains it after dropping the
    /// public operands; an adapter cannot change a later oracle's role.
    fn role(&self) -> &[u8];
    fn relation(&self) -> Relation;
    fn encode(&self) -> Result<Vec<u8>, Error>;
    fn operator(&self, alpha: Element) -> Result<Operator, Error>;
}
pub struct Prover<S> {
    statement: Option<S>,
    statement_digest: [u8; 64],
    relation: Relation,
    phase: Phase,
    witness: Option<Witness>,
    transcript: Transcript,
    first: Option<FirstOracle>,
    second: Option<SecondOracle>,
    inverses: Vec<Element>,
    operator: Option<Operator>,
    linear: Option<LinearOracle>,
    combination: Option<Zeroizing<Vec<Element>>>,
    folding: Option<Fri>,
    false_affine: bool,
    output: Vec<u8>,
    header_emitted: bool,
    output_stage: usize,
    rows: VecDeque<(usize, Vec<u8>)>,
    multiproof: Multiproof,
    _replay: Replay,
}
impl<S: AffineStatement> Prover<S> {
    pub fn new(
        statement: S,
        witness: Witness,
        seed: u64,
        false_affine: bool,
    ) -> Result<Self, Error> {
        if crate::random::REPLAYED.with(|state| state.get().is_some()) {
            return Err(Error::Stage);
        }
        let relation = statement.relation();
        let bytes = statement.encode()?;
        let mut digest = ProtocolHash::new();
        digest.update(&bytes);
        let statement_digest = digest.finalize();
        if witness.relation != relation || witness.statement != statement_digest {
            return Err(Error::Context);
        }
        let role = statement.role();
        let mut hash = transcript::context_hasher(&relation, role);
        hash.update(&bytes);
        let mut transcript = Transcript::new(role, hash.finalize(), relation.message_bytes());
        transcript.next();
        let output = Vec::with_capacity(OUTPUT_BYTES);
        crate::random::REPLAYED.with(|state| state.set(Some(seed)));
        Ok(Self {
            statement: Some(statement),
            statement_digest,
            relation,
            phase: Phase::FirstInitialize,
            witness: Some(witness),
            transcript,
            first: None,
            second: None,
            inverses: Vec::new(),
            operator: None,
            linear: None,
            combination: None,
            folding: None,
            false_affine,
            output,
            header_emitted: false,
            output_stage: 0,
            rows: VecDeque::new(),
            multiproof: Multiproof::default(),
            _replay: Replay,
        })
    }
    pub fn phase(&self) -> u32 {
        match self.phase {
            Phase::FirstInitialize => 1,
            Phase::FirstColumn(_) => 2,
            Phase::FirstFinish => 3,
            Phase::Inverses => 4,
            Phase::SecondInitialize => 5,
            Phase::SecondColumn(_) => 6,
            Phase::SecondFinish => 7,
            Phase::Operator => 8,
            Phase::Linear => 9,
            Phase::Combination => 10,
            Phase::Folding => 11,
            Phase::Output => OUTPUT_PHASE,
            Phase::Done => DONE_PHASE,
        }
    }
    pub fn step(&mut self) -> Result<(), Error> {
        if matches!(self.phase, Phase::Output | Phase::Done) {
            return Err(Error::Stage);
        }
        let witness = self.witness.as_ref().ok_or(Error::Stage)?;
        match self.phase {
            Phase::FirstInitialize => {
                self.first = Some(FirstOracle::initialize(
                    &self.relation,
                    &self.transcript.role,
                    false,
                ));
                self.phase = Phase::FirstColumn(0);
            }
            Phase::FirstColumn(column) => {
                self.first.as_mut().unwrap().commit_column(witness, column);
                self.phase = if column + 1 < self.relation.columns() + 2 {
                    Phase::FirstColumn(column + 1)
                } else {
                    Phase::FirstFinish
                };
            }
            Phase::FirstFinish => {
                let first = self.first.as_mut().unwrap();
                first.finish_commitment();
                self.transcript.respond(&[&first.tree.root()]);
                self.transcript.next();
                self.phase = Phase::Inverses;
            }
            Phase::Inverses => {
                let beta = transcript::challenge(&self.transcript.message, 0, true);
                self.inverses = field::batch_inverse(
                    &(0..SYSTEMATIC)
                        .map(|value| field::subtract(beta, [value as u128, 0, 0]))
                        .collect::<Vec<_>>(),
                );
                self.phase = Phase::SecondInitialize;
            }
            Phase::SecondInitialize => {
                self.second = Some(SecondOracle::initialize(
                    &self.relation,
                    &self.transcript.role,
                ));
                self.phase = Phase::SecondColumn(0);
            }
            Phase::SecondColumn(column) => {
                self.second
                    .as_mut()
                    .unwrap()
                    .commit_column(witness, &self.inverses, column);
                self.phase = if column + 1 < self.relation.lookups() + 2 {
                    Phase::SecondColumn(column + 1)
                } else {
                    Phase::SecondFinish
                };
            }
            Phase::SecondFinish => {
                let second = self.second.as_mut().unwrap();
                second.finish_commitment();
                self.transcript
                    .respond(&[&second.tree.root(), &field::encode(second.mask_sum)]);
                self.transcript.next();
                self.phase = Phase::Operator;
            }
            Phase::Operator => {
                let alpha = transcript::challenge(&self.transcript.message, 0, false);
                self.operator = Some(self.statement.as_ref().unwrap().operator(alpha)?);
                self.statement = None;
                self.phase = Phase::Linear;
            }
            Phase::Linear => {
                let linear = LinearOracle::create(
                    &self.transcript.role,
                    witness,
                    self.first.as_ref().unwrap(),
                    self.second.as_ref().unwrap(),
                    self.operator.take().unwrap(),
                    transcript::challenge(&self.transcript.message, 1, false),
                    self.false_affine,
                );
                self.transcript.respond(&[&linear.tree.root()]);
                self.transcript.next();
                self.linear = Some(linear);
                self.phase = Phase::Combination;
            }
            Phase::Combination => {
                self.combination = Some(Zeroizing::new(combination::polynomial(
                    witness,
                    self.first.as_ref().unwrap(),
                    self.second.as_ref().unwrap(),
                    self.linear.as_ref().unwrap(),
                    field::inverse(self.inverses[0]),
                    &self.inverses,
                    &self.transcript.message,
                )));
                self.phase = Phase::Folding;
            }
            Phase::Folding => {
                let mut combination = self.combination.take().unwrap();
                let role = self.transcript.role.clone();
                self.folding = Some(Fri::create(
                    &role,
                    self.relation.oracles(),
                    std::mem::take(&mut *combination),
                    &mut self.transcript,
                ));
                self.phase = Phase::Output;
            }
            Phase::Output | Phase::Done => return Err(Error::Stage),
        }
        Ok(())
    }
    pub fn output(&self) -> &[u8] {
        &self.output
    }
    pub fn acknowledge_output(&mut self) -> Result<(), Error> {
        if self.output.is_empty() {
            return Err(Error::Stage);
        }
        self.output.clear();
        Ok(())
    }
    /// Serializes only after the earlier chunk is acknowledged. A tree's
    /// raw openings are computed once; records retain the native order and
    /// shared-path cursor irrespective of transport chunk boundaries.
    pub fn next_output(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Output || !self.output.is_empty() {
            return Err(Error::Stage);
        }
        let folding = self.folding.as_ref().unwrap();
        if !self.header_emitted {
            self.output.extend(self.relation.proof_magic);
            self.output.extend(self.statement_digest);
            self.output.extend(self.transcript.context);
            for root in [
                self.first.as_ref().unwrap().tree.root(),
                self.second.as_ref().unwrap().tree.root(),
                self.linear.as_ref().unwrap().tree.root(),
            ] {
                self.output.extend(root);
            }
            self.output
                .extend(field::encode(self.second.as_ref().unwrap().mask_sum));
            for salt in &self.transcript.salts {
                self.output.extend(salt);
            }
            for layer in &folding.layers {
                self.output.extend(layer.tree.root());
            }
            self.output.extend(field::encode(folding.terminal));
            assert!(self.output.len() <= OUTPUT_BYTES);
            self.header_emitted = true;
            return Ok(());
        }
        if self.output_stage == 3 + folding.layers.len() {
            self.folding = None;
            self.phase = Phase::Done;
            return Ok(());
        }
        if self.rows.is_empty() {
            self.multiproof = Multiproof::default();
            let length = if self.output_stage < 3 {
                DOMAIN
            } else {
                DOMAIN >> (self.output_stage - 2)
            };
            let indices = fri::requested(&folding.queries, length);
            let rows = match self.output_stage {
                0 => {
                    let first = self.first.as_ref().unwrap();
                    first
                        .tree
                        .opened_rows(&mut self.multiproof, &indices, |leaves| {
                            first.opened_rows(self.witness.as_ref().unwrap(), leaves)
                        })
                }
                1 => {
                    let second = self.second.as_ref().unwrap();
                    second
                        .tree
                        .opened_rows(&mut self.multiproof, &indices, |leaves| {
                            second.opened_rows(
                                self.witness.as_ref().unwrap(),
                                &self.inverses,
                                leaves,
                            )
                        })
                }
                2 => {
                    let linear = self.linear.as_ref().unwrap();
                    linear
                        .tree
                        .opened_rows(&mut self.multiproof, &indices, |leaves| {
                            linear.opened_rows(leaves)
                        })
                }
                stage => {
                    let layer = &folding.layers[stage - 3];
                    layer
                        .tree
                        .opened_rows(&mut self.multiproof, &indices, |leaves| layer.rows(leaves))
                        .into_iter()
                        .map(Vec::from)
                        .collect()
                }
            };
            assert!(!rows.is_empty());
            self.output.extend((rows.len() as u32).to_le_bytes());
            self.rows = indices.into_iter().zip(rows).collect();
            return Ok(());
        }
        let tree = match self.output_stage {
            0 => &self.first.as_ref().unwrap().tree,
            1 => &self.second.as_ref().unwrap().tree,
            2 => &self.linear.as_ref().unwrap().tree,
            stage => &folding.layers[stage - 3].tree,
        };
        while let Some((_, row)) = self.rows.front() {
            let maximum = 4 + row.len() + SALT_BYTES + 64 * tree.length.ilog2() as usize;
            assert!(maximum <= OUTPUT_BYTES);
            if maximum > OUTPUT_BYTES - self.output.len() {
                break;
            }
            let (index, mut row) = self.rows.pop_front().unwrap();
            tree.write_record(&mut self.multiproof, index, &row, &mut self.output);
            row.fill(0);
            assert!(self.output.len() <= OUTPUT_BYTES);
        }
        if self.rows.is_empty() {
            match self.output_stage {
                0 => self.first = None,
                1 => {
                    self.second = None;
                    self.witness = None;
                    self.inverses = Vec::new();
                }
                2 => self.linear = None,
                _ => {}
            }
            self.output_stage += 1;
        }
        Ok(())
    }
}
