use super::{Refusal, SetupSession, keep_offer};
use crate::{
    CHUNK_BYTES,
    aggregate_publisher::AggregatePublisher,
    offer_verifier::VerifiedCommittedOffer,
    published_aggregate::{AggregateManifest, PublishedAggregateVerifier, evaluation_role},
    verified::StreamedAggregate,
};
use protocol_foundations::Credential;
use statement_stream::committed_polynomial::CommittedPolynomial;
use std::sync::Arc;
use supported_profile::Profile;
use word_proof::public_evaluation::EvaluationProver;

protocol_foundations::operation_codes! {
    pub enum PublicOperation {
        BeginCollection = 1,
        BeginCollectedOffer = 2,
        CollectPolynomial = 3,
        FinishCollectedOffer = 4,
        SealCollection = 5,
        BeginAggregate = 6,
        AggregatePolynomial = 7,
        BeginEvaluation = 8,
        EvaluationProof = 9,
        FinishEvaluation = 10,
        FinishAggregate = 11,
        BeginEvaluationJob = 12,
        BeginJobPolynomial = 13,
        JobPolynomial = 14,
        FinishJobPolynomial = 15,
        NextJobOutput = 16,
        CompactAvailable = 17,
        FinishAggregateCache = 18,
    }
}

#[derive(Default)]
pub(super) struct PublicWork {
    collection: Option<AggregatePublisher>,
    pub(super) streamed: Option<StreamedAggregate>,
    aggregate: Option<PublishedAggregateVerifier>,
    job: Option<EvaluationJob>,
    input_output_bytes: usize,
}

impl PublicWork {
    pub(super) fn reset_selection(&mut self) {
        self.streamed = None;
        self.aggregate = None;
        self.job = None;
        self.input_output_bytes = 0;
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Columns,
    Openings,
    Output,
}
struct EvaluationJob {
    profile: Profile,
    prover: EvaluationProver,
    polynomial: Option<CommittedPolynomial>,
    next: usize,
    phase: Phase,
}

impl EvaluationJob {
    fn begin(&mut self, index: usize) -> Result<(), Refusal> {
        if self.phase == Phase::Output
            || self.polynomial.is_some()
            || self.profile.committed_polynomials().get(self.next) != Some(&index)
        {
            return Err(Refusal);
        }
        self.polynomial = Some(CommittedPolynomial::new(self.profile));
        Ok(())
    }
    fn finish(&mut self) -> Result<(), Refusal> {
        let columns = self
            .polynomial
            .take()
            .ok_or(Refusal)?
            .finish()
            .map_err(|_| Refusal)?;
        for column in columns {
            match self.phase {
                Phase::Columns => self.prover.column(&column),
                Phase::Openings => self.prover.opening_column(&column),
                Phase::Output => return Err(Refusal),
            }
            .map_err(|_| Refusal)?;
        }
        self.next += 1;
        if self.next == self.profile.committed_polynomials().len() {
            self.next = 0;
            self.phase = match self.phase {
                Phase::Columns => {
                    self.prover.finish_columns().map_err(|_| Refusal)?;
                    Phase::Openings
                }
                Phase::Openings => {
                    self.prover.finish_openings().map_err(|_| Refusal)?;
                    Phase::Output
                }
                Phase::Output => return Err(Refusal),
            };
        }
        Ok(())
    }
}

impl SetupSession {
    pub fn retain_aggregate_data(&self, credential: &Credential) -> Result<Vec<u8>, Refusal> {
        self.public_work
            .aggregate
            .as_ref()
            .ok_or(Refusal)?
            .retain_data(credential, self.poll.as_ref().ok_or(Refusal)?)
            .map_err(|_| Refusal)
    }
    pub fn restore_aggregate_data(
        &mut self,
        credential: &Credential,
        bytes: &[u8],
    ) -> Result<(), Refusal> {
        self.public_work
            .aggregate
            .as_mut()
            .ok_or(Refusal)?
            .restore_data(credential, self.poll.as_ref().ok_or(Refusal)?, bytes)
            .map_err(|_| Refusal)
    }
    pub fn retain_collection(&self, credential: &Credential) -> Result<Vec<u8>, Refusal> {
        self.public_work
            .collection
            .as_ref()
            .ok_or(Refusal)?
            .retain(credential, self.poll.as_ref().ok_or(Refusal)?)
            .map_err(|_| Refusal)
    }

    pub fn restore_collection(
        &mut self,
        credential: &Credential,
        bytes: &[u8],
    ) -> Result<Vec<u8>, Refusal> {
        let collection = AggregatePublisher::restore(
            credential,
            self.poll.as_ref().ok_or(Refusal)?,
            self.proposal.clone().ok_or(Refusal)?,
            bytes,
        )
        .map_err(|_| Refusal)?;
        if let Some(selected) = &self.selected
            && collection.offers().iter().any(|offer| {
                !selected.selection().selected().contains(&(
                    offer.envelope().position(),
                    *offer.envelope().body_identity(),
                ))
            })
        {
            return Err(Refusal);
        }
        let mut restored = Vec::new();
        for offer in collection.offers() {
            restored.extend((offer.envelope().position() as u16).to_le_bytes());
            restored.extend(offer.envelope().body_identity());
            keep_offer(&mut self.offers, offer.clone());
        }
        self.public_work.collection = Some(collection);
        Ok(restored)
    }

    pub fn public_output(&self) -> &[u8] {
        if self.public_work.input_output_bytes == 0 {
            &self.output
        } else {
            &self.input[CHUNK_BYTES..CHUNK_BYTES + self.public_work.input_output_bytes]
        }
    }

    fn ordered_committed_offers(&self) -> Result<Vec<Arc<VerifiedCommittedOffer>>, Refusal> {
        let selected = self.selected.as_ref().ok_or(Refusal)?;
        selected
            .selection()
            .selected()
            .iter()
            .map(|(position, identity)| {
                self.committed_offers
                    .iter()
                    .find(|offer| {
                        offer.envelope().position() == *position
                            && offer.envelope().body_identity() == identity
                    })
                    .cloned()
                    .or_else(|| {
                        self.offers
                            .iter()
                            .find(|offer| {
                                offer.envelope().position() == *position
                                    && offer.envelope().body_identity() == identity
                            })
                            .map(|offer| Arc::new(offer.committed()))
                    })
                    .ok_or(Refusal)
            })
            .collect()
    }

    pub fn public_step(
        &mut self,
        operation: PublicOperation,
        index: usize,
        offset: usize,
        length: usize,
    ) -> Result<(), Refusal> {
        self.public_work.input_output_bytes = 0;
        self.output.clear();
        if length > self.input.len() {
            return Err(Refusal);
        }
        match operation {
            PublicOperation::BeginCollection => {
                if index != 0 || offset != 0 || length != 0 {
                    return Err(Refusal);
                }
                self.public_work.collection = Some(AggregatePublisher::new(
                    self.proposal.clone().ok_or(Refusal)?,
                ));
            }
            PublicOperation::BeginCollectedOffer => {
                if offset != 0 || length != 64 {
                    return Err(Refusal);
                }
                let offer = self
                    .offers
                    .iter()
                    .find(|offer| {
                        offer.envelope().position() == index
                            && offer.envelope().body_identity().as_slice() == &self.input[..64]
                    })
                    .cloned()
                    .ok_or(Refusal)?;
                self.public_work
                    .collection
                    .as_mut()
                    .ok_or(Refusal)?
                    .begin(offer)
                    .map_err(|_| Refusal)?;
            }
            PublicOperation::CollectPolynomial => {
                let collection = self.public_work.collection.as_mut().ok_or(Refusal)?;
                let output_bytes = collection
                    .output_bytes(index, length)
                    .map_err(|_| Refusal)?;
                if length > CHUNK_BYTES || output_bytes > self.input.len() - CHUNK_BYTES {
                    return Err(Refusal);
                }
                let (incoming, previous) = self.input.split_at_mut(CHUNK_BYTES);
                collection
                    .polynomial(
                        index,
                        offset,
                        &incoming[..length],
                        &mut previous[..output_bytes],
                    )
                    .map_err(|_| Refusal)?;
                self.public_work.input_output_bytes = output_bytes;
            }
            PublicOperation::FinishCollectedOffer => {
                if index != 0 || offset != 0 || length != 0 {
                    return Err(Refusal);
                }
                let collection = self.public_work.collection.as_mut().ok_or(Refusal)?;
                collection.finish_offer().map_err(|_| Refusal)?;
                self.output
                    .extend((collection.accepted() as u32).to_le_bytes());
            }
            PublicOperation::SealCollection => {
                if index != 0 || offset != 0 || length != 0 {
                    return Err(Refusal);
                }
                let selection = self.selected.clone().ok_or(Refusal)?;
                let (manifest, streamed) = self
                    .public_work
                    .collection
                    .take()
                    .ok_or(Refusal)?
                    .finish(selection)
                    .map_err(|_| Refusal)?;
                self.output = manifest.encode();
                self.public_work.streamed = Some(streamed);
            }
            PublicOperation::BeginAggregate => {
                if index != 0 || offset != 0 {
                    return Err(Refusal);
                }
                let streamed = self.public_work.streamed.clone().ok_or(Refusal)?;
                let aggregate = PublishedAggregateVerifier::new(streamed, &self.input[..length])
                    .map_err(|_| Refusal)?;
                self.output.extend(aggregate.manifest().identity());
                self.public_work.aggregate = Some(aggregate);
            }
            PublicOperation::AggregatePolynomial => {
                self.public_work
                    .aggregate
                    .as_mut()
                    .ok_or(Refusal)?
                    .polynomial(index, offset, &self.input[..length], &mut self.output)
                    .map_err(|_| Refusal)?;
            }
            PublicOperation::BeginEvaluation => {
                if offset != 0 {
                    return Err(Refusal);
                }
                self.public_work
                    .aggregate
                    .as_mut()
                    .ok_or(Refusal)?
                    .begin_evaluation(index, &self.input[..length])
                    .map_err(|_| Refusal)?;
            }
            PublicOperation::EvaluationProof => {
                if index != 0 || offset != 0 {
                    return Err(Refusal);
                }
                self.public_work
                    .aggregate
                    .as_mut()
                    .ok_or(Refusal)?
                    .proof(&self.input[..length])
                    .map_err(|_| Refusal)?;
            }
            PublicOperation::FinishEvaluation => {
                if index != 0 || offset != 0 || length != 0 {
                    return Err(Refusal);
                }
                self.public_work
                    .aggregate
                    .as_mut()
                    .ok_or(Refusal)?
                    .finish_evaluation()
                    .map_err(|_| Refusal)?;
            }
            PublicOperation::FinishAggregate => {
                if index != 0 || offset != 0 || length != 0 {
                    return Err(Refusal);
                }
                let inputs = self
                    .public_work
                    .aggregate
                    .take()
                    .ok_or(Refusal)?
                    .finish()
                    .map_err(|_| Refusal)?;
                if self.inputs.as_ref().is_some_and(|known| {
                    known.identity() != inputs.identity()
                        || known.polynomials() != inputs.polynomials()
                }) || self.verified.as_ref().is_some_and(|known| {
                    known.identity() != inputs.identity()
                        || known.polynomials() != inputs.polynomials()
                }) {
                    return Err(Refusal);
                }
                self.inputs = Some(Arc::new(inputs));
            }
            PublicOperation::BeginEvaluationJob => {
                if offset != 0 {
                    return Err(Refusal);
                }
                let selection = self.selected.as_ref().ok_or(Refusal)?;
                let profile = selection.roster().proposal().profile();
                let manifest = AggregateManifest::decode(selection, &self.input[..length])
                    .map_err(|_| Refusal)?;
                let offers = self.ordered_committed_offers()?;
                let roots: Vec<_> = offers.iter().map(|offer| *offer.public_root()).collect();
                let offer = offers.get(index).ok_or(Refusal)?;
                let contribution_role = offer
                    .roster()
                    .proposal()
                    .contribution_role(offer.envelope().position())
                    .map_err(|_| Refusal)?;
                self.public_work.job = Some(EvaluationJob {
                    profile,
                    prover: EvaluationProver::new(
                        profile,
                        &evaluation_role(selection),
                        manifest.identity(),
                        &roots,
                        index,
                        &contribution_role,
                    )
                    .map_err(|_| Refusal)?,
                    polynomial: None,
                    next: 0,
                    phase: Phase::Columns,
                });
            }
            PublicOperation::BeginJobPolynomial => {
                if offset != 0 || length != 0 {
                    return Err(Refusal);
                }
                self.public_work.job.as_mut().ok_or(Refusal)?.begin(index)?;
            }
            PublicOperation::JobPolynomial => {
                if index != 0 || offset != 0 {
                    return Err(Refusal);
                }
                self.public_work
                    .job
                    .as_mut()
                    .ok_or(Refusal)?
                    .polynomial
                    .as_mut()
                    .ok_or(Refusal)?
                    .push(&self.input[..length])
                    .map_err(|_| Refusal)?;
            }
            PublicOperation::FinishJobPolynomial => {
                if index != 0 || offset != 0 || length != 0 {
                    return Err(Refusal);
                }
                self.public_work.job.as_mut().ok_or(Refusal)?.finish()?;
            }
            PublicOperation::NextJobOutput => {
                if index != 0 || offset != 0 || length != 0 {
                    return Err(Refusal);
                }
                let job = self.public_work.job.as_mut().ok_or(Refusal)?;
                if job.phase != Phase::Output {
                    return Err(Refusal);
                }
                if !job
                    .prover
                    .next_output(&mut self.output)
                    .map_err(|_| Refusal)?
                {
                    self.public_work.job = None;
                }
            }
            PublicOperation::CompactAvailable => {
                if offset != 0 || length != 64 {
                    return Err(Refusal);
                }
                let present = self.committed_offers.iter().any(|offer| {
                    offer.envelope().position() == index
                        && offer.envelope().body_identity().as_slice() == &self.input[..64]
                });
                self.output.push(u8::from(present));
            }
            PublicOperation::FinishAggregateCache => {
                if index != 0 || offset != 0 || length != 0 {
                    return Err(Refusal);
                }
                self.public_work
                    .aggregate
                    .take()
                    .ok_or(Refusal)?
                    .check_cache(self.inputs.as_ref().ok_or(Refusal)?)
                    .map_err(|_| Refusal)?;
            }
        }
        Ok(())
    }
}
