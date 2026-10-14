use crate::{
    CHUNK_LIMIT,
    body::{BallotBodyClassification, BallotBodyClassifier, BallotInputs},
    submission::authenticate_envelope,
};
use protocol_foundations::SIGNATURE_BYTES;
use protocol_foundations::ballot_authentication::ENVELOPE_BYTES;
use protocol_foundations::ballot_body::HEADER_BYTES;
use protocol_foundations::poll::VerifiedPoll;
use setup_aggregate::verified::VerifiedSetupAggregate;
use std::sync::Arc;

/// The refusal of a classification step.
#[derive(Debug)]
pub struct Refusal;

/// The classification of one ballot at a time under the instance's verified
/// setup: its authenticated envelope, its key and body pieces and the
/// classification they reach.
pub struct ClassificationSession {
    input: Vec<u8>,
    classifier: Option<BallotBodyClassifier>,
    classification: Option<BallotBodyClassification>,
    // The statement inputs that the first ballot under the current setup
    // read, which the setup's later ballots share until they are released.
    inputs: Option<Arc<BallotInputs>>,
}
impl ClassificationSession {
    pub fn new() -> Self {
        Self {
            input: vec![0; CHUNK_LIMIT],
            classifier: None,
            classification: None,
            inputs: None,
        }
    }
    pub fn input(&mut self) -> &mut [u8] {
        &mut self.input
    }
    /// Begins a ballot's classification from its envelope, signature and
    /// body header, under the verified setup that `setup` reads.
    pub fn begin(
        &mut self,
        setup: impl FnOnce() -> Option<(Arc<VerifiedPoll>, Arc<VerifiedSetupAggregate>)>,
        length: usize,
    ) -> Result<(), Refusal> {
        let Self {
            input,
            classifier,
            classification,
            inputs,
        } = self;
        *classifier = None;
        *classification = None;
        let result = (|| {
            if length != ENVELOPE_BYTES + SIGNATURE_BYTES + HEADER_BYTES {
                return Err(Refusal);
            }
            let bytes = input.get(..length).ok_or(Refusal)?;
            let (poll, setup) = setup().ok_or(Refusal)?;
            // Another setup's inputs are released before this one reads its
            // own.
            if inputs.as_ref().is_some_and(|value| !value.serves(&setup)) {
                *inputs = None;
            }
            let authentication = authenticate_envelope(
                &setup,
                &bytes[..ENVELOPE_BYTES],
                &bytes[ENVELOPE_BYTES..ENVELOPE_BYTES + SIGNATURE_BYTES],
            )
            .map_err(|_| Refusal)?;
            BallotBodyClassifier::new(
                poll,
                setup,
                authentication,
                &bytes[ENVELOPE_BYTES + SIGNATURE_BYTES..],
                inputs.clone(),
            )
            .map_err(|_| Refusal)
        })();
        *classifier = result.ok();
        if classifier.is_none() {
            Err(Refusal)
        } else {
            Ok(())
        }
    }
    pub fn requires_key(&self) -> bool {
        self.classifier
            .as_ref()
            .is_some_and(BallotBodyClassifier::requires_key)
    }
    pub fn begin_key(&mut self, index: usize) -> Result<(), Refusal> {
        let result = self
            .classifier
            .as_mut()
            .ok_or(Refusal)
            .and_then(|value| value.begin_key(index).map_err(|_| Refusal));
        if result.is_err() {
            self.classifier = None;
            self.classification = None;
        }
        result
    }
    pub fn finish_key(&mut self) -> Result<(), Refusal> {
        let result = self
            .classifier
            .as_mut()
            .ok_or(Refusal)
            .and_then(|value| value.finish_key().map_err(|_| Refusal));
        if result.is_err() {
            self.classifier = None;
            self.classification = None;
        } else if let Some(inputs) = self
            .classifier
            .as_ref()
            .and_then(BallotBodyClassifier::inputs)
        {
            self.inputs = Some(inputs);
        }
        result
    }
    /// Feeds the input's first `length` bytes to the key, when `key` holds,
    /// or else to the body.
    pub fn push(&mut self, length: usize, key: bool) -> Result<(), Refusal> {
        let Self {
            input,
            classifier,
            classification,
            ..
        } = self;
        let result = (|| {
            let bytes = input.get(..length).ok_or(Refusal)?;
            let value = classifier.as_mut().ok_or(Refusal)?;
            if key {
                value.push_key(bytes)
            } else {
                value.push(bytes)
            }
            .map_err(|_| Refusal)
        })();
        if result.is_err() {
            *classifier = None;
            *classification = None;
        }
        result
    }
    /// Finishes the ballot's classification, which holds none when it
    /// failed.
    pub fn finish(&mut self) -> Result<(), Refusal> {
        self.classification = self.classifier.take().and_then(|value| value.finish().ok());
        self.classification.as_ref().map(|_| ()).ok_or(Refusal)
    }
    /// Whether the finished classification holds a valid ballot.
    pub fn valid(&self) -> bool {
        matches!(
            self.classification,
            Some(BallotBodyClassification::Valid(_))
        )
    }
    pub fn take_classification(&mut self) -> Option<BallotBodyClassification> {
        self.classification.take()
    }
    /// Releases the statement inputs that the classified ballots shared.
    pub fn release_inputs(&mut self) {
        self.inputs = None;
    }
}
impl Default for ClassificationSession {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "classification-session-tests.rs"]
mod tests;
