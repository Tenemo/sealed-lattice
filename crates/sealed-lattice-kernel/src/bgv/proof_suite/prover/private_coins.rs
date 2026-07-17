use super::{
    ActionPrivateRandomness, BTreeMap, FoundationSchemaError, Hash512, PRIVATE_PROOF_SALT_PURPOSE,
    PrivateRandomCursor, PrivateRandomnessAttemptIdentifier, PrivateRandomnessDomain,
    PrivateRandomnessStream,
};

/// Private proof coins are supplied by Rust private-randomness custody.  Each
/// purpose is an independent stream beginning at counter zero; implementations
/// must delegate to `PrivateRandomnessStream::sample_modulo` and
/// `PrivateRandomnessStream::fill_bytes`, not to a transcript or host PRNG.
pub(crate) trait CommonProofPrivateCoinSource {
    type Error;

    fn sample_modulo(
        &mut self,
        purpose: u16,
        modulus: u64,
        maximum_candidate_draws_per_output: u32,
    ) -> Result<u64, Self::Error>;

    fn fill_raw_bytes(&mut self, purpose: u16, destination: &mut [u8]) -> Result<(), Self::Error>;
}

/// Private proof coins that can expose their exact authenticated stream
/// positions at a completed commitment boundary. The cursors contain no coin
/// bytes and are never used to initialize deterministic-prefix replay: replay
/// always starts each stream at counter zero and compares the resulting
/// cursors with the authenticated checkpoint manifest.
pub(crate) trait CheckpointableCommonProofPrivateCoinSource:
    CommonProofPrivateCoinSource
{
    fn checkpoint_cursors(&self) -> Vec<PrivateRandomCursor>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PrivateRandomnessCommonProofCoinError {
    Custody(FoundationSchemaError),
    DuplicateCursorPurpose,
}

impl From<FoundationSchemaError> for PrivateRandomnessCommonProofCoinError {
    fn from(error: FoundationSchemaError) -> Self {
        Self::Custody(error)
    }
}

/// Owns the independent private-randomness cursor for every purpose consumed by
/// one common-proof attempt.  The caller must authenticate exported cursors as
/// part of the containing attempt record before resuming them.
pub(crate) struct PrivateRandomnessCommonProofCoinSource<'action> {
    action_private_randomness: &'action ActionPrivateRandomness,
    family_schema_identifier: u16,
    derivation_context_hash: Hash512,
    attempt_identifier: PrivateRandomnessAttemptIdentifier,
    cursors_by_purpose: BTreeMap<u16, PrivateRandomCursor>,
}

impl<'action> PrivateRandomnessCommonProofCoinSource<'action> {
    pub(crate) fn new(
        action_private_randomness: &'action ActionPrivateRandomness,
        family_schema_identifier: u16,
        derivation_context_hash: Hash512,
        attempt_identifier: PrivateRandomnessAttemptIdentifier,
    ) -> Result<Self, PrivateRandomnessCommonProofCoinError> {
        let salt_domain = PrivateRandomnessDomain::from_assigned_pair(
            family_schema_identifier,
            PRIVATE_PROOF_SALT_PURPOSE,
        )?;
        drop(action_private_randomness.begin_stream(
            salt_domain,
            derivation_context_hash,
            attempt_identifier,
        )?);
        Ok(Self {
            action_private_randomness,
            family_schema_identifier,
            derivation_context_hash,
            attempt_identifier,
            cursors_by_purpose: BTreeMap::new(),
        })
    }

    pub(crate) fn resume(
        action_private_randomness: &'action ActionPrivateRandomness,
        family_schema_identifier: u16,
        derivation_context_hash: Hash512,
        attempt_identifier: PrivateRandomnessAttemptIdentifier,
        authenticated_cursors: impl IntoIterator<Item = PrivateRandomCursor>,
    ) -> Result<Self, PrivateRandomnessCommonProofCoinError> {
        let mut source = Self::new(
            action_private_randomness,
            family_schema_identifier,
            derivation_context_hash,
            attempt_identifier,
        )?;
        for cursor in authenticated_cursors {
            let purpose = cursor.purpose();
            let domain =
                PrivateRandomnessDomain::from_assigned_pair(family_schema_identifier, purpose)?;
            drop(action_private_randomness.resume_stream(
                domain,
                derivation_context_hash,
                attempt_identifier,
                cursor,
            )?);
            if source.cursors_by_purpose.insert(purpose, cursor).is_some() {
                return Err(PrivateRandomnessCommonProofCoinError::DuplicateCursorPurpose);
            }
        }
        Ok(source)
    }

    pub(crate) fn cursors(&self) -> impl Iterator<Item = PrivateRandomCursor> + '_ {
        self.cursors_by_purpose.values().copied()
    }

    fn stream_for_purpose(
        &self,
        purpose: u16,
    ) -> Result<PrivateRandomnessStream<'action>, PrivateRandomnessCommonProofCoinError> {
        let domain =
            PrivateRandomnessDomain::from_assigned_pair(self.family_schema_identifier, purpose)?;
        let action_private_randomness: &'action ActionPrivateRandomness =
            self.action_private_randomness;
        match self.cursors_by_purpose.get(&purpose).copied() {
            Some(cursor) => Ok(action_private_randomness.resume_stream(
                domain,
                self.derivation_context_hash,
                self.attempt_identifier,
                cursor,
            )?),
            None => Ok(action_private_randomness.begin_stream(
                domain,
                self.derivation_context_hash,
                self.attempt_identifier,
            )?),
        }
    }

    fn retain_stream_cursor(&mut self, stream: PrivateRandomnessStream<'action>) {
        let cursor = stream.cursor();
        drop(stream);
        self.cursors_by_purpose.insert(cursor.purpose(), cursor);
    }
}

impl CommonProofPrivateCoinSource for PrivateRandomnessCommonProofCoinSource<'_> {
    type Error = PrivateRandomnessCommonProofCoinError;

    fn sample_modulo(
        &mut self,
        purpose: u16,
        modulus: u64,
        maximum_candidate_draws_per_output: u32,
    ) -> Result<u64, Self::Error> {
        let mut stream = self.stream_for_purpose(purpose)?;
        let result = stream
            .sample_modulo(modulus, maximum_candidate_draws_per_output)
            .map_err(PrivateRandomnessCommonProofCoinError::Custody);
        self.retain_stream_cursor(stream);
        result
    }

    fn fill_raw_bytes(&mut self, purpose: u16, destination: &mut [u8]) -> Result<(), Self::Error> {
        let mut stream = self.stream_for_purpose(purpose)?;
        let result = stream
            .fill_bytes(destination)
            .map_err(PrivateRandomnessCommonProofCoinError::Custody);
        self.retain_stream_cursor(stream);
        result
    }
}

impl CheckpointableCommonProofPrivateCoinSource for PrivateRandomnessCommonProofCoinSource<'_> {
    fn checkpoint_cursors(&self) -> Vec<PrivateRandomCursor> {
        self.cursors().collect()
    }
}
