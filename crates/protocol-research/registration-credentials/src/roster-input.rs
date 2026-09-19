use crate::{
    Error,
    poll::{VerifiedPoll, verify_poll},
    registration::{RegistrationVerifier, VerifiedRegistration},
    roster::RosterProposal,
};
use std::sync::Arc;

/// Incremental public input verification; no participant signing authority.
pub struct RosterInputVerifier {
    poll: VerifiedPoll,
    expected: usize,
    records: Vec<Arc<VerifiedRegistration>>,
    current: Option<RegistrationVerifier>,
}
impl RosterInputVerifier {
    pub fn new(input: &[u8]) -> Result<Self, Error> {
        if !(134 + 3309..=1_572_864).contains(&input.len()) {
            return Err(Error::Shape);
        }
        let count = u16::from_le_bytes(input[128..130].try_into().unwrap()) as usize;
        let length = u32::from_le_bytes(input[130..134].try_into().unwrap()) as usize;
        if !(3..=20).contains(&count)
            || length > crate::poll::MAXIMUM_POLL_BYTES
            || input.len() != 134 + length + 3309
        {
            return Err(Error::Shape);
        }
        let poll = verify_poll(
            input[..64].try_into().unwrap(),
            input[64..128].try_into().unwrap(),
            &input[134..134 + length],
            &input[134 + length..],
        )?;
        Ok(Self {
            poll,
            expected: count,
            records: Vec::with_capacity(count),
            current: None,
        })
    }
    pub fn begin_record(&mut self, input: &[u8]) -> Result<(), Error> {
        if !(6 + 3309..=6 + 4096 + 3309).contains(&input.len())
            || self.current.is_some()
            || self.records.len() == self.expected
        {
            return Err(Error::Shape);
        }
        let position = u16::from_le_bytes(input[..2].try_into().unwrap()) as usize;
        let length = u32::from_le_bytes(input[2..6].try_into().unwrap()) as usize;
        if position != self.records.len() || length > 4096 || input.len() != 6 + length + 3309 {
            return Err(Error::Shape);
        }
        self.current = Some(RegistrationVerifier::new(
            &self.poll,
            &input[6..6 + length],
            &input[6 + length..],
        )?);
        Ok(())
    }
    fn advance(
        &mut self,
        operation: impl FnOnce(&mut RegistrationVerifier) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut record = self.current.take().ok_or(Error::Shape)?;
        operation(&mut record)?;
        self.current = Some(record);
        Ok(())
    }
    pub fn push_key(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.advance(|record| record.push_key(bytes))
    }
    pub fn finish_key(&mut self) -> Result<(), Error> {
        self.advance(RegistrationVerifier::finish_key)
    }
    pub fn push_proof(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.advance(|record| record.push_proof(bytes))
    }
    pub fn finish_record(&mut self) -> Result<(), Error> {
        let record = self.current.take().ok_or(Error::Shape)?.finish()?;
        self.records.push(Arc::new(record));
        Ok(())
    }
    pub fn finish(&self) -> Result<RosterProposal, Error> {
        if self.current.is_some() || self.records.len() != self.expected {
            return Err(Error::Shape);
        }
        RosterProposal::new(&self.poll, self.records.clone())
    }
    pub fn into_poll(self) -> VerifiedPoll {
        self.poll
    }
}
