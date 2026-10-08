use crate::{
    Error, SIGNATURE_BYTES,
    poll::{VerifiedPoll, verify_poll},
    registration::{VerifiedRegistration, session::RegistrationSession},
    roster::RosterProposal,
};

use std::sync::Arc;

/// The records a roster verification keeps open at once: one for each
/// helper, whose sessions then run side by side, or one without helpers.
pub fn open_record_limit() -> usize {
    parallel_work::helpers().max(1)
}

crate::operation_codes! {
    /// The steps of one registration record in a roster verification.
    pub enum RecordStep {
        Begin = 0,
        Key = 1,
        KeyFinish = 2,
        Finish = 4,
        Discard = 5,
    }
}

enum Record {
    Unread,
    Open(Box<RegistrationSession>),
    Verified(Arc<VerifiedRegistration>),
    Refused,
}

/// Incremental public input verification; no participant signing authority.
pub struct RosterInputVerifier {
    poll: VerifiedPoll,
    records: Vec<Record>,
    // The shards no open record's session holds.
    shards: Vec<usize>,
    // The original requested body identity at each position, never replaced
    // by a failed public candidate or its retry.
    identities: Vec<Option<[u8; 64]>>,
    verified: Option<Vec<Arc<VerifiedRegistration>>>,
}
impl RosterInputVerifier {
    pub fn new(input: &[u8]) -> Result<Self, Error> {
        if !(134 + SIGNATURE_BYTES..=1_572_864).contains(&input.len()) {
            return Err(Error::Shape);
        }
        let count = u16::from_le_bytes(input[128..130].try_into().unwrap()) as usize;
        let length = u32::from_le_bytes(input[130..134].try_into().unwrap()) as usize;
        if !supported_profile::Profile::participant_range().contains(&count)
            || length > crate::poll::MAXIMUM_POLL_BYTES
            || input.len() != 134 + length + SIGNATURE_BYTES
        {
            return Err(Error::Shape);
        }
        let poll = verify_poll(
            input[..64].try_into().unwrap(),
            input[64..128].try_into().unwrap(),
            &input[134..134 + length],
            &input[134 + length..],
        )?;
        if count > usize::from(poll.maximum_participants()) {
            return Err(Error::Context);
        }
        Ok(Self {
            poll,
            records: (0..count).map(|_| Record::Unread).collect(),
            identities: vec![None; count],
            shards: (0..open_record_limit()).rev().collect(),
            verified: None,
        })
    }
    pub fn poll(&self) -> &VerifiedPoll {
        &self.poll
    }
    /// Runs one step of the record at a position; only a record's begin and
    /// its key take bytes.
    pub fn record_step(
        &mut self,
        step: RecordStep,
        position: usize,
        bytes: &[u8],
    ) -> Result<(), Error> {
        match step {
            RecordStep::Begin => self.begin_record(bytes),
            RecordStep::Key => self.push_key(position, bytes),
            RecordStep::KeyFinish if bytes.is_empty() => self.finish_key(position),
            RecordStep::Finish if bytes.is_empty() => self.finish_record(position),
            RecordStep::Discard if bytes.is_empty() => self.discard_record(position),
            RecordStep::KeyFinish | RecordStep::Finish | RecordStep::Discard => Err(Error::Shape),
        }
    }
    /// Opens a candidate under the original requested body identity. The
    /// control is position, body identity, header length, header and
    /// signature. Only discard_record permits another candidate at an
    /// unfinished position.
    pub fn begin_record(&mut self, input: &[u8]) -> Result<(), Error> {
        if !(70..=70 + 4096 + SIGNATURE_BYTES).contains(&input.len()) {
            return Err(Error::Shape);
        }
        let position = u16::from_le_bytes(input[..2].try_into().unwrap()) as usize;
        let identity = input[2..66].try_into().unwrap();
        let length = u32::from_le_bytes(input[66..70].try_into().unwrap()) as usize;
        if length > 4096 || input.len() < 70 + length {
            return Err(Error::Shape);
        }
        if !matches!(self.records.get(position), Some(Record::Unread)) {
            return Err(Error::Shape);
        }
        if self.identities[position].is_some_and(|expected| expected != identity) {
            return Err(Error::Context);
        }
        self.identities[position] = Some(identity);
        let (header, signature) = input[70..].split_at(length);
        if signature.len() != SIGNATURE_BYTES {
            return Err(Error::Shape);
        }
        let shard = self.shards.pop().ok_or(Error::Shape)?;
        match RegistrationSession::open(&self.poll, shard, header, signature) {
            Ok(session) => {
                self.records[position] = Record::Open(Box::new(session));
                Ok(())
            }
            Err(error) => {
                self.shards.push(shard);
                self.records[position] = Record::Refused;
                Err(error)
            }
        }
    }
    /// Discards only tentative public input. The requested identity and
    /// every positive record survive; no accepted record can be replaced
    /// through this operation.
    pub fn discard_record(&mut self, position: usize) -> Result<(), Error> {
        let record = self.records.get_mut(position).ok_or(Error::Shape)?;
        if matches!(record, Record::Verified(_)) {
            return Err(Error::Consumed);
        }
        if let Record::Open(session) = std::mem::replace(record, Record::Unread) {
            self.shards.push(session.shard());
            drop(session);
        }
        Ok(())
    }
    pub fn push_key(&mut self, position: usize, bytes: &[u8]) -> Result<(), Error> {
        match self.records.get_mut(position) {
            Some(Record::Open(session)) => session.push_key(bytes),
            _ => Err(Error::Shape),
        }
    }
    pub fn finish_key(&mut self, position: usize) -> Result<(), Error> {
        match self.records.get_mut(position) {
            Some(Record::Open(session)) => session.finish_key(),
            _ => Err(Error::Shape),
        }
    }

    /// Accepts only a complete owning-verifier result with the originally
    /// requested body identity.
    pub fn finish_record(&mut self, position: usize) -> Result<(), Error> {
        match self.records.get(position) {
            Some(Record::Open(_)) => {
                let Record::Open(session) =
                    std::mem::replace(&mut self.records[position], Record::Refused)
                else {
                    unreachable!()
                };
                self.shards.push(session.shard());
                let verified = session.finish()?.wait()?;
                if Some(verified.body_digest()) != self.identities[position] {
                    return Err(Error::Context);
                }
                self.records[position] = Record::Verified(Arc::new(verified));
                Ok(())
            }
            _ => Err(Error::Shape),
        }
    }
    /// The proposal of every record, each verified by its session.
    pub fn finish(&mut self) -> Result<RosterProposal, Error> {
        if self.verified.is_none() {
            if !self
                .records
                .iter()
                .all(|record| matches!(record, Record::Verified(_)))
            {
                return Err(Error::Shape);
            }
            let mut verified = Vec::with_capacity(self.records.len());
            for record in &self.records {
                match record {
                    Record::Verified(registration) => verified.push(registration.clone()),
                    _ => unreachable!(),
                }
            }
            self.verified = Some(verified);
        }
        RosterProposal::new(&self.poll, self.verified.clone().unwrap())
    }
    pub fn into_poll(self) -> VerifiedPoll {
        self.poll
    }
}

#[cfg(test)]
#[path = "roster-input-tests.rs"]
mod tests;
