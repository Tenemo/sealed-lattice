use crate::{
    Error,
    poll::{VerifiedPoll, verify_poll},
    registration::{
        VerifiedRegistration,
        session::{PendingRegistration, RegistrationSession},
    },
    roster::RosterProposal,
};
use std::sync::Arc;

/// The records a roster verification keeps open at once: one for each
/// helper, whose sessions then run side by side, or one without helpers.
pub fn open_record_limit() -> usize {
    parallel_work::helpers().max(1)
}

enum Record {
    Unread,
    Open(RegistrationSession),
    Finished(PendingRegistration),
    Refused,
}

/// Incremental public input verification; no participant signing authority.
pub struct RosterInputVerifier {
    poll: VerifiedPoll,
    records: Vec<Record>,
    // The shards no open record's session holds.
    shards: Vec<usize>,
    verified: Option<Vec<Arc<VerifiedRegistration>>>,
    failed: bool,
}
impl RosterInputVerifier {
    pub fn new(input: &[u8]) -> Result<Self, Error> {
        if !(134 + 3309..=1_572_864).contains(&input.len()) {
            return Err(Error::Shape);
        }
        let count = u16::from_le_bytes(input[128..130].try_into().unwrap()) as usize;
        let length = u32::from_le_bytes(input[130..134].try_into().unwrap()) as usize;
        if !supported_profile::Profile::participant_range().contains(&count)
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
            records: (0..count).map(|_| Record::Unread).collect(),
            shards: (0..open_record_limit()).rev().collect(),
            verified: None,
            failed: false,
        })
    }
    /// Opens the record at its position, which no earlier record took, while
    /// fewer than the open-record limit are open.
    pub fn begin_record(&mut self, input: &[u8]) -> Result<(), Error> {
        if !(6 + 3309..=6 + 4096 + 3309).contains(&input.len()) {
            return Err(Error::Shape);
        }
        let position = u16::from_le_bytes(input[..2].try_into().unwrap()) as usize;
        let length = u32::from_le_bytes(input[2..6].try_into().unwrap()) as usize;
        if length > 4096
            || input.len() != 6 + length + 3309
            || !matches!(self.records.get(position), Some(Record::Unread))
        {
            return Err(Error::Shape);
        }
        let shard = self.shards.pop().ok_or(Error::Shape)?;
        match RegistrationSession::open(
            &self.poll,
            shard,
            &input[6..6 + length],
            &input[6 + length..],
        ) {
            Ok(session) => {
                self.records[position] = Record::Open(session);
                Ok(())
            }
            Err(error) => {
                self.shards.push(shard);
                self.records[position] = Record::Refused;
                Err(error)
            }
        }
    }
    fn open(&mut self, position: usize) -> Result<&mut RegistrationSession, Error> {
        match self.records.get_mut(position) {
            Some(Record::Open(session)) => Ok(session),
            _ => Err(Error::Shape),
        }
    }
    pub fn push_key(&mut self, position: usize, bytes: &[u8]) -> Result<(), Error> {
        self.open(position)?.push_key(bytes)
    }
    pub fn finish_key(&mut self, position: usize) -> Result<(), Error> {
        self.open(position)?.finish_key()
    }
    pub fn push_proof(&mut self, position: usize, bytes: &[u8]) -> Result<(), Error> {
        self.open(position)?.push_proof(bytes)
    }
    /// Closes the record at its position; its session's verdict decides it
    /// when the roster finishes.
    pub fn finish_record(&mut self, position: usize) -> Result<(), Error> {
        self.open(position)?;
        let Record::Open(session) = std::mem::replace(&mut self.records[position], Record::Refused)
        else {
            unreachable!()
        };
        self.shards.push(session.shard());
        self.records[position] = Record::Finished(session.finish()?);
        Ok(())
    }
    /// The proposal of every record, each verified by its session.
    pub fn finish(&mut self) -> Result<RosterProposal, Error> {
        if self.failed {
            return Err(Error::Consumed);
        }
        if self.verified.is_none() {
            if !self
                .records
                .iter()
                .all(|record| matches!(record, Record::Finished(_)))
            {
                return Err(Error::Shape);
            }
            let mut verified = Vec::with_capacity(self.records.len());
            for record in std::mem::take(&mut self.records) {
                let Record::Finished(pending) = record else {
                    unreachable!()
                };
                match pending.wait() {
                    Ok(registration) => verified.push(Arc::new(registration)),
                    Err(error) => {
                        self.failed = true;
                        return Err(error);
                    }
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
mod tests {
    use super::*;
    use crate::registration::{KEY_BYTES, session::tests::unproved_record};
    use registration_verifier::CHUNK_LIMIT;

    // One record is open for each helper, or one without helpers. Each
    // position opens once, every step names an open record, and the roster
    // finishes only once every record has finished and its session's verdict
    // accepts it; a refused record refuses the roster, and the roster stays
    // refused.
    #[test]
    fn records_open_within_the_limit_and_the_roster_waits_for_every_verdict() {
        let (packet, header) = unproved_record([4; 64]);
        let input = [
            packet.identity.as_slice(),
            &[4; 64],
            &3u16.to_le_bytes(),
            &(packet.body.len() as u32).to_le_bytes(),
            &packet.body,
            &packet.signature,
        ]
        .concat();
        let mut roster = RosterInputVerifier::new(&input).unwrap();
        let record = |position: u16| {
            [
                position.to_le_bytes().as_slice(),
                &(header.len() as u32).to_le_bytes(),
                &header,
                &[0; 3309],
            ]
            .concat()
        };
        let key = vec![0; KEY_BYTES];
        roster.begin_record(&record(0)).unwrap();
        assert!(matches!(roster.push_key(1, &key[..1]), Err(Error::Shape)));
        assert!(matches!(roster.finish(), Err(Error::Shape)));
        let opened = open_record_limit().min(3) as u16;
        for position in 1..opened {
            roster.begin_record(&record(position)).unwrap();
        }
        if opened < 3 {
            assert!(matches!(
                roster.begin_record(&record(opened)),
                Err(Error::Shape)
            ));
        }
        for position in 0..3 {
            if position >= opened {
                roster.begin_record(&record(position)).unwrap();
            }
            for part in key.chunks(CHUNK_LIMIT) {
                roster.push_key(position.into(), part).unwrap();
            }
            roster.finish_key(position.into()).unwrap();
            roster.finish_record(position.into()).unwrap();
            assert!(matches!(
                roster.begin_record(&record(position)),
                Err(Error::Shape)
            ));
            assert!(matches!(
                roster.finish_record(position.into()),
                Err(Error::Shape)
            ));
        }
        assert!(matches!(roster.begin_record(&record(3)), Err(Error::Shape)));
        assert!(matches!(roster.finish(), Err(Error::Shape)));
        assert!(matches!(roster.finish(), Err(Error::Consumed)));
    }
}
