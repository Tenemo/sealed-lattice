use crate::{
    Credential, Error, SIGNATURE_BYTES, checked_header,
    foundation::RegistrationHeader,
    poll::{VerifiedPoll, verify_poll},
    registration::{
        KEY_BYTES, VerifiedRegistration,
        session::{PendingRegistration, RegistrationSession},
    },
    retained_roster::{RetainedRecord, RetainedRoster, header_digest},
    roster::RosterProposal,
};
use parallel_work::{Digest, ProtocolHash};
use registration_proof::CHUNK_LIMIT;

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
    // A record of a retained roster, awaiting its header.
    Retained(RetainedRecord),
    // Its accepted header, awaiting the key that header names.
    Restoring {
        header: RegistrationHeader,
        record: RetainedRecord,
        key: Vec<u8>,
        key_finished: bool,
    },
    Restored(Arc<VerifiedRegistration>),
    Refused,
}

/// Incremental public input verification; no participant signing authority.
pub struct RosterInputVerifier {
    poll: VerifiedPoll,
    records: Vec<Record>,
    // The shards no open record's session holds.
    shards: Vec<usize>,
    // The proposal identity of the retained roster this verifier restores.
    retained: Option<[u8; 64]>,
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
        if count > usize::from(poll.maximum_participants()) {
            return Err(Error::Context);
        }
        Ok(Self {
            poll,
            records: (0..count).map(|_| Record::Unread).collect(),
            shards: (0..open_record_limit()).rev().collect(),
            retained: None,
            verified: None,
            failed: false,
        })
    }
    /// Restores the result of this participant's earlier roster verification
    /// from the retained roster its credential keyed: each record takes only
    /// the header the verifier accepted and the key that header names, and
    /// the proposal must be the retained one. The poll is verified again.
    pub fn retained(input: &[u8], credential: &Credential, retained: &[u8]) -> Result<Self, Error> {
        let mut verifier = Self::new(input)?;
        let roster =
            RetainedRoster::parse(credential, &verifier.poll, verifier.records.len(), retained)?;
        verifier.records = roster.records.into_iter().map(Record::Retained).collect();
        verifier.retained = Some(roster.identity);
        Ok(verifier)
    }
    /// Whether this verifier restores a retained roster rather than
    /// verifying every record.
    pub fn is_retained(&self) -> bool {
        self.retained.is_some()
    }
    pub fn poll(&self) -> &VerifiedPoll {
        &self.poll
    }
    /// Opens the record at its position, which no earlier record took: a
    /// record to verify with its header and signature while fewer than the
    /// open-record limit are open, a retained record with its header alone.
    pub fn begin_record(&mut self, input: &[u8]) -> Result<(), Error> {
        if !(6..=6 + 4096 + 3309).contains(&input.len()) {
            return Err(Error::Shape);
        }
        let position = u16::from_le_bytes(input[..2].try_into().unwrap()) as usize;
        let length = u32::from_le_bytes(input[2..6].try_into().unwrap()) as usize;
        if length > 4096 || input.len() < 6 + length {
            return Err(Error::Shape);
        }
        let (header, signature) = input[6..].split_at(length);
        match self.records.get(position) {
            Some(Record::Unread) if signature.len() == SIGNATURE_BYTES => {
                let shard = self.shards.pop().ok_or(Error::Shape)?;
                match RegistrationSession::open(&self.poll, shard, header, signature) {
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
            Some(Record::Retained(_)) if signature.is_empty() => {
                let Record::Retained(record) =
                    std::mem::replace(&mut self.records[position], Record::Refused)
                else {
                    unreachable!()
                };
                if header_digest(header) != record.header_digest {
                    return Err(Error::Context);
                }
                let header = checked_header(header, self.poll.identity(), self.poll.runtime())?;
                self.records[position] = Record::Restoring {
                    header,
                    record,
                    key: Vec::with_capacity(KEY_BYTES),
                    key_finished: false,
                };
                Ok(())
            }
            _ => Err(Error::Shape),
        }
    }
    // Refuses the restored record at its position, which then refuses the
    // roster.
    fn refuse(&mut self, position: usize) -> Result<(), Error> {
        self.records[position] = Record::Refused;
        Err(Error::Shape)
    }
    pub fn push_key(&mut self, position: usize, bytes: &[u8]) -> Result<(), Error> {
        match self.records.get_mut(position) {
            Some(Record::Open(session)) => session.push_key(bytes),
            Some(Record::Restoring {
                key,
                key_finished: false,
                ..
            }) if bytes.len() <= CHUNK_LIMIT && bytes.len() <= KEY_BYTES - key.len() => {
                key.extend(bytes);
                Ok(())
            }
            Some(Record::Restoring { .. }) => self.refuse(position),
            _ => Err(Error::Shape),
        }
    }
    pub fn finish_key(&mut self, position: usize) -> Result<(), Error> {
        match self.records.get_mut(position) {
            Some(Record::Open(session)) => session.finish_key(),
            Some(Record::Restoring {
                header,
                key,
                key_finished,
                ..
            }) if !*key_finished
                && key.len() == KEY_BYTES
                && <[u8; 64]>::from(ProtocolHash::digest(&key[..]))
                    == header.recipient_key_hash =>
            {
                *key_finished = true;
                Ok(())
            }
            Some(Record::Restoring { .. }) => self.refuse(position),
            _ => Err(Error::Shape),
        }
    }
    /// Feeds the proof of a record to verify; a restored record takes none.
    pub fn push_proof(&mut self, position: usize, bytes: &[u8]) -> Result<(), Error> {
        match self.records.get_mut(position) {
            Some(Record::Open(session)) => session.push_proof(bytes),
            Some(Record::Restoring { .. }) => self.refuse(position),
            _ => Err(Error::Shape),
        }
    }
    /// Closes the record at its position: a verified record's session
    /// decides it when the roster finishes, and a restored record is the
    /// registration its retained roster names once its key is complete.
    pub fn finish_record(&mut self, position: usize) -> Result<(), Error> {
        match self.records.get(position) {
            Some(Record::Open(_)) => {
                let Record::Open(session) =
                    std::mem::replace(&mut self.records[position], Record::Refused)
                else {
                    unreachable!()
                };
                self.shards.push(session.shard());
                self.records[position] = Record::Finished(session.finish()?);
                Ok(())
            }
            Some(Record::Restoring {
                key_finished: true, ..
            }) => {
                let Record::Restoring {
                    header,
                    record,
                    key,
                    ..
                } = std::mem::replace(&mut self.records[position], Record::Refused)
                else {
                    unreachable!()
                };
                self.records[position] =
                    Record::Restored(Arc::new(VerifiedRegistration::restored(
                        header,
                        record.body_digest,
                        record.proof_hash,
                        key,
                    )));
                Ok(())
            }
            Some(Record::Restoring { .. }) => self.refuse(position),
            _ => Err(Error::Shape),
        }
    }
    /// The proposal of every record, each verified by its session or
    /// restored from the retained roster, which must name this proposal.
    pub fn finish(&mut self) -> Result<RosterProposal, Error> {
        if self.failed {
            return Err(Error::Consumed);
        }
        if self.verified.is_none() {
            if !self
                .records
                .iter()
                .all(|record| matches!(record, Record::Finished(_) | Record::Restored(_)))
            {
                return Err(Error::Shape);
            }
            let mut verified = Vec::with_capacity(self.records.len());
            for record in std::mem::take(&mut self.records) {
                match record {
                    Record::Finished(pending) => match pending.wait() {
                        Ok(registration) => verified.push(Arc::new(registration)),
                        Err(error) => {
                            self.failed = true;
                            return Err(error);
                        }
                    },
                    Record::Restored(registration) => verified.push(registration),
                    _ => unreachable!(),
                }
            }
            self.verified = Some(verified);
        }
        let proposal = RosterProposal::new(&self.poll, self.verified.clone().unwrap())?;
        if self
            .retained
            .is_some_and(|identity| identity != proposal.identity())
        {
            self.failed = true;
            return Err(Error::Context);
        }
        Ok(proposal)
    }
    pub fn into_poll(self) -> VerifiedPoll {
        self.poll
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registration::{KEY_BYTES, session::tests::unproved_record};
    use registration_proof::CHUNK_LIMIT;

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
        // The poll admits at most three participants, so a roster of four
        // is refused before any record opens.
        let above = [&input[..128], &4u16.to_le_bytes(), &input[130..]].concat();
        assert!(matches!(
            RosterInputVerifier::new(&above),
            Err(Error::Context)
        ));
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
