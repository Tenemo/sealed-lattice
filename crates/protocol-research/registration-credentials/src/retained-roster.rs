//! A roster proposal whose every registration this participant's roster
//! verifier accepted, retained beneath the participant root and keyed to the
//! credential. It binds each record's body digest to the proposal identity.
//! The digest is recomputed from the complete header, so a later visit of the same
//! participant restores the verifier's result from the published headers and
//! keys alone: each header must be the one the verifier accepted and each key
//! must hash to the value its header names.
use crate::{Credential, Error, RETAINED_TAG_BYTES, poll::VerifiedPoll, roster::RosterProposal};

const LABEL: &[u8] = b"sealed-lattice/retained-roster/v2";
const MAGIC: &[u8; 4] = b"RRV2";
// Each record's body digest, recomputed from its canonical header.
const RECORD_BYTES: usize = 64;

/// The retained roster of this many registrations has this exact length.
pub fn retained_roster_bytes(participants: usize) -> usize {
    MAGIC.len() + 64 + 2 + participants * RECORD_BYTES + RETAINED_TAG_BYTES
}

impl Credential {
    /// Encodes the proposal that the roster verifier built from the records
    /// it accepted and keys it to this credential.
    pub fn retain_roster(
        &self,
        poll: &VerifiedPoll,
        proposal: &RosterProposal,
    ) -> Result<Vec<u8>, Error> {
        let records = proposal.records();
        let mut bytes = Vec::with_capacity(retained_roster_bytes(records.len()));
        bytes.extend(MAGIC);
        bytes.extend(proposal.identity());
        bytes.extend((records.len() as u16).to_le_bytes());
        for record in records {
            bytes.extend(record.body_digest());
        }
        let tag = self.retained_tag(LABEL, poll, &bytes);
        bytes.extend(tag);
        Ok(bytes)
    }
}

/// What the registration verifier accepted for one record.
pub(crate) struct RetainedRecord {
    pub(crate) body_digest: [u8; 64],
}

/// A retained roster of the poll whose tag the credential accepted.
pub(crate) struct RetainedRoster {
    pub(crate) identity: [u8; 64],
    pub(crate) records: Vec<RetainedRecord>,
}
impl RetainedRoster {
    pub(crate) fn parse(
        credential: &Credential,
        poll: &VerifiedPoll,
        participants: usize,
        bytes: &[u8],
    ) -> Result<Self, Error> {
        if bytes.len() != retained_roster_bytes(participants)
            || &bytes[..4] != MAGIC
            || u16::from_le_bytes(bytes[68..70].try_into().unwrap()) as usize != participants
        {
            return Err(Error::Shape);
        }
        let (body, tag) = bytes.split_at(bytes.len() - RETAINED_TAG_BYTES);
        credential.check_retained_tag(LABEL, poll, body, tag)?;
        Ok(Self {
            identity: body[4..68].try_into().unwrap(),
            records: body[70..]
                .chunks_exact(RECORD_BYTES)
                .map(|record| RetainedRecord {
                    body_digest: record.try_into().unwrap(),
                })
                .collect(),
        })
    }
}

#[cfg(test)]
#[path = "retained-roster-tests.rs"]
mod tests;
