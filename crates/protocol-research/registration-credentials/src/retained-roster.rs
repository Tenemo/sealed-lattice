//! A roster proposal whose every registration this participant's roster
//! verifier accepted, retained beneath the participant root and keyed to the
//! credential. It binds each record's exact header bytes, body digest and
//! proof hash to the proposal identity, so a later visit of the same
//! participant restores the verifier's result from the published headers and
//! keys alone: each header must be the one the verifier accepted and each key
//! must hash to the value its header names.
use crate::{Credential, Error, RETAINED_TAG_BYTES, poll::VerifiedPoll, roster::RosterProposal};
use sha3::{Digest, Sha3_512};

const LABEL: &[u8] = b"sealed-lattice/retained-roster/v1";
const MAGIC: &[u8; 4] = b"RRV1";
// Each record's header digest, body digest and proof hash.
const RECORD_BYTES: usize = 3 * 64;

/// The retained roster of this many registrations has this exact length.
pub fn retained_roster_bytes(participants: usize) -> usize {
    MAGIC.len() + 64 + 2 + participants * RECORD_BYTES + RETAINED_TAG_BYTES
}

pub(crate) fn header_digest(header: &[u8]) -> [u8; 64] {
    Sha3_512::digest(header).into()
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
            bytes.extend(header_digest(&record.header().encode()?));
            bytes.extend(record.body_digest());
            bytes.extend(record.proof_hash());
        }
        let tag = self.retained_tag(LABEL, poll, &bytes);
        bytes.extend(tag);
        Ok(bytes)
    }
}

/// What the registration verifier accepted for one record.
pub(crate) struct RetainedRecord {
    pub(crate) header_digest: [u8; 64],
    pub(crate) body_digest: [u8; 64],
    pub(crate) proof_hash: [u8; 64],
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
                    header_digest: record[..64].try_into().unwrap(),
                    body_digest: record[64..128].try_into().unwrap(),
                    proof_hash: record[128..].try_into().unwrap(),
                })
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        foundation::{
            RegistrationHeader, StabilizedDisplayText,
            ceremony::{Manifest, OptionDefinition},
            normalize_username,
        },
        poll::{PollDraft, SignedPoll, verify_poll},
        registration::{KEY_BYTES, VerifiedRegistration},
        roster_input::RosterInputVerifier,
    };
    use registration_verifier::CHUNK_LIMIT;
    use std::sync::Arc;
    use supported_profile::relation::PROOF_HEADER_BYTES;

    struct Ceremony {
        packet: SignedPoll,
        poll: VerifiedPoll,
        credentials: Vec<Credential>,
        headers: Vec<Vec<u8>>,
        keys: Vec<Vec<u8>>,
        proposal: RosterProposal,
    }

    // An organizer and two members, each with a distinct key whose hash its
    // header names, in a proposal of the records the verifier would accept.
    fn ceremony(runtime: [u8; 64]) -> Ceremony {
        let text =
            |value: &str| StabilizedDisplayText::from_ingress_utf8(value.as_bytes()).unwrap();
        let options = (0..2)
            .map(|index| {
                OptionDefinition::new(
                    index,
                    format!("option-{index}"),
                    text(&format!("Option {index}")),
                )
                .unwrap()
            })
            .collect();
        let draft = PollDraft::new(Manifest::new(text("Question"), options).unwrap(), 2).unwrap();
        let mut credentials: Vec<Credential> = (0..3u8)
            .map(|seed| Credential::from_seeds([seed + 1; 32], [seed + 11; 32], [seed + 21; 32]))
            .collect();
        let packet = credentials[0]
            .create_poll(draft, runtime, [5; 32], [6; 32])
            .unwrap();
        let poll = verify_poll(packet.identity, runtime, &packet.body, &packet.signature).unwrap();
        let keys: Vec<Vec<u8>> = (0..3u8)
            .map(|seed| (0..KEY_BYTES).map(|index| (index as u8) ^ seed).collect())
            .collect();
        let mut headers = Vec::new();
        let mut records = Vec::new();
        for (position, credential) in credentials.iter().enumerate() {
            let header = RegistrationHeader {
                username: normalize_username(format!("Participant {position}").as_bytes()).unwrap(),
                poll: poll.identity(),
                runtime,
                signing_public: *credential.signing_public(),
                mailbox_public: *credential.mailbox_public(),
                recipient_key_hash: Sha3_512::digest(&keys[position]).into(),
                proof_length: PROOF_HEADER_BYTES + position,
            };
            headers.push(header.encode().unwrap());
            records.push(Arc::new(VerifiedRegistration::restored(
                header,
                [position as u8 + 31; 64],
                [position as u8 + 41; 64],
                keys[position].clone(),
            )));
        }
        let proposal = RosterProposal::new(&poll, records).unwrap();
        Ceremony {
            packet,
            poll,
            credentials,
            headers,
            keys,
            proposal,
        }
    }

    fn begin_input(ceremony: &Ceremony, count: u16) -> Vec<u8> {
        [
            ceremony.packet.identity.as_slice(),
            &ceremony.poll.runtime(),
            &count.to_le_bytes(),
            &(ceremony.packet.body.len() as u32).to_le_bytes(),
            &ceremony.packet.body,
            &ceremony.packet.signature,
        ]
        .concat()
    }

    fn header_input(position: u16, header: &[u8]) -> Vec<u8> {
        [
            position.to_le_bytes().as_slice(),
            &(header.len() as u32).to_le_bytes(),
            header,
        ]
        .concat()
    }

    // Streams each record's header and key into the verifier, as the host
    // does, and finishes the roster.
    fn restore(
        verifier: &mut RosterInputVerifier,
        headers: &[Vec<u8>],
        keys: &[Vec<u8>],
    ) -> Result<RosterProposal, Error> {
        for (position, (header, key)) in headers.iter().zip(keys).enumerate() {
            verifier.begin_record(&header_input(position as u16, header))?;
            for part in key.chunks(CHUNK_LIMIT) {
                verifier.push_key(position, part)?;
            }
            verifier.finish_key(position)?;
            verifier.finish_record(position)?;
        }
        verifier.finish()
    }

    // The restored proposal is the retained one, record for record, from
    // the published headers and keys alone.
    #[test]
    fn retained_rosters_restore_the_verified_proposal() {
        let ceremony = ceremony([4; 64]);
        for credential in &ceremony.credentials {
            let retained = credential
                .retain_roster(&ceremony.poll, &ceremony.proposal)
                .unwrap();
            assert_eq!(retained.len(), retained_roster_bytes(3));
            let mut verifier =
                RosterInputVerifier::retained(&begin_input(&ceremony, 3), credential, &retained)
                    .unwrap();
            assert!(verifier.is_retained());
            let restored = restore(&mut verifier, &ceremony.headers, &ceremony.keys).unwrap();
            assert_eq!(restored.identity(), ceremony.proposal.identity());
            assert_eq!(restored.body(), ceremony.proposal.body());
            for (left, right) in restored.records().iter().zip(ceremony.proposal.records()) {
                assert_eq!(
                    left.header().encode().unwrap(),
                    right.header().encode().unwrap()
                );
                assert_eq!(left.body_digest(), right.body_digest());
                assert_eq!(left.proof_hash(), right.proof_hash());
                assert_eq!(left.public_key(), right.public_key());
            }
            // The organizer's signature and every later consumer see the
            // same proposal again.
            assert_eq!(
                verifier.finish().unwrap().identity(),
                ceremony.proposal.identity()
            );
        }
    }

    // Only the credential that retained the roster, for the same poll and
    // runtime and the same record count, restores its exact bytes.
    #[test]
    fn retained_rosters_bind_the_credential_poll_count_and_exact_bytes() {
        let ceremony = ceremony([4; 64]);
        let owner = &ceremony.credentials[1];
        let retained = owner
            .retain_roster(&ceremony.poll, &ceremony.proposal)
            .unwrap();
        let begin = begin_input(&ceremony, 3);
        let refused = |credential: &Credential, begin: &[u8], retained: &[u8]| {
            RosterInputVerifier::retained(begin, credential, retained).is_err()
        };
        assert!(!refused(owner, &begin, &retained));
        // Another signing seed, even with the same mailbox seeds.
        let other = Credential::from_seeds([9; 32], [12; 32], [22; 32]);
        assert!(refused(&other, &begin, &retained));
        assert!(refused(&ceremony.credentials[2], &begin, &retained));
        // The same records under a poll of another runtime.
        let foreign = super::tests::ceremony([7; 64]);
        assert!(refused(owner, &begin_input(&foreign, 3), &retained));
        // A roster of another size.
        assert!(refused(owner, &begin_input(&ceremony, 4), &retained));
        // Every changed, missing or extra byte.
        for position in [
            0,
            4,
            67,
            68,
            70,
            70 + 64,
            70 + 3 * RECORD_BYTES - 1,
            retained.len() - 1,
        ] {
            let mut changed = retained.clone();
            changed[position] ^= 1;
            assert!(refused(owner, &begin, &changed), "{position}");
        }
        assert!(refused(owner, &begin, &retained[..retained.len() - 1]));
        assert!(refused(
            owner,
            &begin,
            &[retained.as_slice(), &[0]].concat()
        ));
    }

    // Each record takes exactly the header the verifier accepted, without a
    // signature or proof, and exactly the key that header names; any other
    // input refuses the record and the roster.
    #[test]
    fn restored_records_refuse_other_headers_keys_and_proofs() {
        let ceremony = ceremony([4; 64]);
        let owner = &ceremony.credentials[0];
        let retained = owner
            .retain_roster(&ceremony.poll, &ceremony.proposal)
            .unwrap();
        let verifier =
            || RosterInputVerifier::retained(&begin_input(&ceremony, 3), owner, &retained).unwrap();
        // Two records' headers exchanged.
        let mut swapped = ceremony.headers.clone();
        swapped.swap(1, 2);
        let mut keys = ceremony.keys.clone();
        keys.swap(1, 2);
        assert!(matches!(
            restore(&mut verifier(), &swapped, &keys),
            Err(Error::Context)
        ));
        // A header with its signature, as a record to verify begins.
        let mut signed = verifier();
        let with_signature = [
            header_input(0, &ceremony.headers[0]).as_slice(),
            &[0; crate::SIGNATURE_BYTES],
        ]
        .concat();
        assert!(signed.begin_record(&with_signature).is_err());
        assert!(
            signed
                .begin_record(&header_input(0, &ceremony.headers[0]))
                .is_ok()
        );
        // A key with one changed byte, a short key and an overlong one.
        let mut changed = ceremony.keys.clone();
        changed[2][KEY_BYTES / 2] ^= 1;
        assert!(restore(&mut verifier(), &ceremony.headers, &changed).is_err());
        let mut short = ceremony.keys.clone();
        short[1].pop();
        assert!(restore(&mut verifier(), &ceremony.headers, &short).is_err());
        let mut long = ceremony.keys.clone();
        long[0].push(0);
        assert!(restore(&mut verifier(), &ceremony.headers, &long).is_err());
        // Proof bytes refuse the record, which takes nothing more.
        let mut proved = verifier();
        proved
            .begin_record(&header_input(0, &ceremony.headers[0]))
            .unwrap();
        assert!(proved.push_proof(0, &[0; 16]).is_err());
        assert!(proved.push_key(0, &[0; 16]).is_err());
        assert!(proved.finish().is_err());
        // A record finished before its key is refused, and a position
        // begins once.
        let mut early = verifier();
        early
            .begin_record(&header_input(1, &ceremony.headers[1]))
            .unwrap();
        assert!(early.finish_record(1).is_err());
        assert!(
            early
                .begin_record(&header_input(1, &ceremony.headers[1]))
                .is_err()
        );
        // A record missing from the stream leaves the roster unfinished.
        assert!(matches!(
            restore(&mut verifier(), &ceremony.headers[..2], &ceremony.keys[..2]),
            Err(Error::Shape)
        ));
    }

    // A tagged roster whose identity is not its records' proposal restores
    // nothing: the verifier checks the proposal it builds, not the tag alone.
    #[test]
    fn restored_proposals_must_have_the_retained_identity() {
        let ceremony = ceremony([4; 64]);
        let owner = &ceremony.credentials[0];
        let retained = owner
            .retain_roster(&ceremony.poll, &ceremony.proposal)
            .unwrap();
        let mut body = retained[..retained.len() - RETAINED_TAG_BYTES].to_vec();
        body[4] ^= 1;
        let tag = owner.retained_tag(LABEL, &ceremony.poll, &body);
        let forged = [body.as_slice(), &tag].concat();
        let mut verifier =
            RosterInputVerifier::retained(&begin_input(&ceremony, 3), owner, &forged).unwrap();
        assert!(matches!(
            restore(&mut verifier, &ceremony.headers, &ceremony.keys),
            Err(Error::Context)
        ));
        assert!(matches!(verifier.finish(), Err(Error::Consumed)));
    }
}
