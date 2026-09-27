//! Registration verifications that a helper runs as sessions of this
//! module's registration verifier. The worker checks each record's header,
//! context and lengths itself, streams the record's bytes to the helper that
//! holds the session and turns the session's verdict into the verified
//! registration. Without helpers the session runs here. Either way the
//! verdict is the registration verifier's for the same bytes, however the
//! worker divides them.
use super::{KEY_BYTES, RegistrationVerifier, VerifiedRegistration};
use crate::{
    Error, SIGNATURE_BYTES, checked_header, foundation::RegistrationHeader, poll::VerifiedPoll,
};
use parallel_work::{Job, Part, Ticket, session, submit};
use registration_verifier::CHUNK_LIMIT;
use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
};

/// Opens, feeds, finishes or discards a helper's registration session. The
/// input is the operation, the session and the operation's bytes.
pub static REGISTRATION: Job = Job { kind: 0x0600, run };
const OPEN: u8 = 0;
const KEY: u8 = 1;
const PROOF: u8 = 2;
const FINISH: u8 = 3;
const DISCARD: u8 = 4;
const OPERATION_BYTES: usize = 9;
/// A verdict: zero, the body digest and the proof hash, or the code of the
/// refusal that ended the session.
const VERDICT_BYTES: usize = 129;
/// The steps a session keeps running before the worker waits for the
/// oldest: a whole record's, so that a busy session's helper holds up no
/// other session's input. The shared arena's bound limits the bytes that
/// queued steps hold.
const WINDOW: usize = 16;

thread_local! {
    // Each open session's verifier, or the refusal that ended it.
    static SESSIONS: RefCell<HashMap<u64, Result<RegistrationVerifier, Error>>> =
        RefCell::default();
}

fn code(error: &Error) -> u8 {
    match error {
        Error::Shape => 1,
        Error::Context => 2,
        Error::Consumed => 3,
        Error::Crypto => 4,
    }
}
fn refusal(code: u8) -> Error {
    match code {
        1 => Error::Shape,
        2 => Error::Context,
        3 => Error::Consumed,
        _ => Error::Crypto,
    }
}

fn run(input: &[u8]) -> Vec<u8> {
    let session = u64::from_le_bytes(input[1..OPERATION_BYTES].try_into().unwrap());
    let bytes = &input[OPERATION_BYTES..];
    SESSIONS.with(|sessions| {
        let mut sessions = sessions.borrow_mut();
        match input[0] {
            OPEN => {
                sessions.insert(session, open(bytes));
                Vec::new()
            }
            KEY | PROOF => {
                let state = sessions.get_mut(&session).expect("An open session");
                if let Ok(verifier) = state
                    && let Err(error) = feed(verifier, input[0], bytes)
                {
                    *state = Err(error);
                }
                Vec::new()
            }
            FINISH => {
                let state = sessions.remove(&session).expect("An open session");
                let result = state.and_then(|mut verifier| {
                    feed(&mut verifier, PROOF, bytes)?;
                    verifier.finish()
                });
                let mut verdict = vec![0; VERDICT_BYTES];
                match result {
                    Ok(record) => {
                        verdict[1..65].copy_from_slice(&record.body_digest);
                        verdict[65..].copy_from_slice(&record.proof_hash);
                    }
                    Err(error) => verdict[0] = code(&error),
                }
                verdict
            }
            DISCARD => {
                sessions.remove(&session);
                Vec::new()
            }
            _ => panic!("Unknown registration operation"),
        }
    })
}

// The poll and runtime identities, the header's length, the header and the
// signature.
fn open(bytes: &[u8]) -> Result<RegistrationVerifier, Error> {
    let length = u32::from_le_bytes(bytes[128..132].try_into().unwrap()) as usize;
    RegistrationVerifier::open(
        bytes[..64].try_into().unwrap(),
        bytes[64..128].try_into().unwrap(),
        &bytes[132..132 + length],
        &bytes[132 + length..],
    )
}

// A complete key, which the key's end follows, or proof bytes.
fn feed(verifier: &mut RegistrationVerifier, operation: u8, bytes: &[u8]) -> Result<(), Error> {
    for part in bytes.chunks(CHUNK_LIMIT) {
        if operation == KEY {
            verifier.push_key(part)?;
        } else {
            verifier.push_proof(part)?;
        }
    }
    if operation == KEY {
        verifier.finish_key()?;
    }
    Ok(())
}

// Starts an operation on the session's shard.
fn send(session: u64, shard: usize, operation: u8, bytes: &[u8], output: usize) -> Ticket {
    let mut header = [0; OPERATION_BYTES];
    header[0] = operation;
    header[1..].copy_from_slice(&session.to_le_bytes());
    submit(
        &REGISTRATION,
        Some(shard),
        &[Part::Bytes(&header), Part::Bytes(bytes)],
        output,
    )
}

/// A registration record whose verification runs as a session on the
/// helper that holds its shard, or here without helpers.
pub struct RegistrationSession {
    session: u64,
    shard: usize,
    header: Option<RegistrationHeader>,
    proof_length: usize,
    key: Vec<u8>,
    key_sent: bool,
    // Proof bytes gathered for the next step, and every proof byte so far.
    proof: Vec<u8>,
    proof_bytes: usize,
    running: VecDeque<Ticket>,
    failed: bool,
    finished: bool,
}
impl RegistrationSession {
    /// Opens the verification of a record of the poll from its header and
    /// detached signature, which this instance checks as the registration
    /// verifier does. Sessions of one shard run in the order they open.
    pub fn open(
        poll: &VerifiedPoll,
        shard: usize,
        header_bytes: &[u8],
        signature: &[u8],
    ) -> Result<Self, Error> {
        let header = checked_header(header_bytes, poll.identity(), poll.runtime())?;
        if signature.len() != SIGNATURE_BYTES {
            return Err(Error::Shape);
        }
        let mut input = Vec::with_capacity(132 + header_bytes.len() + signature.len());
        input.extend(poll.identity());
        input.extend(poll.runtime());
        input.extend((header_bytes.len() as u32).to_le_bytes());
        input.extend(header_bytes);
        input.extend(signature);
        let mut record = Self {
            session: session(),
            shard,
            proof_length: header.proof_length,
            header: Some(header),
            key: Vec::with_capacity(KEY_BYTES),
            key_sent: false,
            proof: Vec::new(),
            proof_bytes: 0,
            running: VecDeque::new(),
            failed: false,
            finished: false,
        };
        let ticket = send(record.session, shard, OPEN, &input, 0);
        record.keep(ticket);
        Ok(record)
    }
    /// The shard whose helper runs the session.
    pub fn shard(&self) -> usize {
        self.shard
    }
    pub fn push_key(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.failed
            || self.key_sent
            || bytes.len() > CHUNK_LIMIT
            || bytes.len() > KEY_BYTES - self.key.len()
        {
            self.failed = true;
            return Err(Error::Shape);
        }
        self.key.extend_from_slice(bytes);
        Ok(())
    }
    /// Sends the complete key, whose hash the session checks.
    pub fn finish_key(&mut self) -> Result<(), Error> {
        if self.failed || self.key_sent || self.key.len() != KEY_BYTES {
            self.failed = true;
            return Err(Error::Shape);
        }
        self.key_sent = true;
        let ticket = send(self.session, self.shard, KEY, &self.key, 0);
        self.keep(ticket);
        Ok(())
    }
    pub fn push_proof(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Consumed);
        }
        if !self.key_sent
            || bytes.len() > CHUNK_LIMIT
            || bytes.len() > self.proof_length - self.proof_bytes
        {
            self.failed = true;
            return Err(Error::Shape);
        }
        self.proof_bytes += bytes.len();
        self.proof.extend_from_slice(bytes);
        if self.proof.len() >= CHUNK_LIMIT {
            let ticket = send(self.session, self.shard, PROOF, &self.proof, 0);
            self.proof.clear();
            self.keep(ticket);
        }
        Ok(())
    }
    /// Sends the rest of the proof and requests the session's verdict.
    pub fn finish(mut self) -> Result<PendingRegistration, Error> {
        if self.failed || !self.key_sent {
            return Err(Error::Consumed);
        }
        let ticket = send(self.session, self.shard, FINISH, &self.proof, VERDICT_BYTES);
        self.finished = true;
        Ok(PendingRegistration {
            ticket,
            header: self.header.take().unwrap(),
            key: std::mem::take(&mut self.key),
        })
    }
    // Keeps a step running, and waits for the oldest beyond the window.
    fn keep(&mut self, ticket: Ticket) {
        self.running.push_back(ticket);
        if self.running.len() > WINDOW {
            self.running.pop_front().unwrap().wait();
        }
    }
}
impl Drop for RegistrationSession {
    // A helper forgets an unfinished session once its steps end.
    fn drop(&mut self) {
        if !self.finished {
            drop(send(self.session, self.shard, DISCARD, &[], 0));
        }
    }
}

/// A finished record whose session's verdict decides it.
pub struct PendingRegistration {
    ticket: Ticket,
    header: RegistrationHeader,
    key: Vec<u8>,
}
impl PendingRegistration {
    /// The verified registration, or the refusal of its verifier.
    pub fn wait(self) -> Result<VerifiedRegistration, Error> {
        let verdict = self.ticket.wait();
        if verdict[0] != 0 {
            return Err(refusal(verdict[0]));
        }
        Ok(VerifiedRegistration {
            header: self.header,
            body_digest: verdict[1..65].try_into().unwrap(),
            proof_hash: verdict[65..].try_into().unwrap(),
            public_key: self.key,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        Credential,
        foundation::{
            StabilizedDisplayText,
            ceremony::{Manifest, OptionDefinition},
            normalize_username,
        },
        poll::{PollDraft, SignedPoll, verify_poll},
    };
    use supported_profile::relation::PROOF_HEADER_BYTES;

    /// A signed poll, its runtime, and the header of a registration of it
    /// with the runtime whose key and proof nothing produced.
    pub(crate) fn unproved_record(runtime: [u8; 64]) -> (SignedPoll, Vec<u8>) {
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
        let mut organizer = Credential::from_seeds([1; 32], [2; 32], [3; 32]);
        let packet = organizer
            .create_poll(draft, [4; 64], [5; 32], [6; 32])
            .unwrap();
        let header = RegistrationHeader {
            username: normalize_username(b"Participant").unwrap(),
            poll: packet.identity,
            runtime,
            signing_public: *organizer.signing_public(),
            mailbox_public: *organizer.mailbox_public(),
            recipient_key_hash: [0; 64],
            proof_length: PROOF_HEADER_BYTES,
        }
        .encode()
        .unwrap();
        (packet, header)
    }

    // A header of another runtime or with extra bytes is refused before any
    // session opens. A dropped session and a finished one leave no state,
    // and a key that does not match its header's hash refuses the session
    // when it finishes, with the verifier's refusal.
    #[test]
    fn sessions_refuse_as_the_verifier_does_and_leave_no_state() {
        let (packet, header) = unproved_record([4; 64]);
        let poll = verify_poll(packet.identity, [4; 64], &packet.body, &packet.signature).unwrap();
        let signature = [0; SIGNATURE_BYTES];
        let (_, foreign) = unproved_record([9; 64]);
        assert!(matches!(
            RegistrationSession::open(&poll, 0, &foreign, &signature),
            Err(Error::Context)
        ));
        let extended = [header.as_slice(), &[0]].concat();
        assert!(matches!(
            RegistrationSession::open(&poll, 0, &extended, &signature),
            Err(Error::Shape)
        ));
        assert!(matches!(
            RegistrationSession::open(&poll, 0, &header, &signature[1..]),
            Err(Error::Shape)
        ));
        let mut session = RegistrationSession::open(&poll, 0, &header, &signature).unwrap();
        assert!(matches!(session.push_proof(&[0]), Err(Error::Shape)));
        drop(session);
        SESSIONS.with(|sessions| assert!(sessions.borrow().is_empty()));
        let mut session = RegistrationSession::open(&poll, 0, &header, &signature).unwrap();
        assert!(matches!(
            session.push_key(&vec![0; CHUNK_LIMIT + 1]),
            Err(Error::Shape)
        ));
        assert!(matches!(session.finish(), Err(Error::Consumed)));
        let mut session = RegistrationSession::open(&poll, 0, &header, &signature).unwrap();
        for part in vec![0; KEY_BYTES].chunks(CHUNK_LIMIT) {
            session.push_key(part).unwrap();
        }
        assert!(matches!(session.push_proof(&[0; 2]), Err(Error::Shape)));
        assert!(matches!(session.finish_key(), Err(Error::Shape)));
        drop(session);
        let mut session = RegistrationSession::open(&poll, 0, &header, &signature).unwrap();
        for part in vec![0; KEY_BYTES].chunks(CHUNK_LIMIT) {
            session.push_key(part).unwrap();
        }
        session.finish_key().unwrap();
        assert!(matches!(
            session.push_proof(&vec![0; PROOF_HEADER_BYTES + 1]),
            Err(Error::Shape)
        ));
        drop(session);
        let mut session = RegistrationSession::open(&poll, 0, &header, &signature).unwrap();
        for part in vec![0; KEY_BYTES].chunks(CHUNK_LIMIT) {
            session.push_key(part).unwrap();
        }
        session.finish_key().unwrap();
        let pending = session.finish().unwrap();
        SESSIONS.with(|sessions| assert!(sessions.borrow().is_empty()));
        assert!(matches!(pending.wait(), Err(Error::Shape)));
    }
}
