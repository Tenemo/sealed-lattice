//! Registration verifications that a helper runs as sessions of this
//! module's registration verifier. The worker checks each record's header,
//! context and lengths itself, streams the record's bytes to the helper that
//! holds the session and turns the session's verdict into the verified
//! registration. Without helpers the session runs here. Either way the
//! verdict is the registration verifier's for the same bytes, however the
//! worker divides them.
use super::{KEY_BYTES, RegistrationVerifier, VerifiedRegistration};
use crate::registration::CHUNK_LIMIT;
use crate::{
    Error, SIGNATURE_BYTES, checked_header, foundation::RegistrationHeader, poll::VerifiedPoll,
};
use parallel_work::{Job, Part, Ticket, session, submit};
use std::{cell::RefCell, collections::HashMap};

/// Opens, feeds, finishes or discards a helper's registration session. The
/// input is the operation, the session and the operation's bytes.
pub static REGISTRATION: Job = Job { kind: 0x0600, run };
const OPEN: u8 = 0;
const KEY: u8 = 1;
const FINISH: u8 = 2;
const DISCARD: u8 = 3;
const OPERATION_BYTES: usize = 9;
/// A verdict: zero, the body digest, or the code of the
/// refusal that ended the session.
const VERDICT_BYTES: usize = 65;

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
            KEY => {
                let state = sessions.get_mut(&session).expect("An open session");
                if let Ok(verifier) = state
                    && let Err(error) = feed(verifier, bytes)
                {
                    *state = Err(error);
                }
                Vec::new()
            }
            FINISH => {
                let state = sessions.remove(&session).expect("An open session");
                let result = state.and_then(|verifier| {
                    if !bytes.is_empty() {
                        return Err(Error::Shape);
                    }
                    verifier.finish()
                });
                let mut verdict = vec![0; VERDICT_BYTES];
                match result {
                    Ok(record) => {
                        verdict[1..65].copy_from_slice(&record.body_digest);
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

// Checks a complete key at its owning verifier.
fn feed(verifier: &mut RegistrationVerifier, bytes: &[u8]) -> Result<(), Error> {
    for part in bytes.chunks(CHUNK_LIMIT) {
        verifier.push_key(part)?;
    }
    verifier.finish_key()
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
    key: Vec<u8>,
    key_sent: bool,
    running: Vec<Ticket>,
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
        let header = checked_header(header_bytes, poll)?;
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
            header: Some(header),
            key: Vec::with_capacity(KEY_BYTES),
            key_sent: false,
            running: Vec::new(),
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

    /// Requests the owning verifier's verdict for the complete record.
    pub fn finish(mut self) -> Result<PendingRegistration, Error> {
        if self.failed || !self.key_sent {
            return Err(Error::Consumed);
        }
        let ticket = send(self.session, self.shard, FINISH, &[], VERDICT_BYTES);
        self.finished = true;
        Ok(PendingRegistration {
            ticket,
            header: self.header.take().unwrap(),
            key: std::mem::take(&mut self.key),
        })
    }
    // Retains the header and key jobs until the record finishes or is dropped.
    fn keep(&mut self, ticket: Ticket) {
        self.running.push(ticket);
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
            public_key: self.key,
        })
    }
}

#[cfg(test)]
#[path = "registration-session-tests.rs"]
pub(crate) mod tests;
