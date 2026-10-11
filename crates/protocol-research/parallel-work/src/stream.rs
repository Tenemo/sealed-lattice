//! Hashes of long byte streams whose sponge one helper holds. The caller
//! streams the bytes to that helper and waits only for the digest, so the
//! hashing overlaps its own work and the other streams'. Without helpers, or
//! for a caller that needs the digest at once, the sponge stays here. Either
//! way the digest equals the one this instance computes alone, however the
//! bytes are divided.
use crate::ProtocolHash;
use crate::{Job, Part, Ticket, helpers, session, submit};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
};

/// The sponges a stream computes, each with a 64-byte digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sponge {
    ProtocolHash,
    /// The first 64 bytes of SHAKE256's output.
    Shake256,
}

enum Local {
    ProtocolHash(ProtocolHash),
    Shake256(Shake256),
}
impl Local {
    fn new(sponge: Sponge) -> Self {
        match sponge {
            Sponge::ProtocolHash => Self::ProtocolHash(ProtocolHash::new()),
            Sponge::Shake256 => Self::Shake256(Shake256::default()),
        }
    }
    fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::ProtocolHash(hash) => hash.update(bytes),
            Self::Shake256(hash) => Update::update(hash, bytes),
        }
    }
    fn finish(self) -> [u8; 64] {
        match self {
            Self::ProtocolHash(hash) => hash.finalize(),
            Self::Shake256(hash) => {
                let mut digest = [0; 64];
                hash.finalize_xof().read(&mut digest);
                digest
            }
        }
    }
}

/// Absorbs bytes into a helper's stream, finishes it or discards it. The
/// input is the operation, the sponge, the stream's session and the bytes.
pub static STREAM: Job = Job {
    kind: 0x0400,
    run: stream,
};
const ABSORB: u8 = 0;
const FINISH: u8 = 1;
const DISCARD: u8 = 2;
const HEADER_BYTES: usize = 10;

thread_local! {static STREAMS: RefCell<HashMap<u64, Local>> = RefCell::default();}

fn stream(input: &[u8]) -> Vec<u8> {
    let sponge = match input[1] {
        0 => Sponge::ProtocolHash,
        1 => Sponge::Shake256,
        _ => panic!("Unknown sponge"),
    };
    let session = u64::from_le_bytes(input[2..HEADER_BYTES].try_into().unwrap());
    let bytes = &input[HEADER_BYTES..];
    STREAMS.with(|streams| {
        let mut streams = streams.borrow_mut();
        match input[0] {
            ABSORB => {
                streams
                    .entry(session)
                    .or_insert_with(|| Local::new(sponge))
                    .update(bytes);
                Vec::new()
            }
            FINISH => {
                let mut local = streams
                    .remove(&session)
                    .unwrap_or_else(|| Local::new(sponge));
                local.update(bytes);
                local.finish().to_vec()
            }
            DISCARD => {
                streams.remove(&session);
                Vec::new()
            }
            _ => panic!("Unknown stream operation"),
        }
    })
}

/// Bytes a stream gathers before it sends them to its helper.
const BATCH_BYTES: usize = 1 << 16;
/// The most bytes one absorption sends.
const SEND_BYTES: usize = 1 << 20;
/// The absorptions a stream keeps running before it waits for the oldest,
/// which bounds the shared memory its bytes hold.
const WINDOW: usize = 4;

struct Remote {
    session: u64,
    pending: Vec<u8>,
    running: VecDeque<Ticket>,
}

/// A 64-byte hash of the bytes streamed into it.
pub struct HashStream {
    sponge: Sponge,
    local: Option<Local>,
    remote: Option<Remote>,
}

impl HashStream {
    /// An empty stream, held by a helper when there are helpers.
    pub fn new(sponge: Sponge) -> Self {
        Self::held(sponge, helpers() > 0)
    }
    /// An empty stream that this instance holds. A caller that waits for
    /// the digest right after its last bytes gains nothing from a helper,
    /// whose queue and wake would only delay the digest.
    pub fn local(sponge: Sponge) -> Self {
        Self::held(sponge, false)
    }
    fn held(sponge: Sponge, remote: bool) -> Self {
        Self {
            sponge,
            local: (!remote).then(|| Local::new(sponge)),
            remote: remote.then(|| Remote {
                session: session(),
                pending: Vec::new(),
                running: VecDeque::new(),
            }),
        }
    }
    pub fn update(&mut self, mut bytes: &[u8]) {
        if let Some(local) = &mut self.local {
            local.update(bytes);
            return;
        }
        let sponge = self.sponge;
        let remote = self.remote.as_mut().expect("A stream is held somewhere");
        // Gathered bytes leave as one batch once they fill it.
        if !remote.pending.is_empty() {
            let count = bytes.len().min(BATCH_BYTES - remote.pending.len());
            remote.pending.extend_from_slice(&bytes[..count]);
            bytes = &bytes[count..];
            if remote.pending.len() < BATCH_BYTES {
                return;
            }
            let pending = std::mem::take(&mut remote.pending);
            remote.keep(send(sponge, remote.session, ABSORB, &pending, 0));
        }
        if bytes.len() < BATCH_BYTES {
            remote.pending.extend_from_slice(bytes);
            return;
        }
        for part in bytes.chunks(SEND_BYTES) {
            remote.keep(send(sponge, remote.session, ABSORB, part, 0));
        }
    }
    pub fn finish(self) -> [u8; 64] {
        self.finish_later().wait()
    }
    /// Starts the digest without waiting for it, so the caller's work goes
    /// on while the stream's helper finishes it. An unwaited digest is still
    /// computed and then cleared.
    pub fn finish_later(mut self) -> PendingDigest {
        if let Some(local) = self.local.take() {
            return PendingDigest(Digesting::Ready(local.finish()));
        }
        let remote = self.remote.take().expect("A stream is held somewhere");
        // The helper finishes the stream after its earlier absorptions.
        let finish = send(self.sponge, remote.session, FINISH, &remote.pending, 64);
        PendingDigest(Digesting::Remote {
            earlier: remote.running,
            finish,
        })
    }
}

/// A stream's digest, which its helper may still be computing.
pub struct PendingDigest(Digesting);
enum Digesting {
    Ready([u8; 64]),
    Remote {
        earlier: VecDeque<Ticket>,
        finish: Ticket,
    },
}

impl PendingDigest {
    pub fn wait(self) -> [u8; 64] {
        match self.0 {
            Digesting::Ready(digest) => digest,
            Digesting::Remote { earlier, finish } => {
                for ticket in earlier {
                    ticket.wait();
                }
                finish.wait().as_slice().try_into().unwrap()
            }
        }
    }
}

impl Remote {
    fn keep(&mut self, ticket: Ticket) {
        self.running.push_back(ticket);
        if self.running.len() > WINDOW {
            self.running.pop_front().unwrap().wait();
        }
    }
}

// Starts an operation on the stream's helper.
fn send(sponge: Sponge, session: u64, operation: u8, bytes: &[u8], output: usize) -> Ticket {
    let mut header = [0; HEADER_BYTES];
    header[0] = operation;
    header[1] = match sponge {
        Sponge::ProtocolHash => 0,
        Sponge::Shake256 => 1,
    };
    header[2..].copy_from_slice(&session.to_le_bytes());
    submit(
        &STREAM,
        Some(session as usize),
        &[Part::Bytes(&header), Part::Bytes(bytes)],
        output,
    )
}

impl Drop for HashStream {
    // A helper forgets an unfinished stream once its absorptions end.
    fn drop(&mut self) {
        if let Some(remote) = self.remote.take() {
            drop(send(self.sponge, remote.session, DISCARD, &[], 0));
        }
    }
}

#[cfg(test)]
#[path = "stream-tests.rs"]
mod tests;
