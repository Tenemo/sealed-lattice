use crate::{
    layout::Layout,
    operator,
    statement::{Statement, encoded_bytes},
};
use std::io::Read;
use word_verifier::{HEADER_LENGTH, Refusal, engine};

pub const ROLE: &[u8] = b"bounded-outer-seed-sharing-fixture/v1";

#[derive(Debug)]
pub enum VerificationError {
    Read(std::io::Error),
    Refused(Refusal),
}
impl From<Refusal> for VerificationError {
    fn from(value: Refusal) -> Self {
        Self::Refused(value)
    }
}

struct StatementStream {
    expected: Vec<u8>,
    received: usize,
    digest: [u8; 64],
    operator: word_proof::affine::Operator,
    queries: Vec<u32>,
}
impl engine::Statement for StatementStream {
    fn push(&mut self, bytes: &[u8]) -> bool {
        let Some(end) = self.received.checked_add(bytes.len()) else {
            return false;
        };
        if self.expected.get(self.received..end) != Some(bytes) {
            return false;
        }
        self.received = end;
        true
    }
    fn finish(self) -> Option<setup_stream_kernel::SetupStatementOutput> {
        if self.received != self.expected.len() {
            return None;
        }
        let target = self.operator.target;
        let lookup_weight = self.operator.lookup_weight;
        Some(setup_stream_kernel::SetupStatementOutput {
            statement_digest: self.digest,
            target,
            lookup_weight,
            coefficients: self
                .operator
                .at_queries(
                    Layout::new(encoded_bytes()).relation.columns(),
                    &self.queries,
                )
                .ok()?,
        })
    }
}

/// Streaming verification against independently fixed full public operands.
/// A roster identity alone cannot replace this caller's actual keys,
/// ciphertexts, common polynomial or sealed-body binding.
pub struct Verifier(engine::Verifier<StatementStream>);
impl Verifier {
    pub fn open(
        expected: &Statement,
        supplied: &[u8],
        role: &[u8],
        header: &[u8],
    ) -> Result<Self, Refusal> {
        let bytes = expected.encode().map_err(|_| Refusal::Encoding)?;
        let parsed = Statement::decode(supplied, &expected.scope).map_err(|_| Refusal::Encoding)?;
        if parsed != *expected || supplied != bytes {
            return Err(Refusal::Context);
        }
        let digest = expected.digest().map_err(|_| Refusal::Encoding)?;
        let relation = Layout::new(encoded_bytes()).relation;
        let mut verifier =
            engine::Verifier::open(relation, role, digest, header, |alpha, queries| {
                Some(StatementStream {
                    expected: bytes,
                    received: 0,
                    digest,
                    operator: operator::build(expected, alpha).ok()?,
                    queries: queries.to_vec(),
                })
            })?;
        for chunk in supplied.chunks(engine::CHUNK_LIMIT) {
            verifier.push_statement(chunk)?;
        }
        verifier.finish_statement()?;
        Ok(Self(verifier))
    }
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        self.0.push_proof(bytes)
    }
    pub fn finish(self) -> Result<(), Refusal> {
        if self.0.finish() {
            Ok(())
        } else {
            Err(Refusal::Relation)
        }
    }
}

pub fn verify(
    input: &mut impl Read,
    expected: &Statement,
    supplied: &[u8],
    role: &[u8],
) -> Result<(), VerificationError> {
    let mut header = vec![0; HEADER_LENGTH];
    input.read_exact(&mut header).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            VerificationError::Refused(Refusal::Length)
        } else {
            VerificationError::Read(error)
        }
    })?;
    let mut verifier = Verifier::open(expected, supplied, role, &header)?;
    let mut buffer = vec![0; engine::CHUNK_LIMIT];
    loop {
        let count = input.read(&mut buffer).map_err(VerificationError::Read)?;
        if count == 0 {
            break;
        }
        verifier.push(&buffer[..count])?;
    }
    verifier.finish().map_err(VerificationError::Refused)
}
