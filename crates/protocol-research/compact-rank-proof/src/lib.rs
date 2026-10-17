//! The compact proof's rank relation, checked against immutable canonical bytes.
//!
//! This relation check grants no participant or release authority. Its caller
//! must authenticate the original owner and every preceding protocol record
//! before using the relation in a protocol. It is not an outcome verifier.

mod authentication;
mod field;
mod frontend;
mod layout;
mod plan;
mod reader;
mod relation;
mod statement;
mod transcript;
mod verifier;

#[cfg(test)]
mod tests;

#[cfg(feature = "screen")]
pub mod screen;

/// A malformed statement or a failed proof check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Statement,
    Encoding,
    Context,
    Authentication,
    Relation,
    Sumcheck,
    Opening,
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "Compact rank proof refused: {self:?}")
    }
}

impl std::error::Error for Error {}

type Result<T> = std::result::Result<T, Error>;

fn require(condition: bool, error: Error) -> Result<()> {
    if condition { Ok(()) } else { Err(error) }
}

/// Checks the complete rank relation with the ordinary SHAKE transcript.
///
/// The role and public context are supplied by the enclosing protocol. The
/// statement includes the owner position, preceding context, source packets,
/// public openings and claimed shares. This function exposes no programmable
/// oracle and returns no verified protocol capability.
pub fn verify(role: &[u8], public_context: &[u8], statement: &[u8], proof: &[u8]) -> Result<()> {
    let statement_value = statement::Statement::decode(statement)?;
    let relation = relation::Relation::new(&statement_value);
    let layout = layout::Layout::new(role, public_context, statement, &relation);
    verifier::verify(role, &statement_value, &relation, &layout, proof)
}
