//! Commitment writing shared by plain and hiding WHIR.
//!
//! Local modification: the unused legacy complete-proof commitment reader was
//! removed after the resumable verifier became the sole reader. See
//! `../../../UPSTREAM.md`.

pub mod writer;
