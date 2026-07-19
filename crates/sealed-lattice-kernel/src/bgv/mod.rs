pub(crate) mod commands;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the internal ballot and evaluator path remains browser-compiled while end-to-end command composition is still open"
    )
)]
pub(crate) mod direct_ballots;
pub(crate) mod parameters;
#[expect(
    dead_code,
    unused_imports,
    reason = "the generic browser proof worker and exact-family adapters remain internal while family-owned statement and witness capability connections are incomplete"
)]
pub(crate) mod proof_suite;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "target partial-decryption framing remains browser-compiled for the later exact release-family adapter"
    )
)]
pub(crate) mod target_decryption;

#[cfg(test)]
mod base_conversion;
mod coefficient_codec;
mod encoding;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the internal ballot and evaluator path remains browser-compiled while end-to-end command composition is still open"
    )
)]
pub(crate) mod evaluator;
pub(crate) mod key_switch_topology;
mod modular_arithmetic;
mod ntt;
mod rns;
mod serialization;
pub(crate) mod setup;
mod setup_helpers;
