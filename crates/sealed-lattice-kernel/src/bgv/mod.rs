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
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        unused_imports,
        reason = "the generic browser proof worker and later exact-family adapters remain compiled while fixed suite selection refuses the exact-family browser resource mismatch"
    )
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

pub(crate) use setup::{
    absorb_bgv_canonical_stream_chunk, active_accepted_setup_proof_binding_session,
    begin_accepted_setup_canonical_stream, begin_accepted_setup_proof_binding_session,
    begin_bgv_canonical_material_reader, begin_bgv_canonical_stream,
    cancel_accepted_setup_proof_binding_session, cancel_bgv_canonical_material_reader,
    cancel_bgv_canonical_stream, finish_bgv_canonical_material_reader, finish_bgv_canonical_stream,
    read_bgv_canonical_material_chunk,
    verify_collective_bgv_setup_package_with_session_from_request,
};
