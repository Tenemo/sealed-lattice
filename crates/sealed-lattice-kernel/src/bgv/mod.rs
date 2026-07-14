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
