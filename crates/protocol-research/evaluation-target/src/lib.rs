#![deny(unsafe_op_in_unsafe_fn)]
#[cfg(target_arch = "wasm32")]
mod browser;
#[cfg(target_arch = "wasm32")]
pub fn verified_browser_target() -> Option<std::sync::Arc<target::VerifiedEvaluationTarget>> {
    browser::verified_target()
}
/// Takes a target restored from the participant's retained copy while this
/// instance holds no target and runs no evaluation.
#[cfg(target_arch = "wasm32")]
pub fn restore_browser_target(target: target::VerifiedEvaluationTarget) -> bool {
    browser::restore_target(target)
}
#[cfg(target_arch = "wasm32")]
pub fn verified_browser_release_context() -> Option<std::sync::Arc<release::ReleaseContext>> {
    completion_browser::verified_context()
}
/// The target certificate that this instance's completion verified.
#[cfg(target_arch = "wasm32")]
pub fn verified_browser_certificate()
-> Option<std::sync::Arc<certification::VerifiedTargetCertificate>> {
    completion_browser::verified_certificate()
}
pub mod certification;
#[cfg(target_arch = "wasm32")]
#[path = "completion-browser.rs"]
mod completion_browser;
mod interpolation;
pub mod program;
pub mod release;
#[path = "release-body.rs"]
pub mod release_body;
#[cfg(target_arch = "wasm32")]
#[path = "scalar-allocator.rs"]
mod scalar_allocator;
#[cfg(target_arch = "wasm32")]
pub use scalar_allocator::{limit_linear_memory, linear_memory_high_water};
pub mod target;
pub mod terminal;

/// The absolute bound on the linear memory of an operation's instances
/// together, which bounds a lone instance too.
pub const MAXIMUM_LINEAR_MEMORY_BYTES: usize = 671_088_640;

/// Plans a helper instance's memory for the evaluation's jobs: a growth
/// brings it to the bytes its live allocations hold and the bytes its input
/// names, so its memory grows once to what those jobs hold rather than
/// beside memory it already has free.
pub static PLAN: parallel_work::Job = parallel_work::Job {
    kind: 0x0700,
    run: plan,
};
fn plan(input: &[u8]) -> Vec<u8> {
    let bytes = u64::from_le_bytes(input.try_into().expect("Planned length"));
    #[cfg(target_arch = "wasm32")]
    scalar_allocator::plan_linear_memory(bytes as usize);
    #[cfg(not(target_arch = "wasm32"))]
    let _ = bytes;
    Vec::new()
}
/// The jobs this crate defines.
pub static JOBS: [&parallel_work::Job; 1] = [&PLAN];

/// Each coefficient of a stored working value of the evaluation takes this
/// many bytes: its whole little-endian words.
pub fn stored_coefficient_bytes(profile: supported_profile::Profile) -> usize {
    rns_arithmetic_probe::ranking::stored_value_bytes(profile)
        / (2 * rns_arithmetic_probe::ranking::DEGREE)
}
