#![deny(unsafe_op_in_unsafe_fn)]
#[cfg(all(target_arch = "wasm32", feature = "browser"))]
mod browser;
#[cfg(all(target_arch = "wasm32", feature = "browser"))]
pub fn verified_browser_target() -> Option<std::sync::Arc<target::VerifiedEvaluationTarget>> {
    browser::verified_target()
}
/// Takes a target restored from the participant's retained copy while this
/// instance holds no target and runs no evaluation.
#[cfg(all(target_arch = "wasm32", feature = "browser"))]
pub fn restore_browser_target(target: target::VerifiedEvaluationTarget) -> bool {
    browser::restore_target(target)
}
#[cfg(all(target_arch = "wasm32", feature = "browser"))]
pub fn verified_browser_release_context() -> Option<std::sync::Arc<release::ReleaseContext>> {
    completion_browser::verified_context()
}
pub mod certification;
#[cfg(all(target_arch = "wasm32", feature = "browser"))]
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

/// Each coefficient of a stored working value of the evaluation takes this
/// many bytes: its whole little-endian words.
pub fn stored_coefficient_bytes(profile: supported_profile::Profile) -> usize {
    rns_arithmetic_probe::ranking::stored_value_bytes(profile)
        / (2 * rns_arithmetic_probe::ranking::DEGREE)
}
