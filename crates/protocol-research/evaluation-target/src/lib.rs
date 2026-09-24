#![deny(unsafe_op_in_unsafe_fn)]
#[cfg(all(target_arch = "wasm32", feature = "browser"))]
mod browser;
#[cfg(all(target_arch = "wasm32", feature = "browser"))]
pub fn verified_browser_target() -> Option<std::sync::Arc<target::VerifiedEvaluationTarget>> {
    browser::verified_target()
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
pub mod target;
pub mod terminal;
