#![deny(unsafe_op_in_unsafe_fn)]
#[cfg(all(target_arch = "wasm32", feature = "browser"))]
mod browser;
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
