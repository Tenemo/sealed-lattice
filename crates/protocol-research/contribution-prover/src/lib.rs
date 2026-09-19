#![deny(unsafe_op_in_unsafe_fn)]
#[cfg(target_arch = "wasm32")]
pub mod browser;
