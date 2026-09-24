pub mod context;
pub mod encryption;
pub mod packing;

#[path = "../../setup-witness/src/convolution.rs"]
mod convolution;
#[path = "../../setup-witness/src/gaussian.rs"]
mod gaussian;
#[path = "../../setup-witness/src/reduction.rs"]
mod reduction;

#[cfg(all(target_arch = "wasm32", feature = "bridge"))]
mod browser;

#[cfg(all(target_arch = "wasm32", feature = "bridge"))]
#[path = "encryption-browser.rs"]
pub mod encryption_browser;
