//! Monotonic clock used only by non-canonical runtime diagnostics.
//!
//! No value returned here may select a cryptographic branch, enter a
//! transcript, authorize a transition, or be serialized as protocol data.

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "sealed_lattice_diagnostics")]
unsafe extern "C" {
    fn monotonic_time_milliseconds() -> f64;
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn now_milliseconds() -> f64 {
    // SAFETY: The scalar-WASM loader supplies this nullary diagnostic clock.
    // Its result is retained only in non-canonical observations.
    unsafe { monotonic_time_milliseconds() }
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn now_milliseconds() -> f64 {
    use std::{cell::OnceCell, time::Instant};

    thread_local! {
        static DIAGNOSTIC_CLOCK_ORIGIN: OnceCell<Instant> = const { OnceCell::new() };
    }
    DIAGNOSTIC_CLOCK_ORIGIN
        .with(|origin| origin.get_or_init(Instant::now).elapsed().as_secs_f64() * 1_000.0)
}
