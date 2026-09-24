// Keep the execution-strategy type free of SIMD values and dispatch branches.
// The modular operations inside each closure are unchanged.
#[derive(Debug, Clone, Copy)]
pub(super) struct Arch;

impl Arch {
    pub(super) const fn new() -> Self {
        Self
    }

    #[inline]
    pub(super) fn dispatch<Result>(&self, operation: impl FnOnce() -> Result) -> Result {
        operation()
    }
}
