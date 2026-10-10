#[cfg(any(test, feature = "test-support"))]
thread_local! {
    /// A test's stand-in for the host's randomness: the state of a SplitMix64
    /// stream, which replays the same bytes from the same seed as an
    /// operation's retained seed does.
    pub static REPLAYED: std::cell::Cell<Option<u64>> =
        const { std::cell::Cell::new(None) };
}

pub fn fill(bytes: &mut [u8]) {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(mut state) = REPLAYED.with(std::cell::Cell::get) {
        for chunk in bytes.chunks_mut(8) {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut word = state;
            word = (word ^ (word >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            word = (word ^ (word >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            word ^= word >> 31;
            chunk.copy_from_slice(&word.to_le_bytes()[..chunk.len()]);
        }
        REPLAYED.with(|replayed| replayed.set(Some(state)));
        return;
    }
    parallel_work::random::proof(bytes);
}
