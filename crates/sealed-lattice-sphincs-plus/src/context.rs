use crate::params::SPX_N;
use zeroize::Zeroize;

/// Sphincs context
pub struct SpxCtx {
    pub pub_seed: [u8; SPX_N],
    pub sk_seed: [u8; SPX_N],

    pub state_seeded: [u8; 40],

    pub state_seeded_512: [u8; 72],
}

impl Default for SpxCtx {
    fn default() -> Self {
        Self {
            pub_seed: [0u8; SPX_N],
            sk_seed: [0u8; SPX_N],

            state_seeded: [0u8; 40],

            state_seeded_512: [0u8; 72],
        }
    }
}

impl Drop for SpxCtx {
    fn drop(&mut self) {
        self.sk_seed.zeroize();
    }
}
