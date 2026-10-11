//! The private randomness the participant module draws. While an operation's
//! retained seed is installed, the operation's witness, ballot and proof
//! draws come from that seed's streams, which the seed's owner serves within
//! the module, and a draw the operation does not make is refused. Every other
//! draw is fresh: in the browser from the host import that names its purpose,
//! so a module's imports show which randomness it may draw, and elsewhere
//! from the system.

use std::cell::Cell;

/// What a seeded draw is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    Witness,
    Ballot,
    Proof,
}

/// Serves a draw of the installed operation, or refuses one of a purpose it
/// does not draw.
pub type Seeded = fn(Purpose, &mut [u8]) -> bool;

thread_local! {
    static SEEDED: Cell<Option<Seeded>> = const { Cell::new(None) };
}

/// Serves every witness, ballot and proof draw from an operation's seed until
/// `release`.
pub fn install(seeded: Seeded) {
    SEEDED.with(|current| assert!(current.replace(Some(seeded)).is_none()));
}

/// Ends the installed operation's draws.
pub fn release() {
    SEEDED.with(|current| current.set(None));
}

// Whether the installed operation served the draw.
fn seeded(purpose: Purpose, bytes: &mut [u8]) -> bool {
    let Some(seeded) = SEEDED.with(Cell::get) else {
        return false;
    };
    assert!(
        seeded(purpose, bytes),
        "The installed operation does not draw this randomness."
    );
    true
}

/// Fills the bytes with a witness's sampled randomness.
pub fn witness(bytes: &mut [u8]) {
    if !seeded(Purpose::Witness, bytes) {
        host::witness(bytes);
    }
}

/// Fills the bytes with a ballot's encryption randomness, which in the
/// browser only the ballot's seed supplies.
pub fn ballot(bytes: &mut [u8]) {
    if !seeded(Purpose::Ballot, bytes) {
        host::ballot(bytes);
    }
}

/// Fills the bytes with a proof's masks and salts.
pub fn proof(bytes: &mut [u8]) {
    if !seeded(Purpose::Proof, bytes) {
        host::proof(bytes);
    }
}

/// Fills the bytes with randomness that no seed supplies: a registration's
/// secrets and keys.
pub fn fresh(bytes: &mut [u8]) {
    host::fresh(bytes);
}

#[cfg(not(target_arch = "wasm32"))]
mod host {
    pub(super) use self::{system as ballot, system as fresh, system as proof, system as witness};

    pub(super) fn system(bytes: &mut [u8]) {
        getrandom::fill(bytes).expect("System randomness failed.");
    }
}

#[cfg(target_arch = "wasm32")]
mod host {
    // Each host import fills at most this many bytes at once.
    const REQUEST_BYTES: usize = 65_536;

    // Defines the purpose's fresh source as the module's import of that name.
    macro_rules! import {
        ($purpose:ident, $module:literal) => {
            pub(super) fn $purpose(bytes: &mut [u8]) {
                #[link(wasm_import_module = $module)]
                unsafe extern "C" {
                    fn fill_random(pointer: *mut u8, length: usize) -> u32;
                }
                for chunk in bytes.chunks_mut(REQUEST_BYTES) {
                    // The host writes exactly this live, exclusively borrowed slice.
                    assert_eq!(unsafe { fill_random(chunk.as_mut_ptr(), chunk.len()) }, 0);
                }
            }
        };
    }
    import!(witness, "setup_witness");
    import!(proof, "word_proof");
    import!(fresh, "enrollment");

    pub(super) fn ballot(_bytes: &mut [u8]) {
        panic!("Only the ballot's seed supplies its randomness.");
    }
}

#[cfg(test)]
#[path = "random-tests.rs"]
mod tests;
