//! A bounded development ABI for cross-language verifier fixtures.
use crate::{Result, reader::Reader, verify};
#[cfg(target_arch = "wasm32")]
use std::cell::RefCell;

#[cfg(target_arch = "wasm32")]
thread_local! { static INPUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) }; }

#[unsafe(no_mangle)]
#[cfg(target_arch = "wasm32")]
pub extern "C" fn rank_screen_input(length: usize) -> usize {
    INPUT.with_borrow_mut(|input| {
        input.clear();
        if length == 0 || length > parallel_work::MAXIMUM_JOB_BYTES {
            return 0;
        }
        input.resize(length, 0);
        input.as_mut_ptr() as usize
    })
}

/// Reads the four bounded fixture parts used by the native and scalar screens.
pub fn verify_framed(bytes: &[u8]) -> Result<()> {
    crate::require(
        bytes.len() <= parallel_work::MAXIMUM_JOB_BYTES,
        crate::Error::Encoding,
    )?;
    let mut reader = Reader::new(bytes);
    let mut parts = Vec::new();
    for _ in 0..4 {
        let length = reader.word()?;
        parts.push(reader.take(length)?);
    }
    reader.finish()?;
    verify(parts[0], parts[1], parts[2], parts[3])
}

#[unsafe(no_mangle)]
#[cfg(target_arch = "wasm32")]
pub extern "C" fn rank_screen_verify() -> u32 {
    INPUT.with_borrow_mut(|input| {
        use crate::Error;
        let result = verify_framed(input);
        input.clear();
        match result {
            Ok(()) => 0,
            Err(Error::Statement) => 1,
            Err(Error::Encoding) => 2,
            Err(Error::Context) => 3,
            Err(Error::Authentication) => 4,
            Err(Error::Relation) => 5,
            Err(Error::Sumcheck) => 6,
            Err(Error::Opening) => 7,
        }
    })
}
