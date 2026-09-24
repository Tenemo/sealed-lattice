pub fn fill(bytes: &mut [u8]) {
    #[cfg(not(target_arch = "wasm32"))]
    getrandom::fill(bytes).expect("System randomness failed.");
    #[cfg(target_arch = "wasm32")]
    {
        #[link(wasm_import_module = "word_proof")]
        unsafe extern "C" {
            fn fill_random(pointer: *mut u8, length: usize) -> u32;
        }
        assert!(bytes.len() <= 65536);
        // The host writes exactly this live, exclusively borrowed byte slice.
        assert_eq!(unsafe { fill_random(bytes.as_mut_ptr(), bytes.len()) }, 0);
    }
}
