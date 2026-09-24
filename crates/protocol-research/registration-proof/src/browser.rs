use crate::{proof::RegistrationProof, statement};
use setup_witness::registration::RegistrationKey;
use sha3::{Digest, Sha3_512};
use std::{
    cell::RefCell,
    io::{self, Write},
};

struct PublicWriter {
    kind: u32,
    offset: usize,
    bytes: Vec<u8>,
}
impl PublicWriter {
    fn new(kind: u32) -> Self {
        Self {
            kind,
            offset: 0,
            bytes: Vec::with_capacity(1 << 20),
        }
    }
    fn send(&mut self) {
        if self.bytes.is_empty() {
            return;
        }
        #[link(wasm_import_module = "registration")]
        unsafe extern "C" {
            fn public_chunk(kind: u32, offset: u32, pointer: *const u8, length: usize) -> u32;
        }
        // Only the canonical public key and proof are routed to this sink.
        assert_eq!(
            unsafe {
                public_chunk(
                    self.kind,
                    self.offset as u32,
                    self.bytes.as_ptr(),
                    self.bytes.len(),
                )
            },
            0
        );
        self.offset += self.bytes.len();
        self.bytes.clear();
    }
}
impl Write for PublicWriter {
    fn write(&mut self, mut bytes: &[u8]) -> io::Result<usize> {
        let length = bytes.len();
        while !bytes.is_empty() {
            let count = bytes.len().min((1 << 20) - self.bytes.len());
            self.bytes.extend(&bytes[..count]);
            bytes = &bytes[count..];
            if self.bytes.len() == 1 << 20 {
                self.send();
            }
        }
        Ok(length)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.send();
        Ok(())
    }
}
struct Session {
    input: Vec<u8>,
    key: Option<RegistrationKey>,
    started: bool,
    public_hash: [u8; 64],
}
thread_local! {static SESSION:RefCell<Session>=RefCell::new(Session{input:vec![0;1024],key:None,started:false,public_hash:[0;64]});}
#[unsafe(no_mangle)]
pub extern "C" fn input_pointer() -> usize {
    SESSION.with(|state| state.borrow_mut().input.as_mut_ptr() as usize)
}
#[unsafe(no_mangle)]
pub extern "C" fn public_key_hash_pointer() -> usize {
    SESSION.with(|state| state.borrow().public_hash.as_ptr() as usize)
}
#[unsafe(no_mangle)]
pub extern "C" fn create(length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        if state.started || length == 0 || length > 1024 {
            return 1;
        }
        state.started = true;
        let proof = RegistrationProof::create(&state.input[..length], false, false);
        if proof.check_retained_key().is_err() {
            return 1;
        }
        let bytes = proof.public_key_bytes();
        let key_hash = Sha3_512::digest(&bytes).into();
        let mut key_output = PublicWriter::new(0);
        key_output.write_all(&bytes).unwrap();
        key_output.flush().unwrap();
        let mut proof_output = PublicWriter::new(1);
        proof.write(&mut proof_output);
        proof_output.flush().unwrap();
        let key = proof.into_key();
        state.public_hash = key_hash;
        state.key = Some(key);
        0
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn check_retained_key() -> u32 {
    SESSION.with(|state| {
        let state = state.borrow();
        match &state.key {
            Some(key) => {
                if key.validate_retained().is_err()
                    || <[u8; 64]>::from(Sha3_512::digest(
                        statement::encode_key(key.public_key()).unwrap(),
                    )) != state.public_hash
                {
                    1
                } else {
                    0
                }
            }
            None => 1,
        }
    })
}
