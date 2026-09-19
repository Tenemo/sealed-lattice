use crate::{CHUNK_LIMIT, HEADER_LENGTH, Verifier};
use registration_proof::statement;
use std::cell::RefCell;

struct Request {
    role: Vec<u8>,
    header: Vec<u8>,
    key: Vec<u8>,
    verifier: Option<Verifier>,
}
struct Session {
    input: Vec<u8>,
    request: Option<Request>,
}
thread_local! {static SESSION:RefCell<Session>=RefCell::new(Session{input:vec![0;CHUNK_LIMIT],request:None});}
#[unsafe(no_mangle)]
pub extern "C" fn input_pointer() -> usize {
    SESSION.with(|value| value.borrow_mut().input.as_mut_ptr() as usize)
}
#[unsafe(no_mangle)]
pub extern "C" fn begin(length: usize) -> u32 {
    SESSION.with(|value| {
        let mut value = value.borrow_mut();
        value.request = None;
        let result = (|| {
            let bytes = value.input.get(..length).ok_or(())?;
            let role_length =
                u32::from_le_bytes(bytes.get(..4).ok_or(())?.try_into().unwrap()) as usize;
            if role_length == 0
                || role_length > 1024
                || bytes.len() != 4 + role_length + HEADER_LENGTH
                || &bytes[4 + role_length..8 + role_length] != b"RWP1"
            {
                return Err(());
            }
            Ok(Request {
                role: bytes[4..4 + role_length].to_vec(),
                header: bytes[4 + role_length..].to_vec(),
                key: Vec::new(),
                verifier: None,
            })
        })();
        value.request = result.ok();
        u32::from(value.request.is_none())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn absorb_key(length: usize) -> u32 {
    SESSION.with(|value| {
        let mut value = value.borrow_mut();
        let Session { input, request } = &mut *value;
        let result = (|| {
            let bytes = input.get(..length).ok_or(())?;
            let request = request.as_mut().ok_or(())?;
            if request.verifier.is_some() || bytes.len() > 65536 * 21 - request.key.len() {
                return Err(());
            }
            request.key.extend(bytes);
            Ok(())
        })();
        if result.is_err() {
            *request = None;
            1
        } else {
            0
        }
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn finish_key() -> u32 {
    SESSION.with(|value| {
        let mut value = value.borrow_mut();
        let result = (|| {
            let request = value.request.as_mut().ok_or(())?;
            if request.key.len() != 65536 * 21 || request.verifier.is_some() {
                return Err(());
            }
            let common = statement::common_bytes();
            let digest = statement::digest(&common, &request.key);
            let mut verifier =
                Verifier::new(&request.role, digest, &request.header).map_err(|_| ())?;
            verifier
                .push_statement(&statement::header())
                .map_err(|_| ())?;
            for bytes in common
                .chunks(CHUNK_LIMIT)
                .chain(request.key.chunks(CHUNK_LIMIT))
            {
                verifier.push_statement(bytes).map_err(|_| ())?;
            }
            verifier.finish_statement().map_err(|_| ())?;
            request.key = Vec::new();
            request.verifier = Some(verifier);
            Ok(())
        })();
        if result.is_err() {
            value.request = None;
            1
        } else {
            0
        }
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn absorb_proof(length: usize) -> u32 {
    SESSION.with(|value| {
        let mut value = value.borrow_mut();
        let Session { input, request } = &mut *value;
        let result = input.get(..length).ok_or(()).and_then(|bytes| {
            request
                .as_mut()
                .ok_or(())?
                .verifier
                .as_mut()
                .ok_or(())?
                .push_proof(bytes)
                .map_err(|_| ())
        });
        if result.is_err() {
            *request = None;
            1
        } else {
            0
        }
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn finish() -> u32 {
    SESSION.with(|value| {
        u32::from(
            value
                .borrow_mut()
                .request
                .take()
                .and_then(|request| request.verifier)
                .is_some_and(Verifier::finish),
        )
    })
}
