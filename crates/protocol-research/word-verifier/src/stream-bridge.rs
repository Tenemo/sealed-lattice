use super::engine::{CHUNK_LIMIT, HEADER_LENGTH, Refusal, Verifier};
use std::cell::RefCell;
struct Session {
    input: Vec<u8>,
    verifier: Option<Verifier>,
}
thread_local! {static SESSION:RefCell<Session>=RefCell::new(Session{input:vec![0;CHUNK_LIMIT],verifier:None});}
#[unsafe(no_mangle)]
pub extern "C" fn input_pointer() -> usize {
    SESSION.with(|session| session.borrow_mut().input.as_mut_ptr() as usize)
}
#[unsafe(no_mangle)]
pub extern "C" fn begin(length: usize) -> u32 {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        session.verifier = None;
        let result = (|| {
            let bytes = session.input.get(..length).ok_or(Refusal::Length)?;
            let role_length =
                u32::from_le_bytes(bytes.get(..4).ok_or(Refusal::Length)?.try_into().unwrap())
                    as usize;
            if role_length == 0
                || role_length > 1024
                || bytes.len() != 4 + role_length + 64 + HEADER_LENGTH
            {
                return Err(Refusal::Length);
            }
            let role = &bytes[4..4 + role_length];
            let statement = bytes[4 + role_length..68 + role_length].try_into().unwrap();
            Verifier::new(role, statement, &bytes[68 + role_length..])
        })();
        session.verifier = result.ok();
        u32::from(session.verifier.is_none())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn absorb_statement(length: usize) -> u32 {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        let Session { input, verifier } = &mut *session;
        let result = input
            .get(..length)
            .ok_or(Refusal::Length)
            .and_then(|bytes| {
                verifier
                    .as_mut()
                    .ok_or(Refusal::Stage)?
                    .push_statement(bytes)
            });
        if result.is_err() {
            *verifier = None;
            1
        } else {
            0
        }
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn finish_statement() -> u32 {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        let result = session
            .verifier
            .as_mut()
            .ok_or(Refusal::Stage)
            .and_then(Verifier::finish_statement);
        if result.is_err() {
            session.verifier = None;
            1
        } else {
            0
        }
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn absorb_proof(length: usize) -> u32 {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        let Session { input, verifier } = &mut *session;
        let result = input
            .get(..length)
            .ok_or(Refusal::Length)
            .and_then(|bytes| verifier.as_mut().ok_or(Refusal::Stage)?.push_proof(bytes));
        if result.is_err() {
            *verifier = None;
            1
        } else {
            0
        }
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn finish() -> u32 {
    SESSION.with(|session| {
        u32::from(
            session
                .borrow_mut()
                .verifier
                .take()
                .is_some_and(Verifier::finish),
        )
    })
}
