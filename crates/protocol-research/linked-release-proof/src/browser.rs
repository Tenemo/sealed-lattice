use crate::{
    CHUNK_LIMIT, HEADER_LENGTH, PreparedRelease, ReleaseInputs, Verifier,
    proof::ReleaseRelationProof, statement::PublicStatement,
};
use std::{
    cell::RefCell,
    io::{self, Write},
};
const ROLE: &[u8] = b"sealed-lattice/linked-release-workload/1";
const PROOF_LIMIT: usize = 14_439_264;
struct BoundedProof(Vec<u8>);
impl Write for BoundedProof {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > PROOF_LIMIT - self.0.len() {
            return Err(io::Error::other("Public proof exceeds its bound."));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct Output {
    statement: PublicStatement,
    proof: Vec<u8>,
}
struct State {
    role: Vec<u8>,
    input: Vec<u8>,
    output: Vec<u8>,
    prepared: Option<ReleaseInputs>,
    derived: Option<PreparedRelease>,
    completed: Option<Output>,
    verifier: Option<Verifier>,
    consumed: bool,
}
thread_local! {static STATE:RefCell<State>=RefCell::new(State{role:ROLE.to_vec(),input:vec![0;CHUNK_LIMIT],output:Vec::with_capacity(CHUNK_LIMIT),prepared:None,derived:None,completed:None,verifier:None,consumed:false});}
// This feature-gated interface operates on synthetic inputs only. It does not
// supply a protocol certificate, original participant key or release capability.
#[unsafe(no_mangle)]
pub extern "C" fn release_set_role(length: usize) -> u32 {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        if !(1..=1024).contains(&length) || state.consumed || state.verifier.is_some() {
            return 1;
        }
        state.role = state.input[..length].to_vec();
        0
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn release_input_pointer() -> *mut u8 {
    STATE.with(|state| state.borrow_mut().input.as_mut_ptr())
}
#[unsafe(no_mangle)]
pub extern "C" fn release_output_pointer() -> *const u8 {
    STATE.with(|state| state.borrow().output.as_ptr())
}
#[unsafe(no_mangle)]
pub extern "C" fn release_output_length() -> usize {
    STATE.with(|state| state.borrow().output.len())
}
#[unsafe(no_mangle)]
pub extern "C" fn release_prepare() -> u32 {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        if state.consumed
            || state.prepared.is_some()
            || state.derived.is_some()
            || state.completed.is_some()
            || state.verifier.is_some()
        {
            return 1;
        }
        state.consumed = true;
        state.prepared = Some(crate::synthetic_inputs());
        0
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn release_derive() -> u32 {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        let Some(prepared) = state.prepared.take() else {
            return 1;
        };
        state.derived = Some(crate::derive(prepared));
        0
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn release_prove() -> u32 {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        let Some(derived) = state.derived.take() else {
            return 1;
        };
        let (statement, proof) = ReleaseRelationProof::from_prepared(&state.role, derived);
        let mut output = BoundedProof(Vec::with_capacity(PROOF_LIMIT));
        proof.write(&mut output);
        drop(proof);
        state.completed = Some(Output {
            statement,
            proof: output.0,
        });
        0
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn release_public_length(kind: u32) -> usize {
    STATE.with(|state| {
        let state = state.borrow();
        let Some(output) = state.completed.as_ref() else {
            return 0;
        };
        match kind {
            0 => crate::parameters::STATEMENT_BYTES,
            1 => output.proof.len(),
            _ => 0,
        }
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn release_read(kind: u32, mut offset: usize, length: usize) -> u32 {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.output.clear();
        if length == 0 || length > CHUNK_LIMIT {
            return 1;
        }
        let Some(completed) = state.completed.as_ref() else {
            return 1;
        };
        let total = match kind {
            0 => crate::parameters::STATEMENT_BYTES,
            1 => completed.proof.len(),
            _ => return 1,
        };
        if offset > total || length > total - offset {
            return 1;
        }
        let mut bytes = Vec::with_capacity(length);
        if kind == 1 {
            bytes.extend_from_slice(&completed.proof[offset..offset + length]);
        } else {
            for part in
                std::iter::once(&completed.statement.header).chain(&completed.statement.polynomials)
            {
                if offset >= part.len() {
                    offset -= part.len();
                    continue;
                }
                let count = (length - bytes.len()).min(part.len() - offset);
                bytes.extend_from_slice(&part[offset..offset + count]);
                offset = 0;
                if bytes.len() == length {
                    break;
                }
            }
        }
        if bytes.len() != length {
            return 1;
        }
        state.output = bytes;
        0
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn release_verifier_start(length: usize) -> u32 {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        if length != 64 + HEADER_LENGTH
            || length > CHUNK_LIMIT
            || state.verifier.is_some()
            || state.prepared.is_some()
            || state.derived.is_some()
        {
            return 1;
        }
        match Verifier::new(
            &state.role,
            state.input[..64].try_into().unwrap(),
            &state.input[64..length],
        ) {
            Ok(verifier) => {
                state.verifier = Some(verifier);
                0
            }
            Err(_) => 1,
        }
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn release_verifier_statement(length: usize) -> u32 {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        if length > CHUNK_LIMIT {
            return 1;
        }
        let State {
            input, verifier, ..
        } = &mut *state;
        match verifier.as_mut() {
            Some(verifier) => u32::from(verifier.push_statement(&input[..length]).is_err()),
            None => 1,
        }
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn release_verifier_statement_finish() -> u32 {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        match state.verifier.as_mut() {
            Some(verifier) => u32::from(verifier.finish_statement().is_err()),
            None => 1,
        }
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn release_verifier_proof(length: usize) -> u32 {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        if length > CHUNK_LIMIT {
            return 1;
        }
        let State {
            input, verifier, ..
        } = &mut *state;
        match verifier.as_mut() {
            Some(verifier) => u32::from(verifier.push_proof(&input[..length]).is_err()),
            None => 1,
        }
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn release_verifier_finish() -> u32 {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        match state.verifier.take() {
            Some(verifier) => u32::from(verifier.finish()),
            None => 0,
        }
    })
}
