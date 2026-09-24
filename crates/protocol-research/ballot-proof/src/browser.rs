use crate::{
    CHUNK_LIMIT, HEADER_LENGTH,
    admission::{BallotRelationVerifier, VerifiedBallotRelation},
};
use std::cell::RefCell;

struct Session {
    input: Vec<u8>,
    verifier: Option<BallotRelationVerifier>,
    relation: Option<VerifiedBallotRelation>,
    context: [u8; 194],
}
thread_local! { static SESSION: RefCell<Session> = RefCell::new(Session { input: vec![0; CHUNK_LIMIT], verifier: None, relation: None, context: [0; 194] }); }
#[unsafe(no_mangle)]
pub extern "C" fn ballot_verifier_input_pointer() -> usize {
    SESSION.with(|session| session.borrow_mut().input.as_mut_ptr() as usize)
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_verifier_begin(length: usize) -> u32 {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        session.verifier = None;
        session.relation = None;
        session.context.fill(0);
        let result = (|| {
            let bytes = session.input.get(..length).ok_or(())?;
            let position =
                u16::from_le_bytes(bytes.get(..2).ok_or(())?.try_into().unwrap()) as usize;
            if bytes.len() != 2 + HEADER_LENGTH {
                return Err(());
            }
            let (poll, setup) = setup_aggregate::setup_browser::context().ok_or(())?;
            let header = &bytes[2..];
            BallotRelationVerifier::new(
                &poll,
                &setup,
                position,
                header[4..68].try_into().unwrap(),
                header,
            )
            .map_err(|_| ())
        })();
        session.verifier = result.ok();
        u32::from(session.verifier.is_none())
    })
}
fn absorb(length: usize, proof: bool) -> u32 {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        let Session {
            input,
            verifier,
            relation,
            ..
        } = &mut *session;
        let result = (|| {
            let bytes = input.get(..length).ok_or(())?;
            let verifier = verifier.as_mut().ok_or(())?;
            if proof {
                verifier.push_proof(bytes)
            } else {
                verifier.push_statement(bytes)
            }
            .map_err(|_| ())
        })();
        if result.is_err() {
            *verifier = None;
            *relation = None;
        }
        u32::from(result.is_err())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_verifier_statement(length: usize) -> u32 {
    absorb(length, false)
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_verifier_proof(length: usize) -> u32 {
    absorb(length, true)
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_verifier_finish_statement() -> u32 {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        let result = session
            .verifier
            .as_mut()
            .ok_or(())
            .and_then(|verifier| verifier.finish_statement().map_err(|_| ()));
        if result.is_err() {
            session.verifier = None;
            session.relation = None;
        }
        u32::from(result.is_err())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_verifier_finish() -> u32 {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        session.relation = session
            .verifier
            .take()
            .and_then(|verifier| verifier.finish().ok());
        if let Some(relation) = session.relation.as_ref() {
            let mut context = [0; 194];
            context[..64].copy_from_slice(relation.poll());
            context[64..128].copy_from_slice(relation.inventory());
            context[128..192].copy_from_slice(relation.statement());
            context[192..].copy_from_slice(&(relation.position() as u16).to_le_bytes());
            session.context = context;
            1
        } else {
            session.context.fill(0);
            0
        }
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_relation_context_pointer() -> usize {
    SESSION.with(|session| {
        let session = session.borrow();
        if session.relation.is_some() {
            session.context.as_ptr() as usize
        } else {
            0
        }
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_verifier_clear() {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        session.verifier = None;
        session.relation = None;
        session.context.fill(0);
        session.input.fill(0);
    });
}
