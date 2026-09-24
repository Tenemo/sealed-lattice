use crate::{
    CHUNK_LIMIT,
    body::{
        BallotBodyClassification, BallotBodyVerifier, SignedBallotVerifier, VerifiedBallotBody,
    },
    submission::{
        AuthenticatedBallotEnvelope, VerifiedBallotSubmission, authenticate_envelope,
        verify_submission,
    },
};
use registration_credentials::ballot_authentication::ENVELOPE_BYTES;
use registration_credentials::ballot_body::HEADER_BYTES;
use std::cell::RefCell;

struct Session {
    input: Vec<u8>,
    verifier: Option<BallotBodyVerifier>,
    body: Option<VerifiedBallotBody>,
    authentication: Option<AuthenticatedBallotEnvelope>,
    submission: Option<VerifiedBallotSubmission>,
    classifier: Option<SignedBallotVerifier>,
    classification: Option<BallotBodyClassification>,
}
thread_local! { static SESSION: RefCell<Session> = RefCell::new(Session { input: vec![0; CHUNK_LIMIT], verifier: None, body: None, authentication: None, submission: None, classifier: None, classification: None }); }
#[unsafe(no_mangle)]
pub extern "C" fn ballot_body_input_pointer() -> usize {
    SESSION.with(|session| session.borrow_mut().input.as_mut_ptr() as usize)
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_body_begin(length: usize) -> u32 {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        session.verifier = None;
        session.body = None;
        session.submission = None;
        session.classifier = None;
        session.classification = None;
        let result = (|| {
            let bytes = session.input.get(..length).ok_or(())?;
            let position =
                u16::from_le_bytes(bytes.get(..2).ok_or(())?.try_into().unwrap()) as usize;
            if bytes.len() != 2 + HEADER_BYTES {
                return Err(());
            }
            let (poll, setup) = setup_aggregate::setup_browser::context().ok_or(())?;
            BallotBodyVerifier::new(poll, setup, position, &bytes[2..]).map_err(|_| ())
        })();
        session.verifier = result.ok();
        u32::from(session.verifier.is_none())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_body_key_begin(index: usize) -> u32 {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        let result = session
            .verifier
            .as_mut()
            .ok_or(())
            .and_then(|verifier| verifier.begin_key(index).map_err(|_| ()));
        if result.is_err() {
            session.verifier = None;
            session.body = None;
        }
        u32::from(result.is_err())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_body_key_finish() -> u32 {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        let result = session
            .verifier
            .as_mut()
            .ok_or(())
            .and_then(|verifier| verifier.finish_key().map_err(|_| ()));
        if result.is_err() {
            session.verifier = None;
            session.body = None;
        }
        u32::from(result.is_err())
    })
}
fn push(length: usize, key: bool) -> u32 {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        let Session {
            input,
            verifier,
            body,
            ..
        } = &mut *session;
        let result = (|| {
            let bytes = input.get(..length).ok_or(())?;
            let verifier = verifier.as_mut().ok_or(())?;
            if key {
                verifier.push_key(bytes)
            } else {
                verifier.push(bytes)
            }
            .map_err(|_| ())
        })();
        if result.is_err() {
            *verifier = None;
            *body = None;
        }
        u32::from(result.is_err())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_body_key_chunk(length: usize) -> u32 {
    push(length, true)
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_body_chunk(length: usize) -> u32 {
    push(length, false)
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_body_finish() -> u32 {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        session.body = session
            .verifier
            .take()
            .and_then(|verifier| verifier.finish().ok());
        u32::from(session.body.is_some())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_body_identity_pointer() -> usize {
    SESSION.with(|session| {
        session
            .borrow()
            .body
            .as_ref()
            .map_or(0, |body| body.identity().as_ptr() as usize)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn ballot_submission_begin(length: usize) -> u32 {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        session.verifier = None;
        session.body = None;
        session.authentication = None;
        session.submission = None;
        session.classifier = None;
        session.classification = None;
        let result = (|| {
            if length != ENVELOPE_BYTES + 3309 {
                return Err(());
            }
            let bytes = session.input.get(..length).ok_or(())?;
            let (_, setup) = setup_aggregate::setup_browser::context().ok_or(())?;
            authenticate_envelope(&setup, &bytes[..ENVELOPE_BYTES], &bytes[ENVELOPE_BYTES..])
                .map_err(|_| ())
        })();
        session.authentication = result.ok();
        u32::from(session.authentication.is_none())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn ballot_submission_finish() -> u32 {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        session.submission = None;
        let result = (|| {
            let authentication = session.authentication.take().ok_or(())?;
            let body = session.body.take().ok_or(())?;
            let (_, setup) = setup_aggregate::setup_browser::context().ok_or(())?;
            verify_submission(body, &setup, authentication).map_err(|_| ())
        })();
        session.submission = result.ok();
        u32::from(session.submission.is_some())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn ballot_submission_identity_pointer() -> usize {
    SESSION.with(|session| {
        session
            .borrow()
            .submission
            .as_ref()
            .map_or(0, |value| value.body().identity().as_ptr() as usize)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn ballot_classification_begin(length: usize) -> u32 {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        session.verifier = None;
        session.body = None;
        session.authentication = None;
        session.submission = None;
        session.classifier = None;
        session.classification = None;
        let result = (|| {
            if length != ENVELOPE_BYTES + 3309 + HEADER_BYTES {
                return Err(());
            }
            let bytes = session.input.get(..length).ok_or(())?;
            let (poll, setup) = setup_aggregate::setup_browser::context().ok_or(())?;
            let authentication = authenticate_envelope(
                &setup,
                &bytes[..ENVELOPE_BYTES],
                &bytes[ENVELOPE_BYTES..ENVELOPE_BYTES + 3309],
            )
            .map_err(|_| ())?;
            SignedBallotVerifier::new(poll, setup, authentication, &bytes[ENVELOPE_BYTES + 3309..])
                .map_err(|_| ())
        })();
        session.classifier = result.ok();
        u32::from(session.classifier.is_none())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_classification_requires_keys() -> u32 {
    SESSION.with(|session| {
        u32::from(
            session
                .borrow()
                .classifier
                .as_ref()
                .is_some_and(SignedBallotVerifier::requires_keys),
        )
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_classification_key_begin(index: usize) -> u32 {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        let result = session
            .classifier
            .as_mut()
            .ok_or(())
            .and_then(|value| value.begin_key(index).map_err(|_| ()));
        if result.is_err() {
            session.classifier = None;
            session.classification = None;
        }
        u32::from(result.is_err())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_classification_key_finish() -> u32 {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        let result = session
            .classifier
            .as_mut()
            .ok_or(())
            .and_then(|value| value.finish_key().map_err(|_| ()));
        if result.is_err() {
            session.classifier = None;
            session.classification = None;
        }
        u32::from(result.is_err())
    })
}
fn classification_push(length: usize, key: bool) -> u32 {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        let Session {
            input,
            classifier,
            classification,
            ..
        } = &mut *session;
        let result = (|| {
            let bytes = input.get(..length).ok_or(())?;
            let value = classifier.as_mut().ok_or(())?;
            if key {
                value.push_key(bytes)
            } else {
                value.push(bytes)
            }
            .map_err(|_| ())
        })();
        if result.is_err() {
            *classifier = None;
            *classification = None;
        }
        u32::from(result.is_err())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_classification_key_chunk(length: usize) -> u32 {
    classification_push(length, true)
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_classification_chunk(length: usize) -> u32 {
    classification_push(length, false)
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_classification_finish() -> u32 {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        session.classification = session
            .classifier
            .take()
            .and_then(|value| value.finish().ok());
        match session.classification {
            Some(BallotBodyClassification::Valid(_)) => 1,
            Some(BallotBodyClassification::Invalid(_)) => 2,
            None => 0,
        }
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_classification_identity_pointer() -> usize {
    SESSION.with(|session| match session.borrow().classification.as_ref() {
        Some(BallotBodyClassification::Valid(value)) => value.body().identity().as_ptr() as usize,
        Some(BallotBodyClassification::Invalid(value)) => {
            value.envelope().body_identity().as_ptr() as usize
        }
        None => 0,
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_classification_position() -> u32 {
    SESSION.with(|session| match session.borrow().classification.as_ref() {
        Some(BallotBodyClassification::Valid(value)) => value.body().relation().position() as u32,
        Some(BallotBodyClassification::Invalid(value)) => value.envelope().position() as u32,
        None => u32::MAX,
    })
}

pub(super) fn take_classification() -> Option<BallotBodyClassification> {
    SESSION.with(|session| session.borrow_mut().classification.take())
}
