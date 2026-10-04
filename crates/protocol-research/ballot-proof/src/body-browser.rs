use crate::{
    CHUNK_LIMIT,
    body::{BallotBodyClassification, BallotInputs, SignedBallotVerifier},
    submission::authenticate_envelope,
};
use registration_credentials::ballot_authentication::ENVELOPE_BYTES;
use registration_credentials::ballot_body::HEADER_BYTES;
use std::{cell::RefCell, sync::Arc};

struct Session {
    input: Vec<u8>,
    classifier: Option<SignedBallotVerifier>,
    classification: Option<BallotBodyClassification>,
    // The statement inputs that the first ballot under the current setup
    // read, which the setup's later ballots share until they are released.
    inputs: Option<Arc<BallotInputs>>,
}
thread_local! { static SESSION: RefCell<Session> = RefCell::new(Session { input: vec![0; CHUNK_LIMIT], classifier: None, classification: None, inputs: None }); }
#[unsafe(no_mangle)]
pub extern "C" fn ballot_body_input_pointer() -> usize {
    SESSION.with(|session| session.borrow_mut().input.as_mut_ptr() as usize)
}

#[unsafe(no_mangle)]
pub extern "C" fn ballot_classification_begin(length: usize) -> u32 {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        let Session {
            input,
            classifier,
            classification,
            inputs,
        } = &mut *session;
        *classifier = None;
        *classification = None;
        let result = (|| {
            if length != ENVELOPE_BYTES + 3309 + HEADER_BYTES {
                return Err(());
            }
            let bytes = input.get(..length).ok_or(())?;
            let (poll, setup) = setup_aggregate::setup_browser::context().ok_or(())?;
            // Another setup's inputs are released before this one reads its
            // own.
            if inputs.as_ref().is_some_and(|value| !value.serves(&setup)) {
                *inputs = None;
            }
            let authentication = authenticate_envelope(
                &setup,
                &bytes[..ENVELOPE_BYTES],
                &bytes[ENVELOPE_BYTES..ENVELOPE_BYTES + 3309],
            )
            .map_err(|_| ())?;
            SignedBallotVerifier::new(
                poll,
                setup,
                authentication,
                &bytes[ENVELOPE_BYTES + 3309..],
                inputs.clone(),
            )
            .map_err(|_| ())
        })();
        *classifier = result.ok();
        u32::from(classifier.is_none())
    })
}
/// The aggregate polynomial that a ballot classified under the verified
/// setup reads as its FHE key; the maximum value when no setup is verified.
#[unsafe(no_mangle)]
pub extern "C" fn ballot_classification_key_index() -> usize {
    setup_aggregate::setup_browser::context()
        .map(|(_, setup)| crate::statement::setup_input(setup.profile()).2)
        .unwrap_or(usize::MAX)
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_classification_requires_key() -> u32 {
    SESSION.with(|session| {
        u32::from(
            session
                .borrow()
                .classifier
                .as_ref()
                .is_some_and(SignedBallotVerifier::requires_key),
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
        } else if let Some(inputs) = session
            .classifier
            .as_ref()
            .and_then(SignedBallotVerifier::inputs)
        {
            session.inputs = Some(inputs);
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

pub(super) fn take_classification() -> Option<BallotBodyClassification> {
    SESSION.with(|session| session.borrow_mut().classification.take())
}

pub(super) fn release_inputs() {
    SESSION.with(|session| session.borrow_mut().inputs = None);
}
