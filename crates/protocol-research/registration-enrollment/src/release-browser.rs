use super::{INPUT_BYTES, SESSION, Session};
use evaluation_target::release_body::{ReleaseBodyVerifier, VerifiedReleaseBody};
use registration_credentials::{
    Error,
    release_signing::{
        MAXIMUM_BODY_BYTES, RELEASE_BODY_HEADER_BYTES, RELEASE_ENVELOPE_BYTES, ReleaseBodyHasher,
        ReleaseEnvelope, body_header,
    },
    target_signing::TargetMessage,
};
use zeroize::{Zeroize, Zeroizing};

const CHUNK_BYTES: usize = 1 << 20;

pub(super) struct ReleaseState {
    body: Vec<u8>,
    envelope: ReleaseEnvelope,
    verified: Option<VerifiedReleaseBody>,
    completed: Option<(Vec<u8>, Vec<u8>)>,
    hasher: Option<ReleaseBodyHasher>,
    import_closed: bool,
}

fn verify_body(
    context: std::sync::Arc<evaluation_target::release::ReleaseContext>,
    body: &[u8],
) -> Result<VerifiedReleaseBody, Error> {
    let header = body.get(..RELEASE_BODY_HEADER_BYTES).ok_or(Error::Shape)?;
    let mut verifier = ReleaseBodyVerifier::new(context, header).map_err(|_| Error::Crypto)?;
    for chunk in body[RELEASE_BODY_HEADER_BYTES..].chunks(CHUNK_BYTES) {
        verifier.push(chunk).map_err(|_| Error::Crypto)?;
    }
    verifier.finish().map_err(|_| Error::Crypto)
}

fn command(session: &mut Session, operation: u32, input: &[u8]) -> Result<Vec<u8>, Error> {
    let close = session.close.as_ref().ok_or(Error::Context)?;
    let owner = close.owner();
    let setup = close.setup();
    let roster = setup.inventory().proposal();
    match operation {
        // The worker commits the target and complete original entropy journal
        // before this call. Only the public verifier can supply the context.
        0 => {
            if session.release.is_some() {
                return Err(Error::Consumed);
            }
            let context =
                evaluation_target::verified_browser_release_context().ok_or(Error::Context)?;
            if input != context.certificate().target().body() {
                return Err(Error::Context);
            }
            if !linked_release_proof::release_entropy::ready() {
                return Err(Error::Context);
            }
            let work = crate::release_work::ReleaseWork::new(owner, context)?;
            let enrollment = session.enrollment.as_mut().ok_or(Error::Context)?;
            let (context, statement, proof) =
                work.prove(&enrollment.key, &mut enrollment.credential)?;
            let mut proof_bytes = Vec::new();
            proof.write(&mut proof_bytes);
            drop(proof);
            let mut body = body_header(context.header(), proof_bytes.len())?;
            body.extend(&statement.polynomials[5]);
            body.extend(proof_bytes);
            drop(statement);
            let verified = verify_body(context, &body)?;
            let envelope = verified.envelope();
            let output = envelope.bytes().to_vec();
            session.release = Some(ReleaseState {
                body,
                envelope,
                verified: Some(verified),
                completed: None,
                hasher: None,
                import_closed: false,
            });
            Ok(output)
        }
        1 => {
            if input.len() != 8 {
                return Err(Error::Shape);
            }
            let offset = u32::from_le_bytes(input[..4].try_into().unwrap()) as usize;
            let length = u32::from_le_bytes(input[4..].try_into().unwrap()) as usize;
            let state = session.release.as_ref().ok_or(Error::Context)?;
            if state.verified.is_none() || length == 0 || length > CHUNK_BYTES {
                return Err(Error::Context);
            }
            state
                .body
                .get(offset..offset.checked_add(length).ok_or(Error::Shape)?)
                .map(|value| value.to_vec())
                .ok_or(Error::Shape)
        }
        // A retained unsigned body must again pass the owning proof verifier
        // under the actual certificate before a signature can be evaluated.
        2 => {
            if session.release.is_some() {
                return Err(Error::Consumed);
            }
            let envelope = ReleaseEnvelope::decode(input)?;
            let context =
                evaluation_target::verified_browser_release_context().ok_or(Error::Context)?;
            if context.position() != owner.position()
                || envelope.position() != owner.position()
                || envelope.poll() != owner.poll()
                || envelope.inventory() != owner.inventory()
                || envelope.target() != context.certificate().target().identity()
            {
                return Err(Error::Context);
            }
            let message = TargetMessage::parse(
                context.certificate().target().body(),
                roster.proposal().records().len(),
            )?;
            let enrollment = session.enrollment.as_mut().ok_or(Error::Context)?;
            enrollment
                .credential
                .begin_release(&owner, roster, &message)?;
            session.release = Some(ReleaseState {
                body: Vec::with_capacity(envelope.body_length()),
                envelope,
                verified: None,
                completed: None,
                hasher: None,
                import_closed: false,
            });
            Ok(Vec::new())
        }
        3 => {
            let state = session.release.as_mut().ok_or(Error::Context)?;
            if state.import_closed
                || state.verified.is_some()
                || input.is_empty()
                || input.len() > CHUNK_BYTES
                || input.len() > state.envelope.body_length() - state.body.len()
            {
                state.import_closed = true;
                return Err(Error::Shape);
            }
            if let Some(hasher) = state.hasher.as_mut() {
                hasher.push(input)?;
            }
            state.body.extend(input);
            Ok(Vec::new())
        }
        4 => {
            if !input.is_empty() {
                return Err(Error::Shape);
            }
            let state = session.release.as_mut().ok_or(Error::Context)?;
            if state.import_closed
                || state.verified.is_some()
                || state.body.len() != state.envelope.body_length()
            {
                state.import_closed = true;
                return Err(Error::Shape);
            }
            // Any failed verification permanently closes this volatile import.
            state.import_closed = true;
            if let Some((body, signature)) = state.completed.as_ref() {
                let identity = state.hasher.take().ok_or(Error::Consumed)?.finish()?;
                if &identity != state.envelope.body_identity() {
                    return Err(Error::Crypto);
                }
                let message = TargetMessage::parse(body, roster.proposal().records().len())?;
                let enrollment = session.enrollment.as_mut().ok_or(Error::Context)?;
                enrollment.credential.restore_release(
                    &owner,
                    roster,
                    &message,
                    &state.envelope,
                    signature,
                )?;
            } else {
                let context =
                    evaluation_target::verified_browser_release_context().ok_or(Error::Context)?;
                let verified = verify_body(context, &state.body)?;
                if verified.envelope().bytes() != state.envelope.bytes() {
                    return Err(Error::Context);
                }
                state.verified = Some(verified);
            }
            // A completed import restores consumed authority only. It does not
            // create a public release-share capability or permit signing.
            Ok(state.envelope.bytes().to_vec())
        }
        5 => {
            let state = session.release.as_ref().ok_or(Error::Context)?;
            let verified = state.verified.as_ref().ok_or(Error::Context)?;
            if input.len() != RELEASE_ENVELOPE_BYTES + 32
                || input[..RELEASE_ENVELOPE_BYTES] != *verified.envelope().bytes()
            {
                return Err(Error::Context);
            }
            let enrollment = session.enrollment.as_mut().ok_or(Error::Context)?;
            let signature = enrollment.credential.sign_release(
                &owner,
                roster,
                &verified.envelope(),
                input[RELEASE_ENVELOPE_BYTES..].try_into().unwrap(),
            )?;
            let mut packet = verified.envelope().bytes().to_vec();
            packet.extend(signature);
            Ok(packet)
        }
        6 => {
            if session.release.is_some() || input.len() < 4 + RELEASE_ENVELOPE_BYTES + 3309 {
                return Err(Error::Consumed);
            }
            let length = u32::from_le_bytes(input[..4].try_into().unwrap()) as usize;
            if length == 0
                || length > 2048
                || input.len() != 4 + length + RELEASE_ENVELOPE_BYTES + 3309
            {
                return Err(Error::Shape);
            }
            let body = &input[4..4 + length];
            let message = TargetMessage::parse(body, roster.proposal().records().len())?;
            let envelope =
                ReleaseEnvelope::decode(&input[4 + length..4 + length + RELEASE_ENVELOPE_BYTES])?;
            if !message.encrypted()
                || envelope.target() != message.identity()
                || envelope.poll() != owner.poll()
                || envelope.inventory() != owner.inventory()
                || envelope.position() != owner.position()
                || envelope.body_length() > MAXIMUM_BODY_BYTES
            {
                return Err(Error::Context);
            }
            let hasher = ReleaseBodyHasher::new(envelope.body_length())?;
            session.release = Some(ReleaseState {
                body: Vec::with_capacity(envelope.body_length()),
                envelope,
                verified: None,
                completed: Some((
                    body.to_vec(),
                    input[4 + length + RELEASE_ENVELOPE_BYTES..].to_vec(),
                )),
                hasher: Some(hasher),
                import_closed: false,
            });
            Ok(Vec::new())
        }
        _ => Err(Error::Shape),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn participant_release_command(operation: u32, length: usize) -> u32 {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        session.contribution_output.clear();
        if length > INPUT_BYTES {
            return 1;
        }
        let input = Zeroizing::new(session.input[..length].to_vec());
        session.input[..length].zeroize();
        match command(&mut session, operation, &input) {
            Ok(output) => {
                session.contribution_output = output;
                0
            }
            Err(_) => 1,
        }
    })
}
