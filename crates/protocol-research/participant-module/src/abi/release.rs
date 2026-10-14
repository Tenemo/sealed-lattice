use super::{SESSION, Session};
use crate::{release_body::OwnReleaseBody, release_work::ReleaseWork};
use protocol_foundations::{
    Refusal,
    release_signing::{ReleaseEnvelope, body_header},
    target_signing::TargetMessage,
};
use zeroize::{Zeroize, Zeroizing};

protocol_foundations::operation_codes! {
    /// The participant's release commands.
    enum ReleaseOperation {
        Create = 0,
        BodySlice = 1,
        BeginImport = 2,
        PushImport = 3,
        FinishImport = 4,
        Sign = 5,
    }
}
fn command(session: &mut Session, operation: u32, input: &[u8]) -> Result<Vec<u8>, Refusal> {
    let close = session.close.as_ref().ok_or(Refusal::Context)?;
    let owner = close.owner();
    let setup = close.setup();
    let profile = setup.profile();
    let roster = setup.roster();
    match ReleaseOperation::from_code(operation) {
        // The worker commits the target and the release seed before this
        // call and installs the seed's undrawn randomness. Only the public
        // verifier can supply the context.
        Some(ReleaseOperation::Create) => {
            if session.release.is_some() {
                return Err(Refusal::Consumed);
            }
            let context = super::completion::verified_release_context().ok_or(Refusal::Context)?;
            if input != context.certificate().target().body() {
                return Err(Refusal::Context);
            }
            if !super::operation_random::ready(crate::operation_random::Purpose::Release) {
                return Err(Refusal::Context);
            }
            let work = ReleaseWork::new(owner, context)?;
            let enrollment = session.enrollment.as_mut().ok_or(Refusal::Context)?;
            let (context, statement, proof) =
                work.prove(&enrollment.key, &mut enrollment.credential)?;
            let mut proof_bytes = Vec::new();
            proof.write(&mut proof_bytes);
            drop(proof);
            let mut body = body_header(profile, context.header(), proof_bytes.len())?;
            body.extend(&statement.polynomials[5]);
            body.extend(proof_bytes);
            drop(statement);
            let release = OwnReleaseBody::generated(context, body)?;
            let output = release.envelope().bytes().to_vec();
            session.release = Some(release);
            Ok(output)
        }
        Some(ReleaseOperation::BodySlice) => {
            if input.len() != 8 {
                return Err(Refusal::Shape);
            }
            let offset = u32::from_le_bytes(input[..4].try_into().unwrap()) as usize;
            let length = u32::from_le_bytes(input[4..].try_into().unwrap()) as usize;
            let release = session.release.as_ref().ok_or(Refusal::Context)?;
            Ok(release.slice(offset, length)?.to_vec())
        }
        // A retained unsigned body must again pass the owning proof verifier
        // under the actual certificate before a signature can be evaluated.
        Some(ReleaseOperation::BeginImport) => {
            if session.release.is_some() {
                return Err(Refusal::Consumed);
            }
            let envelope = ReleaseEnvelope::decode(profile, input)?;
            let context = super::completion::verified_release_context().ok_or(Refusal::Context)?;
            if context.position() != owner.position()
                || envelope.position() != owner.position()
                || envelope.poll() != owner.poll()
                || envelope.setup_identity() != owner.setup_identity()
                || envelope.target() != context.certificate().target().identity()
            {
                return Err(Refusal::Context);
            }
            let message = TargetMessage::parse(
                context.certificate().target().body(),
                roster.proposal().records().len(),
            )?;
            let enrollment = session.enrollment.as_mut().ok_or(Refusal::Context)?;
            enrollment
                .credential
                .begin_release(&owner, roster, &message)?;
            session.release = Some(OwnReleaseBody::importing(envelope));
            Ok(Vec::new())
        }
        Some(ReleaseOperation::PushImport) => {
            let release = session.release.as_mut().ok_or(Refusal::Context)?;
            release.push(input)?;
            Ok(Vec::new())
        }
        Some(ReleaseOperation::FinishImport) => {
            if !input.is_empty() {
                return Err(Refusal::Shape);
            }
            let release = session.release.as_mut().ok_or(Refusal::Context)?;
            release.finish(super::completion::verified_release_context())?;
            Ok(release.envelope().bytes().to_vec())
        }
        Some(ReleaseOperation::Sign) => {
            let release = session.release.as_ref().ok_or(Refusal::Context)?;
            let envelope = release.signable(input)?;
            let enrollment = session.enrollment.as_mut().ok_or(Refusal::Context)?;
            let signature = enrollment
                .credential
                .sign_release(&owner, roster, &envelope)?;
            let mut packet = envelope.bytes().to_vec();
            packet.extend(signature);
            Ok(packet)
        }
        None => Err(Refusal::Shape),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn participant_release_command(operation: u32, length: usize) -> u32 {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        session.participant_output.clear();
        if length > session.input.len() {
            return 1;
        }
        let input = Zeroizing::new(session.input[..length].to_vec());
        session.input[..length].zeroize();
        match command(&mut session, operation, &input) {
            Ok(output) => {
                session.participant_output = output;
                0
            }
            Err(_) => 1,
        }
    })
}
