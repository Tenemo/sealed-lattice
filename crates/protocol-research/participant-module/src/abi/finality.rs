use super::{SESSION, Session};
use protocol_foundations::{
    Error,
    target_signing::{MAXIMUM_TARGET_BODY_BYTES, TARGET_VOTE_BYTES},
};
use zeroize::{Zeroize, Zeroizing};

fn field<'a>(bytes: &mut &'a [u8], maximum: usize) -> Result<&'a [u8], Error> {
    if bytes.len() < 4 {
        return Err(Error::Shape);
    }
    let length = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
    if length > maximum || length > bytes.len() - 4 {
        return Err(Error::Shape);
    }
    let value = &bytes[4..4 + length];
    *bytes = &bytes[4 + length..];
    Ok(value)
}

protocol_foundations::operation_codes! {
    /// The participant's finality commands.
    enum FinalityOperation {
        Begin = 0,
        SignVote = 1,
        RestoreSignedTarget = 2,
        CertifiedBallotInclusion = 3,
    }
}
fn command(session: &mut Session, operation: u32, input: &[u8]) -> Result<Vec<u8>, Error> {
    let close = session.close.as_ref().ok_or(Error::Context)?;
    match FinalityOperation::from_code(operation) {
        // Returns the ballot status code (0 not cast, 1 late, 2 included,
        // 3 omitted) followed by the target body to persist before signing.
        Some(FinalityOperation::Begin) => {
            if session.finality.is_some() || !input.is_empty() {
                return Err(Error::Consumed);
            }
            let target = super::evaluation::verified_target().ok_or(Error::Context)?;
            let work = crate::finality_work::FinalityWork::new(close.owner(), target)?;
            let enrollment = session.enrollment.as_ref().ok_or(Error::Context)?;
            let mut output = vec![work.ballot_inclusion(&enrollment.credential).code()];
            output.extend(work.body());
            session.finality = Some(work);
            Ok(output)
        }
        Some(FinalityOperation::SignVote) => {
            if !(1..=MAXIMUM_TARGET_BODY_BYTES).contains(&input.len()) {
                return Err(Error::Shape);
            }
            let work = session.finality.as_ref().ok_or(Error::Context)?;
            let enrollment = session.enrollment.as_mut().ok_or(Error::Context)?;
            work.sign(&mut enrollment.credential, input)
                .map(|vote| vote.encode())
        }
        Some(FinalityOperation::RestoreSignedTarget) => {
            if session.finality.is_some() {
                return Err(Error::Consumed);
            }
            let mut remaining = input;
            let body = field(&mut remaining, MAXIMUM_TARGET_BODY_BYTES)?;
            if remaining.len() != TARGET_VOTE_BYTES {
                return Err(Error::Shape);
            }
            let enrollment = session.enrollment.as_mut().ok_or(Error::Context)?;
            close.restore_target(&mut enrollment.credential, body, remaining)?;
            Ok(Vec::new())
        }
        // The own ballot's status code in the target this instance
        // certified, for a participant that signed no target of its own.
        // Only the certificate verifier supplies the target.
        Some(FinalityOperation::CertifiedBallotInclusion) => {
            if !input.is_empty() {
                return Err(Error::Shape);
            }
            let certificate = super::completion::verified_certificate().ok_or(Error::Context)?;
            let enrollment = session.enrollment.as_ref().ok_or(Error::Context)?;
            close
                .released_ballot_inclusion(&enrollment.credential, certificate.target().body())
                .map(|status| vec![status.code()])
        }
        None => Err(Error::Shape),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn participant_finality_command(operation: u32, length: usize) -> u32 {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        session.contribution_output.clear();
        if length > session.input.len() {
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
