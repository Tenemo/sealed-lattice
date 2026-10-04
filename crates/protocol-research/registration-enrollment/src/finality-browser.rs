use super::{SESSION, Session};
use registration_credentials::{
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

fn command(session: &mut Session, operation: u32, input: &[u8]) -> Result<Vec<u8>, Error> {
    let close = session.close.as_ref().ok_or(Error::Context)?;
    match operation {
        // Returns the ballot status code (0 not cast, 1 late, 2 included,
        // 3 omitted) followed by the target body to persist before signing.
        0 => {
            if session.finality.is_some() || !input.is_empty() {
                return Err(Error::Consumed);
            }
            let target = evaluation_target::verified_browser_target().ok_or(Error::Context)?;
            let work = crate::finality_work::FinalityWork::new(close.owner(), target)?;
            let enrollment = session.enrollment.as_ref().ok_or(Error::Context)?;
            let mut output = vec![work.ballot_status(&enrollment.credential).code()];
            output.extend(work.body());
            session.finality = Some(work);
            Ok(output)
        }
        1 => {
            if !(33..=MAXIMUM_TARGET_BODY_BYTES + 32).contains(&input.len()) {
                return Err(Error::Shape);
            }
            let body_length = input.len() - 32;
            let work = session.finality.as_ref().ok_or(Error::Context)?;
            let enrollment = session.enrollment.as_mut().ok_or(Error::Context)?;
            work.sign(
                &mut enrollment.credential,
                &input[..body_length],
                input[body_length..].try_into().unwrap(),
            )
            .map(|vote| vote.encode())
        }
        2 => {
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
        3 => {
            if !input.is_empty() {
                return Err(Error::Shape);
            }
            let certificate =
                evaluation_target::verified_browser_certificate().ok_or(Error::Context)?;
            let enrollment = session.enrollment.as_ref().ok_or(Error::Context)?;
            close
                .released_ballot_status(&enrollment.credential, certificate.target().body())
                .map(|status| vec![status.code()])
        }
        _ => Err(Error::Shape),
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
