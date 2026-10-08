use protocol_foundations::{
    Error, SIGNATURE_BYTES,
    poll::{MAXIMUM_POLL_BYTES, VerifiedPoll, verify_poll},
    registration::{CHUNK_LIMIT, RegistrationVerifier, VerifiedRegistration},
};
use std::sync::Arc;

const MAXIMUM_HEADER_BYTES: usize = 4096;
protocol_foundations::operation_codes! {
    /// The steps of the verification of the participant's own registration.
    enum OwnRegistrationStep {
        Begin = 0,
        Key = 1,
        KeyFinish = 2,
        Finish = 4,
    }
}
pub(crate) const CONTROL_BYTES: usize =
    128 + 4 + MAXIMUM_POLL_BYTES + SIGNATURE_BYTES + 4 + MAXIMUM_HEADER_BYTES + SIGNATURE_BYTES;
pub(crate) struct State {
    pub(crate) input: Vec<u8>,
    pub(crate) pending: Option<RegistrationVerifier>,
    // The verified poll that the pending or verified registration names, and
    // its option count; no later input can replace them.
    pub(crate) poll: Option<VerifiedPoll>,
    pub(crate) options: usize,
    pub(crate) verified: Option<Arc<VerifiedRegistration>>,
}
impl State {
    pub(crate) fn new() -> Self {
        Self {
            input: vec![0; CONTROL_BYTES],
            pending: None,
            poll: None,
            options: 0,
            verified: None,
        }
    }
    fn begin(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() < 132 {
            return Err(Error::Shape);
        }
        let definition_bytes = u32::from_le_bytes(bytes[128..132].try_into().unwrap()) as usize;
        if definition_bytes > MAXIMUM_POLL_BYTES
            || bytes.len() < 132 + definition_bytes + SIGNATURE_BYTES + 4
        {
            return Err(Error::Shape);
        }
        let end = 132 + definition_bytes;
        let poll = verify_poll(
            bytes[..64].try_into().unwrap(),
            bytes[64..128].try_into().unwrap(),
            &bytes[132..end],
            &bytes[end..end + SIGNATURE_BYTES],
        )?;
        let header_start = end + SIGNATURE_BYTES + 4;
        let header_bytes =
            u32::from_le_bytes(bytes[header_start - 4..header_start].try_into().unwrap()) as usize;
        if header_bytes > MAXIMUM_HEADER_BYTES
            || bytes.len() != header_start + header_bytes + SIGNATURE_BYTES
        {
            return Err(Error::Shape);
        }
        self.pending = Some(RegistrationVerifier::new(
            &poll,
            &bytes[header_start..header_start + header_bytes],
            &bytes[header_start + header_bytes..],
        )?);
        self.options = poll.manifest().option_count();
        self.poll = Some(poll);
        Ok(())
    }
    pub(crate) fn command(&mut self, operation: u32, length: usize) -> Result<(), Error> {
        let operation = OwnRegistrationStep::from_code(operation);
        if length > self.input.len()
            || (operation != Some(OwnRegistrationStep::Begin) && length > CHUNK_LIMIT)
        {
            return Err(Error::Shape);
        }
        if operation == Some(OwnRegistrationStep::Begin) {
            // Only a refused begin leaves another begin open.
            if self.poll.is_some() {
                return Err(Error::Consumed);
            }
            let bytes = self.input[..length].to_vec();
            return self.begin(&bytes);
        }
        if self.verified.is_some() {
            return Err(Error::Consumed);
        }
        match operation {
            Some(OwnRegistrationStep::Key) => self
                .pending
                .as_mut()
                .ok_or(Error::Consumed)?
                .push_key(&self.input[..length]),
            Some(OwnRegistrationStep::KeyFinish) if length == 0 => {
                self.pending.as_mut().ok_or(Error::Consumed)?.finish_key()
            }
            Some(OwnRegistrationStep::Finish) if length == 0 => {
                let verified = self.pending.take().ok_or(Error::Consumed)?.finish()?;
                self.verified = Some(Arc::new(verified));
                Ok(())
            }
            _ => Err(Error::Shape),
        }
    }
}

#[cfg(test)]
#[path = "own-verification-tests.rs"]
mod tests;
