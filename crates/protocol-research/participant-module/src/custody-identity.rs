//! Identities the participant runtime binds into its retained state or
//! addresses public records by. The module computes them so that the host
//! carries no hash of its own, and computes them here, since the host waits
//! for each identity right after its last bytes.

use crate::Error;
use protocol_foundations::{
    ballot_authentication::ENVELOPE_IDENTITY_DOMAIN, close_signing::ClosePurpose,
    identity::IdentityHasher, target_signing::TARGET_IDENTITY_DOMAIN,
};

/// The bytes one absorb call reads from the host.
pub const INPUT_BYTES: usize = 1 << 16;

protocol_foundations::operation_codes! {
    /// The closed set of purposes the host may request, each under its own
    /// domain. The target, envelope and close-response purposes yield the
    /// certified target's, a ballot envelope's and a close response body's
    /// own identities.
    enum CustodyPurpose {
        Root = 0,
        Record = 1,
        EnrollmentInput = 2,
        Target = 3,
        Envelope = 4,
        CloseResponse = 5,
    }
}
impl CustodyPurpose {
    fn domain(self) -> &'static str {
        match self {
            Self::Root => "sealed-lattice/participant-root/v1",
            Self::Record => "sealed-lattice/participant-record/v1",
            Self::EnrollmentInput => "sealed-lattice/enrollment-input/v1",
            Self::Target => TARGET_IDENTITY_DOMAIN,
            Self::Envelope => ENVELOPE_IDENTITY_DOMAIN,
            Self::CloseResponse => ClosePurpose::Response.context(),
        }
    }
}

pub struct State {
    pub(crate) input: Vec<u8>,
    pub(crate) output: [u8; 64],
    hash: Option<IdentityHasher>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            input: vec![0; INPUT_BYTES],
            output: [0; 64],
            hash: None,
        }
    }
}
impl State {
    /// Starts the identity of `length` bytes, discarding any unfinished one.
    pub fn begin(&mut self, purpose: u32, length: usize) -> Result<(), Error> {
        self.output = [0; 64];
        self.hash = None;
        let purpose = CustodyPurpose::from_code(purpose).ok_or(Error::Shape)?;
        let hash =
            IdentityHasher::local(purpose.domain(), &[], length).map_err(|_| Error::Shape)?;
        self.hash = Some(hash);
        Ok(())
    }
    /// Absorbs the first `length` input bytes, then clears them.
    pub fn absorb(&mut self, length: usize) -> Result<(), Error> {
        let result = match (self.input.get(..length), self.hash.as_mut()) {
            (Some(bytes), Some(hash)) => hash.absorb(bytes).map_err(|_| Error::Shape),
            (None, _) => Err(Error::Shape),
            (_, None) => Err(Error::State),
        };
        self.input[..length.min(INPUT_BYTES)].fill(0);
        if result.is_err() {
            self.hash = None;
        }
        result
    }
    /// Writes the identity once every committed byte is absorbed.
    pub fn finish(&mut self) -> Result<(), Error> {
        self.output = self
            .hash
            .take()
            .ok_or(Error::State)?
            .finish()
            .map_err(|_| Error::Shape)?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "custody-identity-tests.rs"]
mod tests;
