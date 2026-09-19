use crate::{
    certification::{CertificateCollector, VerifiedTargetCertificate},
    release::{Error, ReleaseContext},
    release_body::{AuthenticatedReleaseEnvelope, ReleaseBodyVerifier},
    terminal::{ReleaseCollector, VerifiedNoResult, VerifiedResult, verify_no_result},
};
use setup_aggregate::{AggregatePolynomialReader, VerifiedAggregatePolynomial};
use std::{cell::RefCell, sync::Arc};

const CHUNK_BYTES: usize = 1 << 20;
enum Terminal {
    NoResult(VerifiedNoResult),
    Result(VerifiedResult),
}
struct Operand {
    position: usize,
    index: usize,
    reader: AggregatePolynomialReader,
    constant: Option<VerifiedAggregatePolynomial>,
}
struct State {
    input: Vec<u8>,
    output: Vec<u8>,
    votes: Option<CertificateCollector>,
    certificate: Option<Arc<VerifiedTargetCertificate>>,
    operand: Option<Operand>,
    context: Option<Arc<ReleaseContext>>,
    authentication: Option<AuthenticatedReleaseEnvelope>,
    body: Option<ReleaseBodyVerifier>,
    releases: Option<ReleaseCollector>,
    terminal: Option<Terminal>,
}
impl State {
    fn new() -> Self {
        Self {
            input: vec![0; CHUNK_BYTES],
            output: Vec::new(),
            votes: None,
            certificate: None,
            operand: None,
            context: None,
            authentication: None,
            body: None,
            releases: None,
            terminal: None,
        }
    }
    fn word(&mut self, value: usize) {
        self.output.extend((value as u32).to_le_bytes());
    }
    fn command(&mut self, operation: u32, argument: usize, length: usize) -> Result<(), Error> {
        if length > CHUNK_BYTES || (!matches!(operation, 3 | 4) && argument != 0) {
            return Err(Error::Encoding);
        }
        self.output.clear();
        match operation {
            0 => {
                if length != 0 || self.votes.is_some() {
                    return Err(Error::Context);
                }
                let target = crate::browser::verified_target().ok_or(Error::Incomplete)?;
                let count = target.inventory().setup().inventory().confirmations().len();
                let collector = CertificateCollector::new(target);
                self.word(count);
                self.word(collector.threshold());
                self.votes = Some(collector);
            }
            1 => {
                let votes = self.votes.as_mut().ok_or(Error::Incomplete)?;
                let inserted = votes
                    .insert(&self.input[..length])
                    .map_err(|_| Error::Signature)?;
                let count = votes.accepted();
                self.word(usize::from(inserted));
                self.word(count);
            }
            2 => {
                if length != 0 || self.certificate.is_some() {
                    return Err(Error::Context);
                }
                let certificate = Arc::new(
                    self.votes
                        .as_ref()
                        .ok_or(Error::Incomplete)?
                        .certificate()
                        .map_err(|_| Error::Incomplete)?,
                );
                let encrypted = certificate.target().ciphertext().is_some();
                if encrypted {
                    self.releases = Some(ReleaseCollector::new(certificate.clone())?);
                }
                self.certificate = Some(certificate);
                self.word(usize::from(encrypted));
            }
            3 => {
                if length != 0 {
                    return Err(Error::Encoding);
                }
                let certificate = self.certificate.as_ref().ok_or(Error::Incomplete)?;
                let target = certificate.target();
                if target.ciphertext().is_none() {
                    return Err(Error::NoResult);
                }
                let setup = target.inventory().setup();
                if setup.inventory().confirmations().len() != 10 || argument >= 10 {
                    return Err(Error::Context);
                }
                let index = 44 + 3 * argument;
                let reader = setup.read_polynomial(index).map_err(|_| Error::Context)?;
                // A public-data retry replaces only unfinished verification.
                // It cannot revoke a certified target or an accepted share.
                self.operand = Some(Operand {
                    position: argument,
                    index,
                    reader,
                    constant: None,
                });
                self.context = None;
                self.authentication = None;
                self.body = None;
                self.word(index);
            }
            4 => {
                self.operand
                    .as_mut()
                    .ok_or(Error::Incomplete)?
                    .reader
                    .push(argument, &self.input[..length])
                    .map_err(|_| Error::Encoding)?;
            }
            5 => {
                if length != 0 {
                    return Err(Error::Encoding);
                }
                let operand = self.operand.take().ok_or(Error::Incomplete)?;
                let verified = operand.reader.finish().map_err(|_| Error::Encoding)?;
                let certificate = self.certificate.as_ref().ok_or(Error::Incomplete)?;
                if let Some(constant) = operand.constant {
                    self.context = Some(Arc::new(ReleaseContext::new(
                        certificate.clone(),
                        operand.position,
                        constant,
                        verified,
                    )?));
                    self.word(0);
                } else {
                    let index = operand.index + 1;
                    let reader = certificate
                        .target()
                        .inventory()
                        .setup()
                        .read_polynomial(index)
                        .map_err(|_| Error::Context)?;
                    self.operand = Some(Operand {
                        position: operand.position,
                        index,
                        reader,
                        constant: Some(verified),
                    });
                    self.word(index);
                }
            }
            6 => {
                if self.authentication.is_some() {
                    return Err(Error::Context);
                }
                let authentication = self
                    .context
                    .as_ref()
                    .ok_or(Error::Incomplete)?
                    .authenticate(&self.input[..length])?;
                self.word(authentication.envelope().body_length());
                self.authentication = Some(authentication);
            }
            7 => {
                if self.body.is_some() || self.authentication.is_none() {
                    return Err(Error::Context);
                }
                self.body = Some(ReleaseBodyVerifier::new(
                    self.context.clone().ok_or(Error::Incomplete)?,
                    &self.input[..length],
                )?);
            }
            8 => {
                self.body
                    .as_mut()
                    .ok_or(Error::Incomplete)?
                    .push(&self.input[..length])?;
            }
            9 => {
                if length != 0 {
                    return Err(Error::Encoding);
                }
                let body = self.body.take().ok_or(Error::Incomplete)?.finish()?;
                let authentication = self.authentication.take().ok_or(Error::Incomplete)?;
                let share = Arc::new(body.authenticate(authentication)?);
                let inserted = self
                    .releases
                    .as_mut()
                    .ok_or(Error::Incomplete)?
                    .insert(share)?;
                self.context = None;
                self.word(usize::from(inserted));
            }
            10 => {
                if length != 0 {
                    return Err(Error::Encoding);
                }
                if self.terminal.is_none() {
                    let certificate = self.certificate.clone().ok_or(Error::Incomplete)?;
                    self.terminal = Some(if certificate.target().ciphertext().is_none() {
                        Terminal::NoResult(verify_no_result(certificate)?)
                    } else {
                        Terminal::Result(self.releases.as_ref().ok_or(Error::Incomplete)?.result()?)
                    });
                }
                match self.terminal.as_ref().ok_or(Error::Incomplete)? {
                    Terminal::NoResult(value) => {
                        if value.certificate().target().ciphertext().is_some() {
                            return Err(Error::Context);
                        }
                        self.output.extend(0u32.to_le_bytes());
                    }
                    Terminal::Result(value) => {
                        self.output
                            .extend((value.identifiers().len() as u32).to_le_bytes());
                        for identifier in value.identifiers() {
                            self.output.extend((identifier.len() as u32).to_le_bytes());
                            self.output.extend(identifier.as_bytes());
                        }
                    }
                }
            }
            _ => return Err(Error::Encoding),
        }
        Ok(())
    }
}
thread_local! {static STATE:RefCell<State>=RefCell::new(State::new());}
#[unsafe(no_mangle)]
pub extern "C" fn completion_input_pointer() -> usize {
    STATE.with(|state| state.borrow_mut().input.as_mut_ptr() as usize)
}
#[unsafe(no_mangle)]
pub extern "C" fn completion_output_pointer() -> usize {
    STATE.with(|state| state.borrow().output.as_ptr() as usize)
}
#[unsafe(no_mangle)]
pub extern "C" fn completion_output_length() -> usize {
    STATE.with(|state| state.borrow().output.len())
}
#[unsafe(no_mangle)]
pub extern "C" fn completion_command(operation: u32, argument: usize, length: usize) -> u32 {
    STATE.with(|state| {
        u32::from(
            state
                .borrow_mut()
                .command(operation, argument, length)
                .is_err(),
        )
    })
}
