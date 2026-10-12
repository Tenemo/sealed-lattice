use crate::{
    certification::{CertificateCollector, VerifiedInventoryCertificate},
    release::{Error, ReleaseContext},
    release_body::{AuthenticatedReleaseEnvelope, ReleaseBodyVerifier},
    target::VerifiedEvaluationTarget,
    terminal::{ReleaseCollector, VerifiedNoResult, VerifiedResult, verify_no_result},
};
use setup_aggregate::{AggregatePolynomialReader, VerifiedAggregatePolynomial};
use std::sync::Arc;

protocol_foundations::operation_codes! {
    /// The completion commands: the votes that certify the target, each
    /// release share's operands and body, and the result.
    enum CompletionOperation {
        BeginVotes = 0,
        InsertVote = 1,
        Certify = 2,
        BeginShareConstant = 3,
        PushOperand = 4,
        FinishOperand = 5,
        AuthenticateRelease = 6,
        BeginReleaseBody = 7,
        PushReleaseBody = 8,
        FinishRelease = 9,
        Result = 10,
    }
}
/// The input buffer's length; the host never writes more.
pub const COMPLETION_INPUT_BYTES: usize = 1 << 20;
enum Terminal {
    NoResult(VerifiedNoResult),
    Result(VerifiedResult),
}
struct Operand {
    position: usize,
    reader: AggregatePolynomialReader,
    constant: Option<VerifiedAggregatePolynomial>,
}
/// The completion of one instance: the target's certificate from its votes,
/// the verified release shares and the terminal they reach.
pub struct CompletionSession {
    input: Vec<u8>,
    output: Vec<u8>,
    votes: Option<CertificateCollector>,
    certificate: Option<Arc<VerifiedInventoryCertificate>>,
    operand: Option<Operand>,
    context: Option<Arc<ReleaseContext>>,
    authentication: Option<AuthenticatedReleaseEnvelope>,
    body: Option<ReleaseBodyVerifier>,
    releases: Option<ReleaseCollector>,
    terminal: Option<Terminal>,
}
impl CompletionSession {
    pub fn new() -> Self {
        Self {
            input: vec![0; COMPLETION_INPUT_BYTES],
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
    pub fn input(&mut self) -> &mut [u8] {
        &mut self.input
    }
    pub fn output(&self) -> &[u8] {
        &self.output
    }
    /// The release context of the share being verified.
    pub fn context(&self) -> Option<Arc<ReleaseContext>> {
        self.context.clone()
    }
    /// The inventory certificate this instance verified.
    pub fn certificate(&self) -> Option<Arc<VerifiedInventoryCertificate>> {
        self.certificate.clone()
    }
    fn word(&mut self, value: usize) {
        self.output.extend((value as u32).to_le_bytes());
    }
    /// Runs a completion operation. The first one takes the instance's
    /// verified evaluation target, which `target` reads.
    pub fn command(
        &mut self,
        target: impl FnOnce() -> Option<Arc<VerifiedEvaluationTarget>>,
        operation: u32,
        argument: usize,
        length: usize,
    ) -> Result<(), Error> {
        let operation = CompletionOperation::from_code(operation);
        if length > COMPLETION_INPUT_BYTES
            || (!matches!(
                operation,
                Some(CompletionOperation::BeginShareConstant | CompletionOperation::PushOperand)
            ) && argument != 0)
        {
            return Err(Error::Encoding);
        }
        self.output.clear();
        match operation {
            Some(CompletionOperation::BeginVotes) => {
                if length != 0 || self.votes.is_some() {
                    return Err(Error::Context);
                }
                let target = target().ok_or(Error::Incomplete)?;
                let count = target.setup().profile().participants();
                let collector = CertificateCollector::new(target);
                self.word(count);
                self.word(collector.threshold());
                self.votes = Some(collector);
            }
            Some(CompletionOperation::InsertVote) => {
                let votes = self.votes.as_mut().ok_or(Error::Incomplete)?;
                let inserted = votes
                    .insert(&self.input[..length])
                    .map_err(|_| Error::Signature)?;
                let count = votes.accepted();
                self.word(usize::from(inserted));
                self.word(count);
            }
            Some(CompletionOperation::Certify) => {
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
            Some(CompletionOperation::BeginShareConstant) => {
                if length != 0 {
                    return Err(Error::Encoding);
                }
                let certificate = self.certificate.as_ref().ok_or(Error::Incomplete)?;
                let target = certificate.target();
                if target.ciphertext().is_none() {
                    return Err(Error::NoResult);
                }
                let setup = target.setup();
                let profile = setup.profile();
                if argument >= profile.participants() {
                    return Err(Error::Context);
                }
                let index = profile.share_constant_polynomial(argument);
                let reader = setup.read_polynomial(index).map_err(|_| Error::Context)?;
                // A public-data retry replaces only unfinished verification.
                // It cannot revoke a certified target or an accepted share.
                self.operand = Some(Operand {
                    position: argument,
                    reader,
                    constant: None,
                });
                self.context = None;
                self.authentication = None;
                self.body = None;
                self.word(index);
            }
            Some(CompletionOperation::PushOperand) => {
                self.operand
                    .as_mut()
                    .ok_or(Error::Incomplete)?
                    .reader
                    .push(argument, &self.input[..length])
                    .map_err(|_| Error::Encoding)?;
            }
            Some(CompletionOperation::FinishOperand) => {
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
                    let setup = certificate.target().setup();
                    let index = setup.profile().share_linear_polynomial(operand.position);
                    let reader = setup.read_polynomial(index).map_err(|_| Error::Context)?;
                    self.operand = Some(Operand {
                        position: operand.position,
                        reader,
                        constant: Some(verified),
                    });
                    self.word(index);
                }
            }
            Some(CompletionOperation::AuthenticateRelease) => {
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
            Some(CompletionOperation::BeginReleaseBody) => {
                if self.body.is_some() || self.authentication.is_none() {
                    return Err(Error::Context);
                }
                self.body = Some(ReleaseBodyVerifier::new(
                    self.context.clone().ok_or(Error::Incomplete)?,
                    &self.input[..length],
                )?);
            }
            Some(CompletionOperation::PushReleaseBody) => {
                self.body
                    .as_mut()
                    .ok_or(Error::Incomplete)?
                    .push(&self.input[..length])?;
            }
            Some(CompletionOperation::FinishRelease) => {
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
            Some(CompletionOperation::Result) => {
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
            None => return Err(Error::Encoding),
        }
        Ok(())
    }
}
impl Default for CompletionSession {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "completion-session-tests.rs"]
mod tests;
