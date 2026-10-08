use protocol_foundations::{
    Credential, Error, SIGNATURE_BYTES,
    contribution_body::{ContributionBodyHasher, ContributionBodyHeader},
    contribution_offer::OfferEnvelope,
    roster::RetainedContributionContext,
    source_binding::FheKeyCommitmentHasher,
};

/// Original private work under the parent's authenticated one-shot offer
/// journal. It exposes no signer accepting a host-selected body identity.
#[derive(Default)]
pub struct OfferSigning {
    context: Option<RetainedContributionContext>,
    body: Option<ContributionBodyHasher>,
    source: Option<FheKeyCommitmentHasher>,
    source_matched: bool,
    envelope: Option<OfferEnvelope>,
    signature: Option<[u8; SIGNATURE_BYTES]>,
    failed: bool,
}
impl OfferSigning {
    pub fn body_started(&self) -> bool {
        self.context.is_some()
    }
    pub fn begin_body(
        &mut self,
        credential: &Credential,
        context: RetainedContributionContext,
        header: &[u8],
    ) -> Result<(), Error> {
        if self.context.is_some() || self.failed {
            return Err(Error::Consumed);
        }
        credential.validate_offer_owner(&context)?;
        let decoded = ContributionBodyHeader::decode(context.profile(), header)?;
        let source =
            FheKeyCommitmentHasher::for_retained(&context, credential, &decoded.source_salt)?;
        self.body = Some(ContributionBodyHasher::new(context.profile(), header)?);
        self.source = Some(source);
        self.context = Some(context);
        Ok(())
    }
    pub fn polynomial(&mut self, index: usize, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Consumed);
        }
        let result = (|| {
            let context = self.context.as_ref().ok_or(Error::Consumed)?;
            self.body
                .as_mut()
                .ok_or(Error::Consumed)?
                .push_polynomial(index, offset, bytes)?;
            if index == context.profile().fhe_polynomial(0, 1) {
                self.source
                    .as_mut()
                    .ok_or(Error::Consumed)?
                    .push(offset, bytes)?;
                if offset + bytes.len()
                    == context
                        .profile()
                        .setup_polynomial_bytes(index)
                        .ok_or(Error::Shape)?
                {
                    let actual = self.source.take().ok_or(Error::Consumed)?.finish()?;
                    if &actual != context.fhe_key_commitment() {
                        return Err(Error::Context);
                    }
                    self.source_matched = true;
                }
            }
            Ok(())
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    pub fn proof(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Consumed);
        }
        let result = self
            .body
            .as_mut()
            .ok_or(Error::Consumed)?
            .push_proof(offset, bytes);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    pub fn finish_body(&mut self) -> Result<(), Error> {
        if self.failed || !self.source_matched {
            return Err(Error::Context);
        }
        let body = self.body.take().ok_or(Error::Consumed)?.finish()?;
        self.envelope = Some(OfferEnvelope::for_retained(
            self.context.as_ref().ok_or(Error::Consumed)?,
            body.length(),
            *body.identity(),
        )?);
        Ok(())
    }
    pub fn envelope(&self) -> Option<&OfferEnvelope> {
        self.envelope.as_ref()
    }
    pub fn sign(&mut self, credential: &mut Credential) -> Result<(), Error> {
        if self.failed || self.signature.is_some() {
            return Err(Error::Consumed);
        }
        self.signature = Some(credential.sign_offer(
            self.context.as_ref().ok_or(Error::Consumed)?,
            self.envelope.as_ref().ok_or(Error::Consumed)?,
        )?);
        Ok(())
    }
    pub fn offer(&self) -> Option<(&OfferEnvelope, &[u8; SIGNATURE_BYTES])> {
        Some((self.envelope.as_ref()?, self.signature.as_ref()?))
    }
    pub fn restore(
        &mut self,
        credential: &mut Credential,
        envelope: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        if self.failed
            || self.signature.is_some()
            || self
                .envelope
                .as_ref()
                .is_none_or(|held| held.bytes() != envelope)
        {
            return Err(Error::Context);
        }
        credential.restore_offer(
            self.context.as_ref().ok_or(Error::Consumed)?,
            self.envelope.as_ref().ok_or(Error::Consumed)?,
            signature,
        )?;
        self.signature = Some(signature.try_into().map_err(|_| Error::Shape)?);
        Ok(())
    }
}
