use crate::certification::VerifiedInventoryCertificate;
use linked_release_proof::statement::{self, PublicStatement};
use linked_release_proof::{CHUNK_LIMIT, Verifier};
use num_bigint::BigInt;
use protocol_foundations::foundation::participant_identity::{
    ParticipantIdentity, derive_participant_identity,
};
use protocol_foundations::foundation::{CanonicalItem, CanonicalTuple};
use setup_aggregate::VerifiedAggregatePolynomial;
use statement_stream::coefficient::CenteredCodec;
use std::sync::Arc;
use supported_profile::{
    Profile,
    relation::{RELEASE_HEADER_BYTES, SYSTEMATIC, release_coefficient_bytes},
};

/// Canonical public role bytes; this encoding alone grants no release authority.
fn encode_release_proof_role(
    participant_identity: ParticipantIdentity,
    poll: [u8; 64],
    setup_identity: [u8; 64],
    target: [u8; 64],
    position: usize,
) -> Result<Vec<u8>, Refusal> {
    let position = u16::try_from(position).map_err(|_| Refusal::Context)?;
    CanonicalTuple::new(
        1,
        vec![
            CanonicalItem::nonempty_ascii("sealed-lattice/certified-release")
                .map_err(|_| Refusal::Encoding)?,
            CanonicalItem::nonempty_ascii(&participant_identity.to_lowercase_hex())
                .map_err(|_| Refusal::Encoding)?,
            CanonicalItem::hash512(poll),
            CanonicalItem::hash512(setup_identity),
            CanonicalItem::hash512(target),
            CanonicalItem::unsigned16(position),
        ],
    )
    .encode()
    .map_err(|_| Refusal::Encoding)
}
#[derive(Debug)]
pub enum Refusal {
    Context,
    NoResult,
    Encoding,
    Proof,
    Signature,
    Incomplete,
}
impl From<statement::Refusal> for Refusal {
    fn from(_: statement::Refusal) -> Self {
        Self::Encoding
    }
}

/// The systematic coefficients of a polynomial of the little-endian
/// modulus, in canonical records.
pub(crate) fn decode_polynomial(bytes: &[u8], modulus: &[u8]) -> Result<Vec<BigInt>, Refusal> {
    let codec = CenteredCodec::new(modulus);
    if bytes.len() != SYSTEMATIC * codec.record_bytes() {
        return Err(Refusal::Encoding);
    }
    codec.decode_all(bytes).ok_or(Refusal::Encoding)
}

/// Public operands and original participant position for one certified target.
/// Neither an uncertified body nor a caller-selected ciphertext enters here.
pub struct ReleaseContext {
    profile: Profile,
    certificate: Arc<VerifiedInventoryCertificate>,
    position: usize,
    header: [u8; RELEASE_HEADER_BYTES],
    constant: VerifiedAggregatePolynomial,
    linear: VerifiedAggregatePolynomial,
    target_linear: Vec<BigInt>,
    public_key: Vec<BigInt>,
}
impl ReleaseContext {
    pub fn new(
        certificate: Arc<VerifiedInventoryCertificate>,
        position: usize,
        constant: VerifiedAggregatePolynomial,
        linear: VerifiedAggregatePolynomial,
    ) -> Result<Self, Refusal> {
        let target = certificate.target();
        let setup = target.setup();
        let profile = setup.profile();
        let ciphertext = target.ciphertext().ok_or(Refusal::NoResult)?;
        let records = setup.roster().proposal().records();
        let release_bytes = release_coefficient_bytes(profile);
        if position >= profile.participants()
            || records.len() != profile.participants()
            || records[position].header().poll != target.poll().identity()
            || constant.setup_identity() != &setup.identity()
            || linear.setup_identity() != &setup.identity()
            || constant.index() != profile.share_constant_polynomial(position)
            || linear.index() != profile.share_linear_polynomial(position)
            || ciphertext.len() != 2 * SYSTEMATIC * release_bytes
        {
            return Err(Refusal::Context);
        }
        let public_key = decode_polynomial(
            records[position].public_key(),
            supported_profile::share_modulus(),
        )?;
        let target_linear = decode_polynomial(
            &ciphertext[SYSTEMATIC * release_bytes..],
            &profile.release_modulus().to_bytes(),
        )?;
        let mut header = [0; RELEASE_HEADER_BYTES];
        header[..4].copy_from_slice(b"LRS1");
        header[4..68].copy_from_slice(&target.poll().identity());
        header[68..132].copy_from_slice(&setup.identity());
        header[132..196].copy_from_slice(target.identity());
        header[196..].copy_from_slice(&(position as u16).to_le_bytes());
        Ok(Self {
            profile,
            certificate,
            position,
            header,
            constant,
            linear,
            target_linear,
            public_key,
        })
    }
    pub fn profile(&self) -> Profile {
        self.profile
    }
    pub fn header(&self) -> &[u8; RELEASE_HEADER_BYTES] {
        &self.header
    }
    pub fn position(&self) -> usize {
        self.position
    }
    pub fn certificate(&self) -> &Arc<VerifiedInventoryCertificate> {
        &self.certificate
    }
    pub fn proof_role(&self) -> Result<Vec<u8>, Refusal> {
        let target = self.certificate.target();
        let original = target
            .setup()
            .roster()
            .proposal()
            .records()
            .get(self.position)
            .ok_or(Refusal::Context)?;
        encode_release_proof_role(
            derive_participant_identity(&original.header().signing_public)
                .map_err(|_| Refusal::Context)?,
            target.poll().identity(),
            target.setup().identity(),
            *target.identity(),
            self.position,
        )
    }
    pub fn public_key(&self) -> &[BigInt] {
        &self.public_key
    }
    pub fn encrypted_constant(&self) -> &[BigInt] {
        self.constant.coefficients()
    }
    pub fn encrypted_linear(&self) -> &[BigInt] {
        self.linear.coefficients()
    }
    pub fn target_linear(&self) -> &[BigInt] {
        &self.target_linear
    }
    /// Feeds the exact statement from this immutable verified context. No
    /// full encoded copy of its public polynomials is retained.
    fn visit_statement(
        &self,
        partial: &[u8],
        consume: impl FnMut(usize, &[u8]) -> Result<(), Refusal>,
    ) -> Result<(), Refusal> {
        visit_statement(
            self.profile,
            &self.header,
            [
                self.public_key(),
                self.encrypted_constant(),
                self.encrypted_linear(),
                self.target_linear(),
            ],
            partial,
            consume,
        )
    }
    /// Opens the mathematical verifier only with the original signer and
    /// operands derived from this context's certificate and setup.
    pub fn verifier(&self, partial: &[u8], header: &[u8]) -> Result<Verifier, Refusal> {
        let mut verifier = None;
        self.visit_statement(partial, |_, bytes| {
            // Preserve the oracle order: canonical output and fixed common
            // expansion precede the proof role and its challenges.
            if verifier.is_none() {
                verifier = Some(
                    linked_release_proof::verifier(self.profile, &self.proof_role()?, header)
                        .map_err(|_| Refusal::Proof)?,
                );
            }
            verifier
                .as_mut()
                .ok_or(Refusal::Incomplete)?
                .push_statement(bytes)
                .map_err(|_| Refusal::Proof)
        })?;
        let mut verifier = verifier.ok_or(Refusal::Incomplete)?;
        verifier.finish_statement().map_err(|_| Refusal::Proof)?;
        Ok(verifier)
    }
    /// Compares every generated byte with the same certified operands used
    /// by public verification, without constructing another statement.
    pub fn check_statement(&self, statement: &PublicStatement) -> Result<(), Refusal> {
        if statement.profile != self.profile || statement.polynomials.len() != 6 {
            return Err(Refusal::Context);
        }
        let fields: Vec<&[u8]> = std::iter::once(statement.header.as_slice())
            .chain(statement.polynomials.iter().map(Vec::as_slice))
            .collect();
        let mut offsets = [0; 7];
        self.visit_statement(&statement.polynomials[5], |index, bytes| {
            let end = offsets[index] + bytes.len();
            if fields[index].get(offsets[index]..end) != Some(bytes) {
                return Err(Refusal::Context);
            }
            offsets[index] = end;
            Ok(())
        })?;
        if offsets
            .iter()
            .zip(fields)
            .any(|(used, field)| *used != field.len())
        {
            return Err(Refusal::Context);
        }
        Ok(())
    }
}

fn visit_statement(
    profile: Profile,
    header: &[u8; RELEASE_HEADER_BYTES],
    polynomials: [&[BigInt]; 4],
    partial: &[u8],
    mut consume: impl FnMut(usize, &[u8]) -> Result<(), Refusal>,
) -> Result<(), Refusal> {
    let codec = CenteredCodec::new(&profile.release_modulus().to_bytes());
    if partial.len() != SYSTEMATIC * codec.record_bytes()
        || !partial
            .chunks_exact(codec.record_bytes())
            .all(|record| codec.is_canonical(record))
    {
        return Err(Refusal::Encoding);
    }
    let common = setup_witness::contribution::common_share_polynomial();
    consume(0, header)?;
    for (index, values) in std::iter::once(common.as_slice())
        .chain(polynomials)
        .enumerate()
    {
        let width = if index < 4 {
            statement::share_coefficient_bytes()
        } else {
            codec.record_bytes()
        };
        statement::polynomial_chunks(values, width, |bytes| consume(index + 1, bytes))?;
    }
    for chunk in partial.chunks(CHUNK_LIMIT) {
        consume(6, chunk)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "release-tests.rs"]
mod tests;
