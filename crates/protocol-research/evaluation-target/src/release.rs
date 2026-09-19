use crate::certification::VerifiedTargetCertificate;
use linked_release_proof::{
    parameters::{HEADER_BYTES, SYSTEMATIC},
    statement::{self, PublicStatement},
};
use num_bigint::{BigInt, Sign};
use setup_aggregate::VerifiedAggregatePolynomial;
use std::sync::Arc;

pub const RELEASE_PROOF_ROLE: &[u8] = b"sealed-lattice/certified-release/v1";
#[derive(Debug)]
pub enum Error {
    Context,
    NoResult,
    Encoding,
    Proof,
    Signature,
    Incomplete,
}

pub(crate) fn decode_polynomial(
    bytes: &[u8],
    width: usize,
    modulus: &BigInt,
) -> Result<Vec<BigInt>, Error> {
    if bytes.len() != SYSTEMATIC * width {
        return Err(Error::Encoding);
    }
    let half = modulus >> 1usize;
    bytes
        .chunks_exact(width)
        .map(|coefficient| {
            let magnitude = BigInt::from_bytes_le(Sign::Plus, &coefficient[1..]);
            if coefficient[0] > 1
                || magnitude > half
                || (coefficient[0] == 1 && magnitude == BigInt::from(0))
            {
                return Err(Error::Encoding);
            }
            Ok(if coefficient[0] == 1 {
                -magnitude
            } else {
                magnitude
            })
        })
        .collect()
}

/// Public operands and original participant position for one certified target.
/// Neither an uncertified body nor a caller-selected ciphertext enters here.
pub struct ReleaseContext {
    certificate: Arc<VerifiedTargetCertificate>,
    position: usize,
    header: [u8; HEADER_BYTES],
    constant: VerifiedAggregatePolynomial,
    linear: VerifiedAggregatePolynomial,
    target_linear: Vec<BigInt>,
    public_key: Vec<BigInt>,
}
impl ReleaseContext {
    pub fn new(
        certificate: Arc<VerifiedTargetCertificate>,
        position: usize,
        constant: VerifiedAggregatePolynomial,
        linear: VerifiedAggregatePolynomial,
    ) -> Result<Self, Error> {
        let target = certificate.target();
        let inventory = target.inventory();
        let setup = inventory.setup();
        let ciphertext = target.ciphertext().ok_or(Error::NoResult)?;
        let records = setup.inventory().proposal().proposal().records();
        if records.len() != 10
            || position >= records.len()
            || constant.inventory() != &setup.inventory().identity()
            || linear.inventory() != &setup.inventory().identity()
            || constant.index() != 44 + 3 * position
            || linear.index() != 45 + 3 * position
            || ciphertext.len() != 2 * SYSTEMATIC * 25
        {
            return Err(Error::Context);
        }
        let public_key = decode_polynomial(
            records[position].public_key(),
            21,
            &statement::share_modulus(),
        )?;
        let target_linear = decode_polynomial(
            &ciphertext[SYSTEMATIC * 25..],
            25,
            &statement::release_modulus(),
        )?;
        let mut header = [0; HEADER_BYTES];
        header[..4].copy_from_slice(b"LRS1");
        header[4..68].copy_from_slice(&inventory.poll().identity());
        header[68..132].copy_from_slice(&setup.inventory().identity());
        header[132..196].copy_from_slice(target.identity());
        header[196..].copy_from_slice(&(position as u16).to_le_bytes());
        Ok(Self {
            certificate,
            position,
            header,
            constant,
            linear,
            target_linear,
            public_key,
        })
    }
    pub fn header(&self) -> &[u8; HEADER_BYTES] {
        &self.header
    }
    pub fn position(&self) -> usize {
        self.position
    }
    pub fn certificate(&self) -> &Arc<VerifiedTargetCertificate> {
        &self.certificate
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
    pub fn statement(&self, partial: &[u8]) -> Result<PublicStatement, Error> {
        // The parser checks the actual partial, not a producer's range claim.
        decode_polynomial(partial, 25, &statement::release_modulus())?;
        let common =
            setup_witness::contribution::common_polynomial(42).map_err(|_| Error::Context)?;
        let mut polynomials = [
            common.as_slice(),
            self.public_key(),
            self.encrypted_constant(),
            self.encrypted_linear(),
            self.target_linear(),
        ]
        .into_iter()
        .enumerate()
        .map(|(index, values)| {
            statement::encode_polynomial(values, if index < 4 { 21 } else { 25 })
                .map_err(|_| Error::Encoding)
        })
        .collect::<Result<Vec<_>, _>>()?;
        polynomials.push(partial.to_vec());
        Ok(PublicStatement {
            header: self.header.to_vec(),
            polynomials,
        })
    }
}
