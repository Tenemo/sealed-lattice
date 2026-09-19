use crate::{CHUNK_BYTES, ModulusKind, PolynomialAdder};
use opened_contribution::OpenedContributionVerifier;
use registration_credentials::contribution_authentication::CommitmentInventory;
use sha2::{Digest, Sha512};
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct AggregatePolynomial {
    pub(crate) index: usize,
    pub(crate) bytes: usize,
    pub(crate) digest: [u8; 64],
}
impl AggregatePolynomial {
    pub fn index(&self) -> usize {
        self.index
    }
    pub fn bytes(&self) -> usize {
        self.bytes
    }
    pub fn digest(&self) -> &[u8; 64] {
        &self.digest
    }
}

pub struct VerifiedSetupAggregate {
    inventory: Arc<CommitmentInventory>,
    polynomials: Vec<AggregatePolynomial>,
}
impl VerifiedSetupAggregate {
    pub fn inventory(&self) -> &Arc<CommitmentInventory> {
        &self.inventory
    }
    pub fn polynomials(&self) -> &[AggregatePolynomial] {
        &self.polynomials
    }
    pub fn read_polynomial(
        &self,
        index: usize,
    ) -> Result<crate::AggregatePolynomialReader, Refusal> {
        let polynomial = self
            .polynomials
            .iter()
            .find(|polynomial| polynomial.index == index)
            .ok_or(Refusal::Order)?;
        crate::AggregatePolynomialReader::new(self.inventory.identity(), polynomial.clone())
    }
}

#[derive(Debug)]
pub enum Refusal {
    Context,
    Order,
    Body,
    PreviousAggregate,
    Proof,
    Incomplete,
}

struct Pending {
    verifier: OpenedContributionVerifier,
    ordinal: usize,
    offset: usize,
    previous_hash: Sha512,
    output_hash: Sha512,
    outputs: Vec<AggregatePolynomial>,
    failed: bool,
}

/// Only a completed, positively verified opening advances the accepted prefix.
/// Output chunks are provisional until `finish_contribution` succeeds.
pub struct SetupAggregator {
    inventory: Arc<CommitmentInventory>,
    accepted: usize,
    indices: Vec<usize>,
    previous: Vec<AggregatePolynomial>,
    pending: Option<Pending>,
}
impl SetupAggregator {
    pub fn new(inventory: Arc<CommitmentInventory>) -> Result<Self, Refusal> {
        if inventory.confirmations().len() != 10 {
            return Err(Refusal::Context);
        }
        Ok(Self {
            inventory,
            accepted: 0,
            indices: (0..75)
                .filter(|index| ModulusKind::for_contribution_polynomial(*index).is_some())
                .collect(),
            previous: Vec::new(),
            pending: None,
        })
    }
    pub fn accepted(&self) -> usize {
        self.accepted
    }
    pub fn polynomials(&self) -> &[AggregatePolynomial] {
        &self.previous
    }
    pub fn begin(
        &mut self,
        opening_body: &[u8],
        signature: &[u8],
        body_header: &[u8],
        proof_header: &[u8],
    ) -> Result<(), Refusal> {
        if self.accepted >= self.inventory.confirmations().len() {
            return Err(Refusal::Order);
        }
        let verifier = OpenedContributionVerifier::new(
            self.inventory.clone(),
            opening_body,
            signature,
            body_header,
            proof_header,
        )
        .map_err(|_| Refusal::Context)?;
        self.pending = Some(Pending {
            verifier,
            ordinal: 0,
            offset: 0,
            previous_hash: Sha512::new(),
            output_hash: Sha512::new(),
            outputs: Vec::new(),
            failed: false,
        });
        Ok(())
    }
    pub fn polynomial(
        &mut self,
        index: usize,
        offset: usize,
        incoming: &[u8],
        previous_and_output: &mut [u8],
    ) -> Result<(), Refusal> {
        let pending = self.pending.as_mut().ok_or(Refusal::Order)?;
        if pending.failed {
            return Err(Refusal::Order);
        }
        let result = (|| {
            if incoming.is_empty()
                || incoming.len() > CHUNK_BYTES
                || incoming.len() != previous_and_output.len()
            {
                return Err(Refusal::Body);
            }
            if self.indices.get(pending.ordinal) != Some(&index) || pending.offset != offset {
                return Err(Refusal::Order);
            }
            let kind = ModulusKind::for_contribution_polynomial(index).ok_or(Refusal::Order)?;
            let bytes = kind.degree() * kind.coefficient_bytes();
            if incoming.len() > bytes.saturating_sub(offset) {
                return Err(Refusal::Order);
            }
            pending
                .verifier
                .polynomial(index, offset, incoming)
                .map_err(|_| Refusal::Body)?;
            if self.accepted == 0 {
                previous_and_output.fill(0);
            } else {
                pending.previous_hash.update(&*previous_and_output);
            }
            PolynomialAdder::new(kind)
                .add_into(incoming, previous_and_output)
                .map_err(|_| Refusal::Body)?;
            pending.output_hash.update(&*previous_and_output);
            pending.offset += incoming.len();
            if pending.offset == bytes {
                if self.accepted > 0 {
                    let expected = &self.previous[pending.ordinal];
                    let digest: [u8; 64] = pending.previous_hash.clone().finalize().into();
                    if expected.index != index
                        || expected.bytes != bytes
                        || expected.digest != digest
                    {
                        return Err(Refusal::PreviousAggregate);
                    }
                }
                pending.outputs.push(AggregatePolynomial {
                    index,
                    bytes,
                    digest: pending.output_hash.clone().finalize().into(),
                });
                pending.previous_hash = Sha512::new();
                pending.output_hash = Sha512::new();
                pending.ordinal += 1;
                pending.offset = 0;
            }
            Ok(())
        })();
        if result.is_err() {
            pending.failed = true;
        }
        result
    }
    pub fn proof(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Refusal> {
        let pending = self.pending.as_mut().ok_or(Refusal::Order)?;
        if pending.failed || pending.ordinal != self.indices.len() {
            return Err(Refusal::Order);
        }
        if pending.verifier.proof(offset, bytes).is_err() {
            pending.failed = true;
            return Err(Refusal::Proof);
        }
        Ok(())
    }
    pub fn finish_contribution(&mut self) -> Result<(), Refusal> {
        let pending = self.pending.take().ok_or(Refusal::Order)?;
        if pending.failed || pending.ordinal != self.indices.len() || pending.offset != 0 {
            return Err(Refusal::Incomplete);
        }
        let verified = pending.verifier.finish().map_err(|_| Refusal::Proof)?;
        if verified.position() != self.accepted
            || verified.inventory() != &self.inventory.identity()
        {
            return Err(Refusal::Context);
        }
        self.previous = pending.outputs;
        self.accepted += 1;
        Ok(())
    }
    pub fn finish(self) -> Result<VerifiedSetupAggregate, Refusal> {
        if self.pending.is_some() || self.accepted != self.inventory.confirmations().len() {
            return Err(Refusal::Incomplete);
        }
        Ok(VerifiedSetupAggregate {
            inventory: self.inventory,
            polynomials: self.previous,
        })
    }
}

#[cfg(test)]
mod retained_tests {
    use super::*;
    use num_bigint::{BigInt, Sign};

    fn source(index: usize) -> (AggregatePolynomial, Vec<u8>, Vec<BigInt>) {
        let kind = ModulusKind::for_contribution_polynomial(index).unwrap();
        let width = kind.coefficient_bytes();
        let half = BigInt::from_bytes_le(Sign::Plus, kind.magnitude_bytes()) >> 1usize;
        let values = vec![
            BigInt::from(0),
            BigInt::from(1),
            BigInt::from(-1),
            half.clone(),
            -half,
        ];
        let mut bytes = vec![0; kind.degree() * width];
        for (position, coefficient) in bytes.chunks_exact_mut(width).enumerate() {
            let (sign, magnitude) = values[position % values.len()].to_bytes_le();
            coefficient[0] = u8::from(sign == Sign::Minus);
            coefficient[1..1 + magnitude.len()].copy_from_slice(&magnitude);
        }
        let expected = AggregatePolynomial {
            index,
            bytes: bytes.len(),
            digest: Sha512::digest(&bytes).into(),
        };
        (expected, bytes, values)
    }
    #[test]
    fn retained_coefficients_match_both_boundaries_in_every_modulus() {
        for index in [1, 44, 74] {
            let (expected, bytes, values) = source(index);
            let kind = ModulusKind::for_contribution_polynomial(index).unwrap();
            let mut reader = crate::AggregatePolynomialReader::new([19; 64], expected).unwrap();
            let chunk = CHUNK_BYTES / kind.coefficient_bytes() * kind.coefficient_bytes();
            for (ordinal, bytes) in bytes.chunks(chunk).enumerate() {
                reader.push(ordinal * chunk, bytes).unwrap();
            }
            let key = reader.finish().unwrap();
            assert_eq!(key.inventory(), &[19; 64]);
            assert_eq!(key.index(), index);
            assert_eq!(key.coefficients().len(), kind.degree());
            for (position, coefficient) in key.coefficients().iter().enumerate() {
                assert_eq!(coefficient, &values[position % values.len()]);
            }
        }
    }
    #[test]
    fn changed_canonical_cache_and_incomplete_reads_supply_no_key() {
        let (expected, mut bytes, _) = source(74);
        let mut reader = crate::AggregatePolynomialReader::new([0; 64], expected.clone()).unwrap();
        reader.push(0, &bytes[..bytes.len() - 6]).unwrap();
        assert!(matches!(reader.finish(), Err(Refusal::Incomplete)));
        bytes[1] = 1;
        let mut reader = crate::AggregatePolynomialReader::new([0; 64], expected).unwrap();
        reader.push(0, &bytes).unwrap();
        assert!(matches!(reader.finish(), Err(Refusal::PreviousAggregate)));
    }
    #[test]
    fn malformed_reads_poison_only_the_pending_key() {
        let (expected, bytes, _) = source(74);
        let mut negative_zero = vec![0; 6];
        negative_zero[0] = 1;
        let mut unknown_sign = vec![0; 6];
        unknown_sign[0] = 2;
        for (offset, invalid) in [
            (6, vec![0; 6]),
            (0, vec![]),
            (0, vec![0; 5]),
            (0, vec![0; CHUNK_BYTES + 1]),
            (0, negative_zero),
            (0, unknown_sign),
        ] {
            let mut reader =
                crate::AggregatePolynomialReader::new([0; 64], expected.clone()).unwrap();
            assert!(reader.push(offset, &invalid).is_err());
            assert!(reader.push(0, &bytes).is_err());
            assert!(reader.finish().is_err());
        }
        let mut reader = crate::AggregatePolynomialReader::new([0; 64], expected.clone()).unwrap();
        reader.push(0, &bytes[..6]).unwrap();
        assert!(reader.push(0, &bytes[..6]).is_err());
        assert!(reader.finish().is_err());
        let mut reader = crate::AggregatePolynomialReader::new([0; 64], expected).unwrap();
        reader.push(0, &bytes).unwrap();
        assert!(reader.push(bytes.len(), &bytes[..6]).is_err());
        assert!(reader.finish().is_err());
    }
}
