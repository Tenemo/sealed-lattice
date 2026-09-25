use crate::{CHUNK_BYTES, PolynomialAdder};
use opened_contribution::OpenedContributionVerifier;
use registration_credentials::{
    contribution_authentication::CommitmentInventory,
    identity::{IdentityHasher, PUBLIC_POLYNOMIAL_DOMAIN},
};
use std::sync::Arc;
use supported_profile::Profile;

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
    pub fn profile(&self) -> Profile {
        self.inventory.proposal().proposal().profile()
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
        crate::AggregatePolynomialReader::new(
            self.profile(),
            self.inventory.identity(),
            polynomial.clone(),
        )
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
    // The identities of the polynomial in progress: the previous aggregate
    // read back from the host, and the new aggregate.
    previous_hash: Option<IdentityHasher>,
    output_hash: Option<IdentityHasher>,
    outputs: Vec<AggregatePolynomial>,
    failed: bool,
}

/// Only a completed, positively verified opening advances the accepted prefix.
/// Output chunks are provisional until `finish_contribution` succeeds.
pub struct SetupAggregator {
    inventory: Arc<CommitmentInventory>,
    profile: Profile,
    accepted: usize,
    indices: Vec<usize>,
    previous: Vec<AggregatePolynomial>,
    pending: Option<Pending>,
}
impl SetupAggregator {
    pub fn new(inventory: Arc<CommitmentInventory>) -> Result<Self, Refusal> {
        let profile = inventory.proposal().proposal().profile();
        if inventory.confirmations().len() != profile.participants() {
            return Err(Refusal::Context);
        }
        Ok(Self {
            inventory,
            profile,
            accepted: 0,
            indices: profile.contribution_body_polynomials(),
            previous: Vec::new(),
            pending: None,
        })
    }
    pub fn accepted(&self) -> usize {
        self.accepted
    }
    /// Every roster position's opening is accepted and none is pending.
    pub fn complete(&self) -> bool {
        self.pending.is_none() && self.accepted == self.inventory.confirmations().len()
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
            previous_hash: None,
            output_hash: None,
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
            let family = self.profile.setup_family(index).ok_or(Refusal::Order)?;
            let bytes = self
                .profile
                .setup_polynomial_bytes(index)
                .ok_or(Refusal::Order)?;
            if incoming.len() > bytes.saturating_sub(offset) {
                return Err(Refusal::Order);
            }
            pending
                .verifier
                .polynomial(index, offset, incoming)
                .map_err(|_| Refusal::Body)?;
            let identity = || {
                IdentityHasher::new(PUBLIC_POLYNOMIAL_DOMAIN, &[], bytes).map_err(|_| Refusal::Body)
            };
            if offset == 0 {
                pending.previous_hash = (self.accepted > 0).then(identity).transpose()?;
                pending.output_hash = Some(identity()?);
            }
            match pending.previous_hash.as_mut() {
                None => previous_and_output.fill(0),
                Some(hash) => hash
                    .absorb(previous_and_output)
                    .map_err(|_| Refusal::PreviousAggregate)?,
            }
            PolynomialAdder::new(self.profile, family)
                .add_into(incoming, previous_and_output)
                .map_err(|_| Refusal::Body)?;
            pending
                .output_hash
                .as_mut()
                .ok_or(Refusal::Order)?
                .absorb(previous_and_output)
                .map_err(|_| Refusal::Body)?;
            pending.offset += incoming.len();
            if pending.offset == bytes {
                if let Some(hash) = pending.previous_hash.take() {
                    let expected = &self.previous[pending.ordinal];
                    let digest = hash.finish().map_err(|_| Refusal::PreviousAggregate)?;
                    if expected.index != index
                        || expected.bytes != bytes
                        || expected.digest != digest
                    {
                        return Err(Refusal::PreviousAggregate);
                    }
                }
                let digest = pending
                    .output_hash
                    .take()
                    .ok_or(Refusal::Order)?
                    .finish()
                    .map_err(|_| Refusal::Body)?;
                pending.outputs.push(AggregatePolynomial {
                    index,
                    bytes,
                    digest,
                });
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
        if !self.complete() {
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

    fn source(profile: Profile, index: usize) -> (AggregatePolynomial, Vec<u8>, Vec<BigInt>) {
        let family = crate::contribution_family(profile, index).unwrap();
        let width = 1 + profile.family_magnitude_bytes(family);
        let half = BigInt::from_bytes_le(Sign::Plus, &profile.family_modulus(family)) >> 1usize;
        let values = vec![
            BigInt::from(0),
            BigInt::from(1),
            BigInt::from(-1),
            half.clone(),
            -half,
        ];
        let mut bytes = vec![0; profile.family_degree(family) * width];
        for (position, coefficient) in bytes.chunks_exact_mut(width).enumerate() {
            let (sign, magnitude) = values[position % values.len()].to_bytes_le();
            coefficient[0] = u8::from(sign == Sign::Minus);
            coefficient[1..1 + magnitude.len()].copy_from_slice(&magnitude);
        }
        let expected = AggregatePolynomial {
            index,
            bytes: bytes.len(),
            digest: registration_credentials::identity::identity(PUBLIC_POLYNOMIAL_DOMAIN, &bytes)
                .unwrap(),
        };
        (expected, bytes, values)
    }
    #[test]
    fn retained_coefficients_match_both_boundaries_in_every_modulus() {
        for (participants, options) in [(3, 2), (20, 20)] {
            let profile = Profile::new(participants, options).unwrap();
            for index in [
                profile.fhe_polynomial(profile.gadget_length() - 1, 6),
                profile.share_linear_polynomial(participants - 1),
                profile.auxiliary_key_polynomial(),
            ] {
                let (expected, bytes, values) = source(profile, index);
                let family = profile.setup_family(index).unwrap();
                let width = 1 + profile.family_magnitude_bytes(family);
                let mut reader =
                    crate::AggregatePolynomialReader::new(profile, [19; 64], expected).unwrap();
                let chunk = CHUNK_BYTES / width * width;
                for (ordinal, bytes) in bytes.chunks(chunk).enumerate() {
                    reader.push(ordinal * chunk, bytes).unwrap();
                }
                let key = reader.finish().unwrap();
                assert_eq!(key.inventory(), &[19; 64]);
                assert_eq!(key.index(), index);
                assert_eq!(key.coefficients().len(), profile.family_degree(family));
                for (position, coefficient) in key.coefficients().iter().enumerate() {
                    assert_eq!(coefficient, &values[position % values.len()]);
                }
            }
        }
    }
    #[test]
    fn readers_refuse_a_reference_of_another_profile_or_polynomial() {
        let small = Profile::new(3, 2).unwrap();
        let wide = Profile::new(20, 20).unwrap();
        let index = wide.fhe_polynomial(0, 1);
        let (expected, _, _) = source(wide, index);
        // The same key position has fewer ciphertext bytes in the smaller
        // profile, and a common polynomial is never an aggregate.
        assert!(crate::AggregatePolynomialReader::new(small, [0; 64], expected.clone()).is_err());
        let common = AggregatePolynomial {
            index: wide.fhe_polynomial(0, 0),
            ..expected
        };
        assert!(crate::AggregatePolynomialReader::new(wide, [0; 64], common).is_err());
    }
    #[test]
    fn changed_canonical_cache_and_incomplete_reads_supply_no_key() {
        let profile = Profile::new(3, 2).unwrap();
        let (expected, mut bytes, _) = source(profile, profile.auxiliary_key_polynomial());
        let mut reader =
            crate::AggregatePolynomialReader::new(profile, [0; 64], expected.clone()).unwrap();
        reader.push(0, &bytes[..bytes.len() - 6]).unwrap();
        assert!(matches!(reader.finish(), Err(Refusal::Incomplete)));
        bytes[1] = 1;
        let mut reader = crate::AggregatePolynomialReader::new(profile, [0; 64], expected).unwrap();
        reader.push(0, &bytes).unwrap();
        assert!(matches!(reader.finish(), Err(Refusal::PreviousAggregate)));
    }
    #[test]
    fn malformed_reads_poison_only_the_pending_key() {
        let profile = Profile::new(3, 2).unwrap();
        let (expected, bytes, _) = source(profile, profile.auxiliary_key_polynomial());
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
                crate::AggregatePolynomialReader::new(profile, [0; 64], expected.clone()).unwrap();
            assert!(reader.push(offset, &invalid).is_err());
            assert!(reader.push(0, &bytes).is_err());
            assert!(reader.finish().is_err());
        }
        let mut reader =
            crate::AggregatePolynomialReader::new(profile, [0; 64], expected.clone()).unwrap();
        reader.push(0, &bytes[..6]).unwrap();
        assert!(reader.push(0, &bytes[..6]).is_err());
        assert!(reader.finish().is_err());
        let mut reader = crate::AggregatePolynomialReader::new(profile, [0; 64], expected).unwrap();
        reader.push(0, &bytes).unwrap();
        assert!(reader.push(bytes.len(), &bytes[..6]).is_err());
        assert!(reader.finish().is_err());
    }
}
