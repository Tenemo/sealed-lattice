//! The published key sum is provisional until all compact offers, every
//! streamed polynomial and every aggregate-bound evaluation proof verify.
use crate::{
    CHUNK_BYTES,
    limb_sum::{self, LimbSumCodec},
    offer_verifier::VerifiedCommittedOffer,
    verified::{AggregatePolynomial, StreamedAggregate, VerifiedSelectionInputs},
};
use protocol_foundations::{
    Credential, RETAINED_TAG_BYTES,
    identity::{IdentityHasher, PUBLIC_POLYNOMIAL_DOMAIN, identity},
    poll::VerifiedPoll,
    setup_selection::AuthenticatedSelectionProposal,
};
use statement_stream::proof_field::{add, multiply, multiply_extension};
use std::sync::Arc;
use supported_profile::{DEGREE, Profile, relation::maximum_evaluation_proof_bytes};
use word_verifier::public_evaluation::{self, EvaluationVerifier};

type Element = [u128; 3];
const ZERO: Element = [0; 3];
const DATA_LABEL: &[u8] = b"sealed-lattice/aggregate-data";
pub(crate) const LIMB_SUM_DOMAIN: &str = "sealed-lattice/setup-limb-sum";

#[derive(Debug)]
pub enum Refusal {
    Shape,
    Order,
    Context,
    Encoding,
    Digest,
    Proof,
    Incomplete,
}

pub fn manifest_bytes(profile: Profile) -> usize {
    1 + 64 * profile.committed_polynomials().len()
}
pub fn retained_data_bytes(profile: Profile) -> usize {
    64 + 48 + 64 * profile.committed_polynomials().len() + RETAINED_TAG_BYTES
}

pub struct AggregateManifest {
    profile: Profile,
    width: usize,
    digests: Vec<[u8; 64]>,
    identity: [u8; 64],
}
impl AggregateManifest {
    pub fn decode(
        selection: &AuthenticatedSelectionProposal,
        bytes: &[u8],
    ) -> Result<Self, Refusal> {
        let profile = selection.roster().proposal().profile();
        if bytes.len() != manifest_bytes(profile) {
            return Err(Refusal::Shape);
        }
        let width = usize::from(bytes[0]);
        LimbSumCodec::new(profile, width).map_err(|_| Refusal::Encoding)?;
        let mut identity_bytes = selection.selection().identity().to_vec();
        identity_bytes.extend(bytes);
        Ok(Self {
            profile,
            width,
            digests: bytes[1..]
                .chunks_exact(64)
                .map(|digest| digest.try_into().unwrap())
                .collect(),
            identity: identity("sealed-lattice/published-aggregate", &identity_bytes)
                .map_err(|_| Refusal::Shape)?,
        })
    }
    pub fn identity(&self) -> &[u8; 64] {
        &self.identity
    }
    pub fn limb_bytes(&self) -> usize {
        self.width
    }
    pub fn polynomial_bytes(&self) -> usize {
        DEGREE * self.profile.fhe_limbs() * self.width
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = vec![self.width as u8];
        for digest in &self.digests {
            bytes.extend(digest);
        }
        bytes
    }
}

pub fn evaluation_role(selection: &AuthenticatedSelectionProposal) -> Vec<u8> {
    let mut role = b"sealed-lattice/setup-aggregate".to_vec();
    role.extend(selection.selection().identity());
    role
}

struct Polynomial {
    raw: IdentityHasher,
    normalized: IdentityHasher,
    offset: usize,
    coefficient: usize,
    record: Vec<u8>,
    power: Element,
}

pub struct PublishedAggregateVerifier {
    selection: Arc<AuthenticatedSelectionProposal>,
    offers: Vec<Arc<VerifiedCommittedOffer>>,
    manifest: AggregateManifest,
    codec: LimbSumCodec,
    indices: Vec<usize>,
    ordinal: usize,
    polynomial: Option<Polynomial>,
    polynomials: Vec<AggregatePolynomial>,
    role: Vec<u8>,
    roots: Vec<[u8; 64]>,
    point: Element,
    weights: Vec<Element>,
    expected: Element,
    claims: Element,
    evaluated: usize,
    evaluation: Option<EvaluationVerifier>,
    proof_bytes: usize,
    failed: bool,
}

impl PublishedAggregateVerifier {
    pub fn check_cache(&self, inputs: &VerifiedSelectionInputs) -> Result<(), Refusal> {
        if self.failed
            || self.ordinal != self.indices.len()
            || self.polynomial.is_some()
            || inputs.identity() != self.selection.selection().identity()
        {
            return Err(Refusal::Incomplete);
        }
        if self.polynomials.len() != inputs.polynomials().len()
            || self
                .polynomials
                .iter()
                .any(|polynomial| !inputs.polynomials().contains(polynomial))
        {
            return Err(Refusal::Digest);
        }
        Ok(())
    }
    pub fn retain_data(
        &self,
        credential: &Credential,
        poll: &VerifiedPoll,
    ) -> Result<Vec<u8>, Refusal> {
        if self.failed
            || self.ordinal != self.indices.len()
            || self.polynomial.is_some()
            || self.selection.roster().proposal().records()[0]
                .header()
                .poll
                != poll.identity()
        {
            return Err(Refusal::Incomplete);
        }
        let mut bytes = self.manifest.identity.to_vec();
        for value in self.expected {
            bytes.extend(value.to_le_bytes());
        }
        for index in &self.indices {
            bytes.extend(
                self.polynomials
                    .iter()
                    .find(|polynomial| polynomial.index == *index)
                    .ok_or(Refusal::Incomplete)?
                    .digest,
            );
        }
        let tag = credential.retained_tag(DATA_LABEL, poll, &bytes);
        bytes.extend(tag);
        Ok(bytes)
    }

    pub fn restore_data(
        &mut self,
        credential: &Credential,
        poll: &VerifiedPoll,
        bytes: &[u8],
    ) -> Result<(), Refusal> {
        if self.failed
            || self.ordinal != 0
            || self.polynomial.is_some()
            || self.evaluation.is_some()
            || self.evaluated != 0
            || bytes.len() != retained_data_bytes(self.manifest.profile)
            || bytes[..64] != self.manifest.identity
            || self.selection.roster().proposal().records()[0]
                .header()
                .poll
                != poll.identity()
        {
            return Err(Refusal::Context);
        }
        let end = bytes.len() - RETAINED_TAG_BYTES;
        credential
            .check_retained_tag(DATA_LABEL, poll, &bytes[..end], &bytes[end..])
            .map_err(|_| Refusal::Context)?;
        let expected: Element = std::array::from_fn(|index| {
            u128::from_le_bytes(bytes[64 + index * 16..80 + index * 16].try_into().unwrap())
        });
        if expected
            .iter()
            .any(|value| *value >= statement_stream::proof_field::MODULUS)
        {
            return Err(Refusal::Encoding);
        }
        for (index, digest) in self.indices.iter().zip(bytes[112..end].chunks_exact(64)) {
            self.polynomials.push(AggregatePolynomial {
                index: *index,
                bytes: self
                    .manifest
                    .profile
                    .setup_polynomial_bytes(*index)
                    .ok_or(Refusal::Shape)?,
                digest: digest.try_into().unwrap(),
            });
        }
        self.expected = expected;
        self.ordinal = self.indices.len();
        Ok(())
    }
    pub fn new(streamed: StreamedAggregate, manifest: &[u8]) -> Result<Self, Refusal> {
        let selection = streamed.selection;
        let profile = selection.roster().proposal().profile();
        let manifest = AggregateManifest::decode(&selection, manifest)?;
        let offers: Vec<_> = selection
            .selection()
            .selected()
            .iter()
            .map(|(position, identity)| {
                streamed
                    .offers
                    .iter()
                    .find(|offer| {
                        offer.envelope().position() == *position
                            && offer.envelope().body_identity() == identity
                    })
                    .cloned()
                    .ok_or(Refusal::Context)
            })
            .collect::<Result<_, _>>()?;
        let roots: Vec<_> = offers.iter().map(|offer| *offer.public_root()).collect();
        let role = evaluation_role(&selection);
        let (point, weights) =
            public_evaluation::aggregate_challenges(profile, &role, manifest.identity(), &roots)
                .map_err(|_| Refusal::Context)?;
        let codec = LimbSumCodec::new(profile, manifest.width).map_err(|_| Refusal::Shape)?;
        Ok(Self {
            selection,
            offers,
            manifest,
            codec,
            indices: profile.committed_polynomials(),
            ordinal: 0,
            polynomial: None,
            polynomials: streamed.polynomials,
            role,
            roots,
            point,
            weights,
            expected: ZERO,
            claims: ZERO,
            evaluated: 0,
            evaluation: None,
            proof_bytes: 0,
            failed: false,
        })
    }

    pub fn manifest(&self) -> &AggregateManifest {
        &self.manifest
    }

    /// Returns normalized records for the existing public aggregate cache.
    /// They grant no authority while the final evaluation check is pending.
    pub fn polynomial(
        &mut self,
        index: usize,
        offset: usize,
        bytes: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<(), Refusal> {
        output.clear();
        if self.failed {
            return Err(Refusal::Order);
        }
        let result = self.consume_polynomial(index, offset, bytes, output);
        if result.is_err() {
            self.failed = true;
            output.clear();
        }
        result
    }

    fn consume_polynomial(
        &mut self,
        index: usize,
        offset: usize,
        mut bytes: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<(), Refusal> {
        if self.indices.get(self.ordinal) != Some(&index)
            || bytes.is_empty()
            || bytes.len() > CHUNK_BYTES
        {
            return Err(Refusal::Order);
        }
        let length = self.manifest.polynomial_bytes();
        let normalized_length = DEGREE * self.codec.centered_record_bytes();
        if self.polynomial.is_none() {
            if offset != 0 {
                return Err(Refusal::Order);
            }
            self.polynomial = Some(Polynomial {
                raw: IdentityHasher::new(LIMB_SUM_DOMAIN, &[], length)
                    .map_err(|_| Refusal::Shape)?,
                normalized: IdentityHasher::new(PUBLIC_POLYNOMIAL_DOMAIN, &[], normalized_length)
                    .map_err(|_| Refusal::Shape)?,
                offset: 0,
                coefficient: 0,
                record: Vec::with_capacity(self.codec.record_bytes()),
                power: [1, 0, 0],
            });
        }
        let polynomial = self.polynomial.as_mut().ok_or(Refusal::Order)?;
        if offset != polynomial.offset || bytes.len() > length.saturating_sub(offset) {
            return Err(Refusal::Order);
        }
        polynomial.raw.absorb(bytes).map_err(|_| Refusal::Shape)?;
        polynomial.offset += bytes.len();
        let limbs = self.manifest.profile.fhe_limbs();
        let weights = &self.weights[self.ordinal * limbs..(self.ordinal + 1) * limbs];
        let mut decoded = vec![0; limbs];
        while !bytes.is_empty() {
            let count = bytes
                .len()
                .min(self.codec.record_bytes() - polynomial.record.len());
            polynomial.record.extend_from_slice(&bytes[..count]);
            bytes = &bytes[count..];
            if polynomial.record.len() != self.codec.record_bytes() {
                continue;
            }
            self.codec
                .decode(&polynomial.record, &mut decoded)
                .map_err(|_| Refusal::Encoding)?;
            let mut combined = ZERO;
            for (limb, weight) in decoded.iter().zip(weights) {
                let value = limb_sum::field_value(*limb);
                for coordinate in 0..3 {
                    combined[coordinate] =
                        add(combined[coordinate], multiply(weight[coordinate], value));
                }
            }
            let value = multiply_extension(combined, polynomial.power);
            for (expected, value) in self.expected.iter_mut().zip(value) {
                *expected = add(*expected, value);
            }
            polynomial.power = multiply_extension(polynomial.power, self.point);
            let start = output.len();
            output.resize(start + self.codec.centered_record_bytes(), 0);
            self.codec
                .normalize(&decoded, &mut output[start..])
                .map_err(|_| Refusal::Encoding)?;
            polynomial.coefficient += 1;
            polynomial.record.clear();
        }
        polynomial
            .normalized
            .absorb(output)
            .map_err(|_| Refusal::Shape)?;
        if polynomial.offset == length {
            let polynomial = self.polynomial.take().ok_or(Refusal::Order)?;
            if polynomial.coefficient != DEGREE || !polynomial.record.is_empty() {
                return Err(Refusal::Shape);
            }
            if polynomial.raw.finish().map_err(|_| Refusal::Shape)?
                != self.manifest.digests[self.ordinal]
            {
                return Err(Refusal::Digest);
            }
            self.polynomials.push(AggregatePolynomial {
                index,
                bytes: normalized_length,
                digest: polynomial.normalized.finish().map_err(|_| Refusal::Shape)?,
            });
            self.ordinal += 1;
        }
        Ok(())
    }

    pub fn begin_evaluation(&mut self, ordinal: usize, header: &[u8]) -> Result<(), Refusal> {
        if self.failed
            || self.ordinal != self.indices.len()
            || self.polynomial.is_some()
            || ordinal != self.evaluated
        {
            return Err(Refusal::Order);
        }
        self.evaluation = None;
        let offer = self.offers.get(ordinal).ok_or(Refusal::Order)?;
        let profile = self.manifest.profile;
        let role = offer
            .roster()
            .proposal()
            .contribution_role(offer.envelope().position())
            .map_err(|_| Refusal::Context)?;
        self.evaluation = Some(
            EvaluationVerifier::open(
                profile,
                &self.role,
                self.manifest.identity(),
                &self.roots,
                ordinal,
                &role,
                header,
            )
            .map_err(|_| Refusal::Proof)?,
        );
        self.proof_bytes = header.len();
        Ok(())
    }

    pub fn proof(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        if self.failed {
            return Err(Refusal::Order);
        }
        if bytes.len()
            > maximum_evaluation_proof_bytes(self.manifest.profile).saturating_sub(self.proof_bytes)
        {
            self.evaluation = None;
            return Err(Refusal::Shape);
        }
        let evaluation = self.evaluation.as_mut().ok_or(Refusal::Order)?;
        self.proof_bytes += bytes.len();
        if evaluation.push(bytes).is_err() {
            return Err(Refusal::Proof);
        }
        Ok(())
    }

    pub fn finish_evaluation(&mut self) -> Result<(), Refusal> {
        if self.failed {
            return Err(Refusal::Order);
        }
        let value = self
            .evaluation
            .take()
            .and_then(EvaluationVerifier::finish)
            .ok_or(Refusal::Proof)?;
        for (claim, value) in self.claims.iter_mut().zip(value) {
            *claim = add(*claim, value);
        }
        self.evaluated += 1;
        Ok(())
    }

    pub fn finish(mut self) -> Result<VerifiedSelectionInputs, Refusal> {
        if self.failed
            || self.ordinal != self.indices.len()
            || self.polynomial.is_some()
            || self.evaluation.is_some()
            || self.evaluated != self.offers.len()
            || self.claims != self.expected
        {
            return Err(Refusal::Incomplete);
        }
        self.polynomials.sort_by_key(|polynomial| polynomial.index);
        Ok(VerifiedSelectionInputs {
            selection: self.selection,
            polynomials: self.polynomials,
        })
    }
}
