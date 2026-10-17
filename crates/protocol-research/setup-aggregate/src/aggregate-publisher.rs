//! Accumulates complete verified offers in discovery order. Addition is
//! independent of that order; sealing checks the exact sorted selected set.
use crate::{
    CHUNK_BYTES, PolynomialAdder,
    limb_sum::{LimbSumCodec, generated_limb_bytes},
    offer_verifier::{
        COLLECTION_LABEL, VerifiedContributionOffer, collected_offer_bytes, restore_collection,
    },
    published_aggregate::{AggregateManifest, LIMB_SUM_DOMAIN},
    verified::{AggregatePolynomial, StreamedAggregate, build_selection},
};
use protocol_foundations::{
    Credential, RETAINED_TAG_BYTES,
    identity::{IdentityHasher, PUBLIC_POLYNOMIAL_DOMAIN},
    poll::VerifiedPoll,
    roster_authentication::AuthenticatedRosterProposal,
    setup_selection::AuthenticatedSelectionProposal,
};
use std::sync::Arc;
use supported_profile::Profile;

#[derive(Debug)]
pub enum Refusal {
    Context,
    Order,
    Shape,
    Digest,
    Incomplete,
}

pub fn maximum_collected_reference_bytes(profile: Profile) -> usize {
    2 + profile.setup_contributors() * collected_offer_bytes(profile)
        + 64 * profile.contribution_body_polynomials().len()
        + RETAINED_TAG_BYTES
}

struct Polynomial {
    incoming: IdentityHasher,
    previous: Option<IdentityHasher>,
    output: IdentityHasher,
    offset: usize,
}

struct Incoming {
    offer: Arc<VerifiedContributionOffer>,
    ordinal: usize,
    polynomial: Option<Polynomial>,
    outputs: Vec<AggregatePolynomial>,
}

pub struct AggregatePublisher {
    roster: Arc<AuthenticatedRosterProposal>,
    profile: Profile,
    indices: Vec<usize>,
    committed: Vec<usize>,
    codec: LimbSumCodec,
    offers: Vec<Arc<VerifiedContributionOffer>>,
    sums: Vec<AggregatePolynomial>,
    incoming: Option<Incoming>,
    failed: bool,
}

impl AggregatePublisher {
    pub fn new(roster: Arc<AuthenticatedRosterProposal>) -> Self {
        let profile = roster.proposal().profile();
        Self {
            roster,
            profile,
            indices: profile.contribution_body_polynomials(),
            committed: profile.committed_polynomials(),
            codec: LimbSumCodec::new(profile, generated_limb_bytes(profile))
                .expect("Generated limb sums fit their profile"),
            offers: Vec::new(),
            sums: Vec::new(),
            incoming: None,
            failed: false,
        }
    }

    pub fn accepted(&self) -> usize {
        self.offers.len()
    }
    pub fn offers(&self) -> &[Arc<VerifiedContributionOffer>] {
        &self.offers
    }

    pub fn retain(&self, credential: &Credential, poll: &VerifiedPoll) -> Result<Vec<u8>, Refusal> {
        if self.failed
            || self.incoming.is_some()
            || self.offers.is_empty()
            || self.roster.proposal().records()[0].header().poll != poll.identity()
        {
            return Err(Refusal::Context);
        }
        let mut bytes = (self.offers.len() as u16).to_le_bytes().to_vec();
        for offer in &self.offers {
            bytes.extend(offer.envelope().bytes());
            bytes.extend(offer.authenticated().signature());
            bytes.extend(offer.public_root());
            for polynomial in offer.polynomials() {
                bytes.extend(polynomial.digest());
            }
        }
        for polynomial in &self.sums {
            bytes.extend(polynomial.digest);
        }
        let tag = credential.retained_tag(COLLECTION_LABEL, poll, &bytes);
        bytes.extend(tag);
        Ok(bytes)
    }

    pub fn restore(
        credential: &Credential,
        poll: &VerifiedPoll,
        roster: Arc<AuthenticatedRosterProposal>,
        bytes: &[u8],
    ) -> Result<Self, Refusal> {
        let retained = restore_collection(credential, poll, roster.clone(), bytes)
            .map_err(|_| Refusal::Context)?;
        let mut restored = Self::new(roster);
        restored.offers = retained.offers;
        restored.sums = restored
            .indices
            .iter()
            .zip(retained.sum_digests)
            .map(|(index, digest)| AggregatePolynomial {
                index: *index,
                bytes: if restored.committed.contains(index) {
                    supported_profile::DEGREE * restored.codec.record_bytes()
                } else {
                    restored.profile.setup_polynomial_bytes(*index).unwrap()
                },
                digest,
            })
            .collect();
        Ok(restored)
    }

    pub fn begin(&mut self, offer: Arc<VerifiedContributionOffer>) -> Result<(), Refusal> {
        if self.failed
            || self.incoming.is_some()
            || self.offers.len() == self.profile.setup_contributors()
        {
            return Err(Refusal::Order);
        }
        if offer.roster().proposal().identity() != self.roster.proposal().identity()
            || self
                .offers
                .iter()
                .any(|known| known.envelope().position() == offer.envelope().position())
        {
            return Err(Refusal::Context);
        }
        self.incoming = Some(Incoming {
            offer,
            ordinal: 0,
            polynomial: None,
            outputs: Vec::new(),
        });
        Ok(())
    }

    /// The required previous-sum buffer for this many source bytes.
    pub fn output_bytes(&self, index: usize, incoming_bytes: usize) -> Result<usize, Refusal> {
        let family = self.profile.setup_family(index).ok_or(Refusal::Shape)?;
        let width = 1 + self.profile.family_magnitude_bytes(family);
        if incoming_bytes == 0
            || incoming_bytes > CHUNK_BYTES
            || !incoming_bytes.is_multiple_of(width)
        {
            return Err(Refusal::Shape);
        }
        Ok(if self.committed.contains(&index) {
            incoming_bytes / width * self.codec.record_bytes()
        } else {
            incoming_bytes
        })
    }

    pub fn polynomial(
        &mut self,
        index: usize,
        offset: usize,
        bytes: &[u8],
        previous_and_output: &mut [u8],
    ) -> Result<(), Refusal> {
        if self.failed {
            return Err(Refusal::Order);
        }
        let result = self.consume_polynomial(index, offset, bytes, previous_and_output);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn consume_polynomial(
        &mut self,
        index: usize,
        offset: usize,
        bytes: &[u8],
        previous_and_output: &mut [u8],
    ) -> Result<(), Refusal> {
        if previous_and_output.len() != self.output_bytes(index, bytes.len())? {
            return Err(Refusal::Shape);
        }
        let incoming = self.incoming.as_mut().ok_or(Refusal::Order)?;
        if self.indices.get(incoming.ordinal) != Some(&index) {
            return Err(Refusal::Order);
        }
        let source_bytes = self
            .profile
            .setup_polynomial_bytes(index)
            .ok_or(Refusal::Shape)?;
        let committed = self.committed.contains(&index);
        let output_bytes = if committed {
            supported_profile::DEGREE * self.codec.record_bytes()
        } else {
            source_bytes
        };
        let domain = if committed {
            LIMB_SUM_DOMAIN
        } else {
            PUBLIC_POLYNOMIAL_DOMAIN
        };
        if incoming.polynomial.is_none() {
            if offset != 0 {
                return Err(Refusal::Order);
            }
            incoming.polynomial = Some(Polynomial {
                incoming: IdentityHasher::new(PUBLIC_POLYNOMIAL_DOMAIN, &[], source_bytes)
                    .map_err(|_| Refusal::Shape)?,
                previous: if self.offers.is_empty() {
                    None
                } else {
                    Some(
                        IdentityHasher::new(domain, &[], output_bytes)
                            .map_err(|_| Refusal::Shape)?,
                    )
                },
                output: IdentityHasher::new(domain, &[], output_bytes)
                    .map_err(|_| Refusal::Shape)?,
                offset: 0,
            });
        }
        let polynomial = incoming.polynomial.as_mut().ok_or(Refusal::Order)?;
        if offset != polynomial.offset || bytes.len() > source_bytes.saturating_sub(offset) {
            return Err(Refusal::Order);
        }
        polynomial
            .incoming
            .absorb(bytes)
            .map_err(|_| Refusal::Shape)?;
        if let Some(hash) = &mut polynomial.previous {
            hash.absorb(previous_and_output)
                .map_err(|_| Refusal::Shape)?;
        } else {
            previous_and_output.fill(0);
        }
        if committed {
            self.codec
                .add_records(bytes, previous_and_output)
                .map_err(|_| Refusal::Shape)?;
        } else {
            PolynomialAdder::new(
                self.profile,
                self.profile.setup_family(index).ok_or(Refusal::Shape)?,
            )
            .add_into(bytes, previous_and_output)
            .map_err(|_| Refusal::Shape)?;
        }
        polynomial
            .output
            .absorb(previous_and_output)
            .map_err(|_| Refusal::Shape)?;
        polynomial.offset += bytes.len();
        if polynomial.offset == source_bytes {
            let polynomial = incoming.polynomial.take().ok_or(Refusal::Order)?;
            let expected = incoming
                .offer
                .polynomials()
                .get(incoming.ordinal)
                .ok_or(Refusal::Order)?;
            if expected.index() != index
                || expected.bytes() != source_bytes
                || polynomial.incoming.finish().map_err(|_| Refusal::Shape)? != *expected.digest()
            {
                return Err(Refusal::Digest);
            }
            if let Some(previous) = polynomial.previous {
                let expected = self.sums.get(incoming.ordinal).ok_or(Refusal::Order)?;
                if expected.index() != index
                    || expected.bytes() != output_bytes
                    || previous.finish().map_err(|_| Refusal::Shape)? != *expected.digest()
                {
                    return Err(Refusal::Digest);
                }
            }
            incoming.outputs.push(AggregatePolynomial {
                index,
                bytes: output_bytes,
                digest: polynomial.output.finish().map_err(|_| Refusal::Shape)?,
            });
            incoming.ordinal += 1;
        }
        Ok(())
    }

    pub fn finish_offer(&mut self) -> Result<(), Refusal> {
        if self.failed {
            return Err(Refusal::Order);
        }
        let incoming = self.incoming.take().ok_or(Refusal::Order)?;
        if incoming.ordinal != self.indices.len() || incoming.polynomial.is_some() {
            self.failed = true;
            return Err(Refusal::Incomplete);
        }
        self.sums = incoming.outputs;
        self.offers.push(incoming.offer);
        Ok(())
    }

    pub fn finish(
        mut self,
        selection: Arc<AuthenticatedSelectionProposal>,
    ) -> Result<(AggregateManifest, StreamedAggregate), Refusal> {
        if self.failed
            || self.incoming.is_some()
            || self.offers.len() != self.profile.setup_contributors()
        {
            return Err(Refusal::Incomplete);
        }
        self.offers.sort_by_key(|offer| offer.envelope().position());
        let expected = build_selection(&self.roster, &self.offers).map_err(|_| Refusal::Context)?;
        if expected.body() != selection.selection().body() {
            return Err(Refusal::Context);
        }
        let mut encoded = vec![generated_limb_bytes(self.profile) as u8];
        for polynomial in &self.sums {
            if self.committed.contains(&polynomial.index) {
                encoded.extend(polynomial.digest);
            }
        }
        let manifest =
            AggregateManifest::decode(&selection, &encoded).map_err(|_| Refusal::Shape)?;
        let streamed = StreamedAggregate {
            selection,
            polynomials: self
                .sums
                .into_iter()
                .filter(|polynomial| !self.committed.contains(&polynomial.index))
                .collect(),
            offers: self
                .offers
                .iter()
                .map(|offer| Arc::new(offer.committed()))
                .collect(),
        };
        Ok((manifest, streamed))
    }
}
