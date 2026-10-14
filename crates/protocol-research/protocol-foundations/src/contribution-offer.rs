use crate::{
    Credential, Refusal, SIGNATURE_BYTES, contribution_body,
    foundation::{CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple},
    identity::identity,
    roster::{RetainedContributionContext, RosterProposal},
    roster_authentication::AuthenticatedRosterProposal,
};
use fips204::{
    ml_dsa_65,
    traits::{SerDes, Verifier},
};
use std::sync::Arc;
pub const OFFER_PURPOSE: &str = "sealed-lattice/contribution-offer";
pub(crate) const OFFER_IDENTITY_DOMAIN: &str = "sealed-lattice/contribution-offer-identity";
pub const MAXIMUM_OFFER_BYTES: usize = 1024;
pub fn offer_envelope_bytes() -> usize {
    let profile = supported_profile::Profile::new(
        *supported_profile::Profile::participant_range().start(),
        *supported_profile::Profile::option_range().start(),
    )
    .expect("Supported profile");
    OfferEnvelope::from_parts(
        profile,
        [0; 64],
        0,
        *contribution_body::body_lengths(profile).start(),
        [0; 64],
    )
    .expect("Canonical envelope")
    .bytes
    .len()
}

#[derive(Clone)]
pub struct OfferEnvelope {
    bytes: Vec<u8>,
    roster: [u8; 64],
    position: usize,
    body_length: usize,
    body_identity: [u8; 64],
}
impl OfferEnvelope {
    pub fn new(
        roster: &RosterProposal,
        position: usize,
        body_length: usize,
        body_identity: [u8; 64],
    ) -> Result<Self, Refusal> {
        Self::from_parts(
            roster.profile(),
            roster.identity(),
            position,
            body_length,
            body_identity,
        )
    }
    pub fn for_retained(
        context: &RetainedContributionContext,
        body_length: usize,
        body_identity: [u8; 64],
    ) -> Result<Self, Refusal> {
        Self::from_parts(
            context.profile(),
            *context.identity(),
            context.position(),
            body_length,
            body_identity,
        )
    }
    fn from_parts(
        profile: supported_profile::Profile,
        roster: [u8; 64],
        position: usize,
        body_length: usize,
        body_identity: [u8; 64],
    ) -> Result<Self, Refusal> {
        if position >= profile.setup_eligible_contributors()
            || !contribution_body::body_lengths(profile).contains(&body_length)
        {
            return Err(Refusal::Shape);
        }
        let bytes = CanonicalTuple::new(
            1,
            vec![
                CanonicalItem::nonempty_ascii(OFFER_PURPOSE).map_err(|_| Refusal::Shape)?,
                CanonicalItem::hash512(roster),
                CanonicalItem::unsigned16(position as u16),
                CanonicalItem::unsigned64(body_length as u64),
                CanonicalItem::hash512(body_identity),
            ],
        )
        .encode()
        .map_err(|_| Refusal::Shape)?;
        Ok(Self {
            bytes,
            roster,
            position,
            body_length,
            body_identity,
        })
    }
    pub fn decode(roster: &RosterProposal, bytes: &[u8]) -> Result<Self, Refusal> {
        let limits = CanonicalDecodeLimits {
            maximum_tuple_byte_length: MAXIMUM_OFFER_BYTES,
            maximum_item_count: 5,
            maximum_item_byte_length: MAXIMUM_OFFER_BYTES,
            maximum_nesting_depth: 0,
            ..CanonicalDecodeLimits::default()
        };
        let tuple = CanonicalTuple::decode(bytes, &limits).map_err(|_| Refusal::Shape)?;
        if !tuple.has_header(5) {
            return Err(Refusal::Shape);
        }
        let items = &tuple.items;
        let types = [
            CanonicalItemType::Ascii,
            CanonicalItemType::Hash512,
            CanonicalItemType::Unsigned16,
            CanonicalItemType::Unsigned64,
            CanonicalItemType::Hash512,
        ];
        if items
            .iter()
            .zip(types)
            .any(|(item, kind)| item.item_type() != kind)
            || items[0]
                .variable_value_bytes()
                .map_err(|_| Refusal::Shape)?
                != OFFER_PURPOSE.as_bytes()
            || items[1].canonical_bytes() != roster.identity()
        {
            return Err(Refusal::Context);
        }
        Self::new(
            roster,
            u16::from_le_bytes(
                items[2]
                    .canonical_bytes()
                    .try_into()
                    .map_err(|_| Refusal::Shape)?,
            ) as usize,
            usize::try_from(u64::from_le_bytes(
                items[3]
                    .canonical_bytes()
                    .try_into()
                    .map_err(|_| Refusal::Shape)?,
            ))
            .map_err(|_| Refusal::Shape)?,
            items[4]
                .canonical_bytes()
                .try_into()
                .map_err(|_| Refusal::Shape)?,
        )
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn position(&self) -> usize {
        self.position
    }
    pub fn body_length(&self) -> usize {
        self.body_length
    }
    pub fn body_identity(&self) -> &[u8; 64] {
        &self.body_identity
    }
    pub fn roster_identity(&self) -> &[u8; 64] {
        &self.roster
    }
    pub fn identity(&self) -> [u8; 64] {
        identity(OFFER_IDENTITY_DOMAIN, &self.bytes).expect("Canonical offer identity")
    }
}
pub struct AuthenticatedContributionOffer {
    roster: Arc<AuthenticatedRosterProposal>,
    envelope: OfferEnvelope,
    signature: [u8; SIGNATURE_BYTES],
}
impl AuthenticatedContributionOffer {
    pub fn roster(&self) -> &Arc<AuthenticatedRosterProposal> {
        &self.roster
    }
    pub fn envelope(&self) -> &OfferEnvelope {
        &self.envelope
    }
    pub fn signature(&self) -> &[u8; SIGNATURE_BYTES] {
        &self.signature
    }
}
pub fn authenticate_offer(
    roster: Arc<AuthenticatedRosterProposal>,
    bytes: &[u8],
    signature: &[u8],
) -> Result<AuthenticatedContributionOffer, Refusal> {
    let envelope = OfferEnvelope::decode(roster.proposal(), bytes)?;
    let signature = signature.try_into().map_err(|_| Refusal::Shape)?;
    let key = ml_dsa_65::PublicKey::try_from_bytes(
        roster.proposal().records()[envelope.position()]
            .header()
            .signing_public,
    )
    .map_err(|_| Refusal::Shape)?;
    if !key.verify(&envelope.identity(), &signature, OFFER_PURPOSE.as_bytes()) {
        return Err(Refusal::Crypto);
    }
    Ok(AuthenticatedContributionOffer {
        roster,
        envelope,
        signature,
    })
}
impl Credential {
    pub fn sign_offer(
        &mut self,
        context: &RetainedContributionContext,
        envelope: &OfferEnvelope,
    ) -> Result<[u8; SIGNATURE_BYTES], Refusal> {
        self.validate_offer_context(context)?;
        if envelope.roster_identity() != context.identity()
            || envelope.position() != context.position()
        {
            return Err(Refusal::Context);
        }
        self.offer_signed = Some(envelope.identity());
        self.sign_deterministically(&envelope.identity(), OFFER_PURPOSE.as_bytes())
    }
}
