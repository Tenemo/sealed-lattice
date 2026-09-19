use crate::{
    Credential, Error,
    contribution_commitment::ComputedContributionCommitment,
    foundation::{
        CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple,
        hash_foundation_tuple_512,
    },
    roster::RetainedContributionContext,
    roster_authentication::OrganizerSignedRoster,
};
use fips204::{
    ml_dsa_65,
    traits::{KeyGen, SerDes, Signer, Verifier},
};
use std::sync::Arc;
use zeroize::Zeroizing;

pub const CONFIRMATION_CONTEXT: &[u8] = b"sealed-lattice/roster-confirmation/v1";
pub const OPENING_CONTEXT: &[u8] = b"sealed-lattice/setup-opening/v1";
const MAXIMUM_MESSAGE_BYTES: usize = 1024;

pub(crate) struct ConfirmationLock {
    proposal: [u8; 64],
    position: usize,
    commitment: [u8; 64],
    salt: Zeroizing<[u8; 64]>,
    opened: bool,
}

pub struct SignedConfirmation {
    body: Vec<u8>,
    signature: [u8; 3309],
}
impl SignedConfirmation {
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn signature(&self) -> &[u8; 3309] {
        &self.signature
    }
}
pub struct VerifiedConfirmation {
    proposal: [u8; 64],
    position: usize,
    commitment: [u8; 64],
    body: Vec<u8>,
    signature: [u8; 3309],
}
impl VerifiedConfirmation {
    pub fn position(&self) -> usize {
        self.position
    }
    pub fn commitment(&self) -> &[u8; 64] {
        &self.commitment
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn signature(&self) -> &[u8; 3309] {
        &self.signature
    }
}

pub(crate) fn identity(domain: &str, body: &[u8]) -> Result<[u8; 64], Error> {
    hash_foundation_tuple_512(
        domain,
        &[CanonicalItem::variable_bytes(body).map_err(|_| Error::Shape)?],
    )
    .map(|hash| hash.into_bytes())
    .map_err(|_| Error::Shape)
}
fn body(
    purpose: &str,
    predecessor: [u8; 64],
    position: usize,
    value: CanonicalItem,
) -> Result<Vec<u8>, Error> {
    let position = u16::try_from(position).map_err(|_| Error::Shape)?;
    CanonicalTuple::new(
        1,
        1,
        vec![
            CanonicalItem::nonempty_ascii(purpose).map_err(|_| Error::Shape)?,
            CanonicalItem::hash512(predecessor),
            CanonicalItem::unsigned16(position),
            value,
        ],
    )
    .encode()
    .map_err(|_| Error::Shape)
}
pub(crate) fn decode(
    bytes: &[u8],
    purpose: &[u8],
    predecessor: [u8; 64],
    value_type: CanonicalItemType,
) -> Result<(usize, [u8; 64]), Error> {
    if bytes.len() > MAXIMUM_MESSAGE_BYTES {
        return Err(Error::Shape);
    }
    let limits = CanonicalDecodeLimits {
        maximum_tuple_byte_length: MAXIMUM_MESSAGE_BYTES,
        maximum_item_count: 4,
        maximum_item_byte_length: MAXIMUM_MESSAGE_BYTES,
        maximum_nesting_depth: 1,
        maximum_cumulative_work_byte_length: 4 * MAXIMUM_MESSAGE_BYTES,
        maximum_cumulative_allocation_byte_length: 4 * MAXIMUM_MESSAGE_BYTES,
    };
    let tuple = CanonicalTuple::decode(bytes, &limits).map_err(|_| Error::Shape)?;
    if tuple.schema_identifier != 1 || tuple.schema_version != 1 || tuple.items.len() != 4 {
        return Err(Error::Shape);
    }
    let items = &tuple.items;
    if items[0].item_type() != CanonicalItemType::Ascii
        || items[0].variable_value_bytes().map_err(|_| Error::Shape)? != purpose
        || items[1].item_type() != CanonicalItemType::Hash512
        || items[1].canonical_bytes() != predecessor
        || items[2].item_type() != CanonicalItemType::Unsigned16
        || items[3].item_type() != value_type
    {
        return Err(Error::Context);
    }
    let position = u16::from_le_bytes(
        items[2]
            .canonical_bytes()
            .try_into()
            .map_err(|_| Error::Shape)?,
    ) as usize;
    let value = items[3]
        .canonical_bytes()
        .try_into()
        .map_err(|_| Error::Shape)?;
    Ok((position, value))
}
fn verify_signature(
    proposal: &OrganizerSignedRoster,
    position: usize,
    identity: &[u8; 64],
    signature: &[u8],
    context: &[u8],
) -> Result<[u8; 3309], Error> {
    let record = proposal
        .proposal()
        .records()
        .get(position)
        .ok_or(Error::Context)?;
    let signature = signature.try_into().map_err(|_| Error::Shape)?;
    let key = ml_dsa_65::PublicKey::try_from_bytes(record.header().signing_public)
        .map_err(|_| Error::Shape)?;
    if !key.verify(identity, &signature, context) {
        return Err(Error::Crypto);
    }
    Ok(signature)
}

impl Credential {
    pub fn validate_retained_confirmation(
        &self,
        context: &RetainedContributionContext,
    ) -> Result<(), Error> {
        if self.confirmation.is_some() {
            return Err(Error::Consumed);
        }
        if self.completed_body != Some(context.owner_body) {
            return Err(Error::Context);
        }
        Ok(())
    }
    pub fn retained_confirmation_body(
        &self,
        context: &RetainedContributionContext,
        computed: &ComputedContributionCommitment,
    ) -> Result<Vec<u8>, Error> {
        self.validate_retained_confirmation(context)?;
        if computed.proposal != context.proposal || computed.position != context.position {
            return Err(Error::Context);
        }
        Self::computed_confirmation_body(computed)
    }
    pub fn sign_retained_confirmation(
        &mut self,
        context: &RetainedContributionContext,
        computed: ComputedContributionCommitment,
        coins: [u8; 32],
    ) -> Result<SignedConfirmation, Error> {
        let body = self.retained_confirmation_body(context, &computed)?;
        self.sign_computed_confirmation(body, computed, coins)
    }
    pub fn validate_confirmation_position(
        &self,
        proposal: &OrganizerSignedRoster,
        position: usize,
    ) -> Result<(), Error> {
        if self.confirmation.is_some() {
            return Err(Error::Consumed);
        }
        let record = proposal
            .proposal()
            .records()
            .get(position)
            .ok_or(Error::Context)?;
        if self.signing_public != record.header().signing_public
            || self.completed_body != Some(record.body_digest())
        {
            return Err(Error::Context);
        }
        Ok(())
    }
    fn check_confirmation_owner(
        &self,
        proposal: &OrganizerSignedRoster,
        computed: &ComputedContributionCommitment,
    ) -> Result<(), Error> {
        if computed.proposal != proposal.proposal().identity() {
            return Err(Error::Context);
        }
        self.validate_confirmation_position(proposal, computed.position)
    }
    pub fn confirmation_body(
        &self,
        proposal: &OrganizerSignedRoster,
        computed: &ComputedContributionCommitment,
    ) -> Result<Vec<u8>, Error> {
        self.check_confirmation_owner(proposal, computed)?;
        Self::computed_confirmation_body(computed)
    }
    fn computed_confirmation_body(
        computed: &ComputedContributionCommitment,
    ) -> Result<Vec<u8>, Error> {
        body(
            "sealed-lattice/roster-confirmation/v1",
            computed.proposal,
            computed.position,
            CanonicalItem::hash512(computed.digest),
        )
    }
    pub fn sign_confirmation(
        &mut self,
        proposal: &OrganizerSignedRoster,
        computed: ComputedContributionCommitment,
        coins: [u8; 32],
    ) -> Result<SignedConfirmation, Error> {
        let body = self.confirmation_body(proposal, &computed)?;
        self.sign_computed_confirmation(body, computed, coins)
    }
    fn sign_computed_confirmation(
        &mut self,
        body: Vec<u8>,
        computed: ComputedContributionCommitment,
        coins: [u8; 32],
    ) -> Result<SignedConfirmation, Error> {
        let message = identity("sealed-lattice/roster-confirmation-id/v1", &body)?;
        self.confirmation = Some(ConfirmationLock {
            proposal: computed.proposal,
            position: computed.position,
            commitment: computed.digest,
            salt: computed.salt,
            opened: false,
        });
        let coins = Zeroizing::new(coins);
        let (_, key) = ml_dsa_65::KG::keygen_from_seed(&self.signing_seed);
        let signature = key
            .try_sign_with_seed(&coins, &message, CONFIRMATION_CONTEXT)
            .map_err(|_| Error::Crypto)?;
        Ok(SignedConfirmation { body, signature })
    }
    pub fn restore_confirmation(
        &mut self,
        proposal: &OrganizerSignedRoster,
        computed: ComputedContributionCommitment,
        confirmation: &VerifiedConfirmation,
    ) -> Result<(), Error> {
        if self.confirmation.is_some() {
            return Err(Error::Consumed);
        }
        self.check_confirmation_owner(proposal, &computed)?;
        if confirmation.proposal != computed.proposal
            || confirmation.position != computed.position
            || confirmation.commitment != computed.digest
        {
            return Err(Error::Context);
        }
        self.confirmation = Some(ConfirmationLock {
            proposal: computed.proposal,
            position: computed.position,
            commitment: computed.digest,
            salt: computed.salt,
            opened: false,
        });
        Ok(())
    }
}

pub fn verify_confirmation(
    proposal: &OrganizerSignedRoster,
    bytes: &[u8],
    signature: &[u8],
) -> Result<VerifiedConfirmation, Error> {
    let (position, commitment) = decode(
        bytes,
        CONFIRMATION_CONTEXT,
        proposal.proposal().identity(),
        CanonicalItemType::Hash512,
    )?;
    let digest = identity("sealed-lattice/roster-confirmation-id/v1", bytes)?;
    let signature = verify_signature(proposal, position, &digest, signature, CONFIRMATION_CONTEXT)?;
    Ok(VerifiedConfirmation {
        proposal: proposal.proposal().identity(),
        position,
        commitment,
        body: bytes.to_vec(),
        signature,
    })
}

pub struct CommitmentInventory {
    proposal: Arc<OrganizerSignedRoster>,
    confirmations: Vec<VerifiedConfirmation>,
    body: Vec<u8>,
    identity: [u8; 64],
}
impl CommitmentInventory {
    pub fn new(
        proposal: Arc<OrganizerSignedRoster>,
        mut confirmations: Vec<VerifiedConfirmation>,
    ) -> Result<Self, Error> {
        let count = proposal.proposal().records().len();
        if confirmations.len() != count {
            return Err(Error::Shape);
        }
        confirmations.sort_by_key(|confirmation| confirmation.position);
        let mut commitments = Vec::from((count as u32).to_le_bytes());
        for (position, confirmation) in confirmations.iter().enumerate() {
            if confirmation.position != position
                || confirmation.proposal != proposal.proposal().identity()
            {
                return Err(Error::Context);
            }
            commitments.extend(confirmation.commitment);
        }
        let body = CanonicalTuple::new(
            1,
            1,
            vec![
                CanonicalItem::nonempty_ascii("sealed-lattice/commitment-inventory/v1")
                    .map_err(|_| Error::Shape)?,
                CanonicalItem::hash512(proposal.proposal().identity()),
                CanonicalItem::variable_bytes(commitments).map_err(|_| Error::Shape)?,
            ],
        )
        .encode()
        .map_err(|_| Error::Shape)?;
        let identity = identity("sealed-lattice/commitment-inventory-id/v1", &body)?;
        Ok(Self {
            proposal,
            confirmations,
            body,
            identity,
        })
    }
    pub fn identity(&self) -> [u8; 64] {
        self.identity
    }
    pub fn identity_bytes(&self) -> &[u8; 64] {
        &self.identity
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn proposal(&self) -> &OrganizerSignedRoster {
        &self.proposal
    }
    pub fn confirmations(&self) -> &[VerifiedConfirmation] {
        &self.confirmations
    }
}

pub struct SignedOpening {
    body: Vec<u8>,
    signature: [u8; 3309],
}
impl SignedOpening {
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn signature(&self) -> &[u8; 3309] {
        &self.signature
    }
}
pub struct AuthenticatedOpening {
    inventory: [u8; 64],
    position: usize,
    salt: [u8; 64],
}
impl AuthenticatedOpening {
    pub fn inventory(&self) -> [u8; 64] {
        self.inventory
    }
    pub fn position(&self) -> usize {
        self.position
    }
    pub fn salt(&self) -> &[u8; 64] {
        &self.salt
    }
}
impl Credential {
    pub fn opening_body(&self, inventory: &CommitmentInventory) -> Result<Vec<u8>, Error> {
        let lock = self.confirmation.as_ref().ok_or(Error::Consumed)?;
        if lock.opened {
            return Err(Error::Consumed);
        }
        if inventory.proposal.proposal().identity() != lock.proposal
            || inventory
                .confirmations
                .get(lock.position)
                .is_none_or(|entry| entry.commitment != lock.commitment)
        {
            return Err(Error::Context);
        }
        body(
            "sealed-lattice/setup-opening/v1",
            inventory.identity,
            lock.position,
            CanonicalItem::fixed_bytes(*lock.salt).map_err(|_| Error::Shape)?,
        )
    }
    pub fn sign_opening(
        &mut self,
        inventory: &CommitmentInventory,
        coins: [u8; 32],
    ) -> Result<SignedOpening, Error> {
        let body = self.opening_body(inventory)?;
        let message = identity("sealed-lattice/setup-opening-id/v1", &body)?;
        self.confirmation.as_mut().ok_or(Error::Consumed)?.opened = true;
        let coins = Zeroizing::new(coins);
        let (_, key) = ml_dsa_65::KG::keygen_from_seed(&self.signing_seed);
        let signature = key
            .try_sign_with_seed(&coins, &message, OPENING_CONTEXT)
            .map_err(|_| Error::Crypto)?;
        Ok(SignedOpening { body, signature })
    }
    pub fn consume_opening(&mut self) -> Result<(), Error> {
        self.confirmation.as_mut().ok_or(Error::Consumed)?.opened = true;
        Ok(())
    }
    pub fn restore_opening(
        &mut self,
        inventory: &CommitmentInventory,
        body: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        let opening = verify_opening(inventory, body, signature)?;
        let lock = self.confirmation.as_ref().ok_or(Error::Consumed)?;
        if opening.position != lock.position
            || opening.salt != *lock.salt
            || inventory.proposal.proposal().identity() != lock.proposal
            || inventory.confirmations[lock.position].commitment != lock.commitment
        {
            return Err(Error::Context);
        }
        self.consume_opening()
    }
}
pub fn verify_opening(
    inventory: &CommitmentInventory,
    bytes: &[u8],
    signature: &[u8],
) -> Result<AuthenticatedOpening, Error> {
    let (position, salt) = decode(
        bytes,
        OPENING_CONTEXT,
        inventory.identity,
        CanonicalItemType::RawBytes,
    )?;
    let digest = identity("sealed-lattice/setup-opening-id/v1", bytes)?;
    verify_signature(
        &inventory.proposal,
        position,
        &digest,
        signature,
        OPENING_CONTEXT,
    )?;
    Ok(AuthenticatedOpening {
        inventory: inventory.identity,
        position,
        salt,
    })
}
