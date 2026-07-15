use fips204::{
    ml_dsa_65,
    traits::{SerDes as SignatureSerDes, Verifier},
};

use super::schemas::{SchemaResult, read_hash, require_header};
use super::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, FOUNDATION_PROFILE,
    FoundationSchemaError, Hash512, ML_DSA_65_SIGNATURE_BYTE_LENGTH, ParticipantIdentity,
    RefusalReason, Roster, VerificationResult, hash_foundation_tuple_512,
};

pub const NAMESPACE_FRESHNESS_CHECKPOINT_SCHEMA_IDENTIFIER: u16 = 0x1617;
pub const NAMESPACE_FRESHNESS_VOTE_SCHEMA_IDENTIFIER: u16 = 0x1618;
pub const SIGNED_NAMESPACE_FRESHNESS_VOTE_SCHEMA_IDENTIFIER: u16 = 0x1619;

const NAMESPACE_FRESHNESS_SCHEMA_VERSION: u16 = 1;
const CHECKPOINT_HASH_DOMAIN: &str = "sealed-lattice/namespace-freshness/checkpoint/v1";
const VOTE_SIGNATURE_MESSAGE_HASH_DOMAIN: &str =
    "sealed-lattice/namespace-freshness/vote-signature-message/v1";
const VOTE_SIGNATURE_CONTEXT: &[u8] = b"sealed-lattice/namespace-freshness-vote/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamespaceFreshnessCheckpoint {
    suite_identifier: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    subject_participant_identity: ParticipantIdentity,
    storage_instance_identity: Hash512,
    namespace_sequence: u64,
    authenticated_head_digest: Hash512,
    previous_checkpoint_hash: Option<Hash512>,
}

impl NamespaceFreshnessCheckpoint {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        suite_identifier: Hash512,
        ceremony_context_hash: Hash512,
        action_context_hash: Hash512,
        subject_participant_identity: ParticipantIdentity,
        storage_instance_identity: Hash512,
        namespace_sequence: u64,
        authenticated_head_digest: Hash512,
        previous_checkpoint_hash: Option<Hash512>,
    ) -> SchemaResult<Self> {
        if (namespace_sequence == 0) != previous_checkpoint_hash.is_none() {
            return Err(schema_error(
                RefusalReason::MissingPrerequisite,
                "namespace freshness checkpoint predecessor does not match its sequence",
            ));
        }
        Ok(Self {
            suite_identifier,
            ceremony_context_hash,
            action_context_hash,
            subject_participant_identity,
            storage_instance_identity,
            namespace_sequence,
            authenticated_head_digest,
            previous_checkpoint_hash,
        })
    }

    pub const fn suite_identifier(self) -> Hash512 {
        self.suite_identifier
    }

    pub const fn ceremony_context_hash(self) -> Hash512 {
        self.ceremony_context_hash
    }

    pub const fn action_context_hash(self) -> Hash512 {
        self.action_context_hash
    }

    pub const fn subject_participant_identity(self) -> ParticipantIdentity {
        self.subject_participant_identity
    }

    pub const fn storage_instance_identity(self) -> Hash512 {
        self.storage_instance_identity
    }

    pub const fn namespace_sequence(self) -> u64 {
        self.namespace_sequence
    }

    pub const fn authenticated_head_digest(self) -> Hash512 {
        self.authenticated_head_digest
    }

    pub const fn previous_checkpoint_hash(self) -> Option<Hash512> {
        self.previous_checkpoint_hash
    }

    pub fn encode(self) -> SchemaResult<Vec<u8>> {
        let previous_checkpoint_hash = self
            .previous_checkpoint_hash
            .map(|hash| CanonicalItem::hash512(hash.into_bytes()));
        Ok(CanonicalTuple::new(
            NAMESPACE_FRESHNESS_CHECKPOINT_SCHEMA_IDENTIFIER,
            NAMESPACE_FRESHNESS_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(FOUNDATION_PROFILE.protocol_version),
                CanonicalItem::hash512(self.suite_identifier.into_bytes()),
                CanonicalItem::hash512(self.ceremony_context_hash.into_bytes()),
                CanonicalItem::hash512(self.action_context_hash.into_bytes()),
                CanonicalItem::participant_identity(self.subject_participant_identity.into_bytes()),
                CanonicalItem::hash512(self.storage_instance_identity.into_bytes()),
                CanonicalItem::unsigned64(self.namespace_sequence),
                CanonicalItem::hash512(self.authenticated_head_digest.into_bytes()),
                CanonicalItem::optional(
                    CanonicalItemType::Hash512,
                    previous_checkpoint_hash.as_ref(),
                )?,
            ],
        )
        .encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_header(&tuple, NAMESPACE_FRESHNESS_CHECKPOINT_SCHEMA_IDENTIFIER, 9)?;
        if read_unsigned16(&tuple.items[0])? != FOUNDATION_PROFILE.protocol_version {
            return Err(schema_error(
                RefusalReason::UnsupportedVersionOrSuite,
                "namespace freshness protocol version is unsupported",
            ));
        }
        Self::new(
            read_hash(&tuple.items[1])?,
            read_hash(&tuple.items[2])?,
            read_hash(&tuple.items[3])?,
            read_participant_identity(&tuple.items[4])?,
            read_hash(&tuple.items[5])?,
            read_unsigned64(&tuple.items[6])?,
            read_hash(&tuple.items[7])?,
            read_optional_hash(&tuple.items[8])?,
        )
    }

    pub fn checkpoint_hash(self) -> SchemaResult<Hash512> {
        Ok(hash_foundation_tuple_512(
            CHECKPOINT_HASH_DOMAIN,
            &[CanonicalItem::variable_bytes(self.encode()?)?],
        )?)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamespaceFreshnessVote {
    checkpoint_hash: Hash512,
    witness_participant_identity: ParticipantIdentity,
    suite_identifier: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
}

impl NamespaceFreshnessVote {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        checkpoint_hash: Hash512,
        witness_participant_identity: ParticipantIdentity,
        suite_identifier: Hash512,
        ceremony_context_hash: Hash512,
        action_context_hash: Hash512,
    ) -> Self {
        Self {
            checkpoint_hash,
            witness_participant_identity,
            suite_identifier,
            ceremony_context_hash,
            action_context_hash,
        }
    }

    pub const fn checkpoint_hash(self) -> Hash512 {
        self.checkpoint_hash
    }

    pub const fn witness_participant_identity(self) -> ParticipantIdentity {
        self.witness_participant_identity
    }

    pub const fn suite_identifier(self) -> Hash512 {
        self.suite_identifier
    }

    pub const fn ceremony_context_hash(self) -> Hash512 {
        self.ceremony_context_hash
    }

    pub const fn action_context_hash(self) -> Hash512 {
        self.action_context_hash
    }

    pub fn encode(self) -> SchemaResult<Vec<u8>> {
        Ok(CanonicalTuple::new(
            NAMESPACE_FRESHNESS_VOTE_SCHEMA_IDENTIFIER,
            NAMESPACE_FRESHNESS_SCHEMA_VERSION,
            vec![
                CanonicalItem::hash512(self.checkpoint_hash.into_bytes()),
                CanonicalItem::participant_identity(self.witness_participant_identity.into_bytes()),
                CanonicalItem::hash512(self.suite_identifier.into_bytes()),
                CanonicalItem::hash512(self.ceremony_context_hash.into_bytes()),
                CanonicalItem::hash512(self.action_context_hash.into_bytes()),
            ],
        )
        .encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_header(&tuple, NAMESPACE_FRESHNESS_VOTE_SCHEMA_IDENTIFIER, 5)?;
        Ok(Self::new(
            read_hash(&tuple.items[0])?,
            read_participant_identity(&tuple.items[1])?,
            read_hash(&tuple.items[2])?,
            read_hash(&tuple.items[3])?,
            read_hash(&tuple.items[4])?,
        ))
    }

    pub fn signature_message(self, roster_hash: Hash512) -> SchemaResult<Hash512> {
        Ok(hash_foundation_tuple_512(
            VOTE_SIGNATURE_MESSAGE_HASH_DOMAIN,
            &[
                CanonicalItem::variable_bytes(self.encode()?)?,
                CanonicalItem::hash512(roster_hash.into_bytes()),
            ],
        )?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedNamespaceFreshnessVote {
    vote: NamespaceFreshnessVote,
    signature: [u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH],
}

impl SignedNamespaceFreshnessVote {
    pub const fn new(
        vote: NamespaceFreshnessVote,
        signature: [u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH],
    ) -> Self {
        Self { vote, signature }
    }

    pub const fn vote(&self) -> NamespaceFreshnessVote {
        self.vote
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(CanonicalTuple::new(
            SIGNED_NAMESPACE_FRESHNESS_VOTE_SCHEMA_IDENTIFIER,
            NAMESPACE_FRESHNESS_SCHEMA_VERSION,
            vec![
                CanonicalItem::variable_bytes(self.vote.encode()?)?,
                CanonicalItem::fixed_bytes(self.signature)?,
            ],
        )
        .encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_header(&tuple, SIGNED_NAMESPACE_FRESHNESS_VOTE_SCHEMA_IDENTIFIER, 2)?;
        let vote_bytes = read_variable_bytes(&tuple.items[0])?;
        let signature = read_fixed_signature(&tuple.items[1])?;
        let value = Self::new(
            NamespaceFreshnessVote::decode(vote_bytes, limits)?,
            signature,
        );
        if value.encode()? != bytes {
            return Err(schema_error(
                RefusalReason::MalformedEncoding,
                "namespace freshness vote carrier is not canonical",
            ));
        }
        Ok(value)
    }
}

pub struct VerifiedNamespaceFreshnessCheckpoint {
    checkpoint: NamespaceFreshnessCheckpoint,
    checkpoint_hash: Hash512,
    canonical_checkpoint: Vec<u8>,
}

impl VerifiedNamespaceFreshnessCheckpoint {
    pub const fn checkpoint(&self) -> NamespaceFreshnessCheckpoint {
        self.checkpoint
    }

    pub const fn checkpoint_hash(&self) -> Hash512 {
        self.checkpoint_hash
    }

    pub fn canonical_checkpoint(&self) -> &[u8] {
        &self.canonical_checkpoint
    }
}

pub struct VerifiedNamespaceFreshnessCertificate {
    checkpoint: NamespaceFreshnessCheckpoint,
    checkpoint_hash: Hash512,
    witness_participant_identities: Vec<ParticipantIdentity>,
}

impl VerifiedNamespaceFreshnessCertificate {
    pub const fn checkpoint(&self) -> NamespaceFreshnessCheckpoint {
        self.checkpoint
    }

    pub const fn checkpoint_hash(&self) -> Hash512 {
        self.checkpoint_hash
    }

    pub fn witness_participant_identities(&self) -> &[ParticipantIdentity] {
        &self.witness_participant_identities
    }
}

pub struct NamespaceFreshnessVerifier {
    suite_identifier: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    subject_participant_identity: ParticipantIdentity,
    storage_instance_identity: Hash512,
    roster: Roster,
    roster_hash: Hash512,
    external_witness_identities: Vec<ParticipantIdentity>,
}

impl NamespaceFreshnessVerifier {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        suite_identifier: Hash512,
        ceremony_context_hash: Hash512,
        action_context_hash: Hash512,
        subject_participant_identity: ParticipantIdentity,
        storage_instance_identity: Hash512,
        roster: &Roster,
    ) -> SchemaResult<Self> {
        let roster = Roster::new(roster.entries.clone())?;
        let roster_hash = roster.roster_hash()?;
        if !roster
            .entries
            .iter()
            .any(|entry| entry.participant_identity().ok() == Some(subject_participant_identity))
        {
            return Err(schema_error(
                RefusalReason::WrongContext,
                "namespace freshness subject is absent from the external roster",
            ));
        }
        let external_witness_identities = roster
            .entries
            .iter()
            .map(|entry| entry.participant_identity())
            .filter_map(|identity| match identity {
                Ok(identity) if identity != subject_participant_identity => Some(Ok(identity)),
                Ok(_) => None,
                Err(error) => Some(Err(error)),
            })
            .collect::<SchemaResult<Vec<_>>>()?;
        if external_witness_identities.len()
            != usize::from(FOUNDATION_PROFILE.participant_count - 1)
        {
            return Err(schema_error(
                RefusalReason::WrongContext,
                "namespace freshness witness universe is incomplete",
            ));
        }
        Ok(Self {
            suite_identifier,
            ceremony_context_hash,
            action_context_hash,
            subject_participant_identity,
            storage_instance_identity,
            roster,
            roster_hash,
            external_witness_identities,
        })
    }

    pub fn prepare_checkpoint(
        &self,
        namespace_sequence: u64,
        authenticated_head_digest: Hash512,
        previous_checkpoint_hash: Option<Hash512>,
    ) -> VerificationResult<VerifiedNamespaceFreshnessCheckpoint> {
        let checkpoint = match NamespaceFreshnessCheckpoint::new(
            self.suite_identifier,
            self.ceremony_context_hash,
            self.action_context_hash,
            self.subject_participant_identity,
            self.storage_instance_identity,
            namespace_sequence,
            authenticated_head_digest,
            previous_checkpoint_hash,
        ) {
            Ok(value) => value,
            Err(error) => return VerificationResult::refused(error.refusal_reason),
        };
        self.verify_checkpoint_value(checkpoint)
    }

    pub fn verify_checkpoint(
        &self,
        canonical_checkpoint: &[u8],
        limits: &CanonicalDecodeLimits,
    ) -> VerificationResult<VerifiedNamespaceFreshnessCheckpoint> {
        let checkpoint = match NamespaceFreshnessCheckpoint::decode(canonical_checkpoint, limits) {
            Ok(value) => value,
            Err(error) => return VerificationResult::refused(error.refusal_reason),
        };
        let value = match self.verify_checkpoint_value(checkpoint).into_result() {
            Ok(value) => value,
            Err(refusal_reason) => return VerificationResult::refused(refusal_reason),
        };
        if value.canonical_checkpoint() != canonical_checkpoint {
            return VerificationResult::refused(RefusalReason::MalformedEncoding);
        }
        VerificationResult::valid(value)
    }

    fn verify_checkpoint_value(
        &self,
        checkpoint: NamespaceFreshnessCheckpoint,
    ) -> VerificationResult<VerifiedNamespaceFreshnessCheckpoint> {
        if checkpoint.suite_identifier() != self.suite_identifier
            || checkpoint.ceremony_context_hash() != self.ceremony_context_hash
            || checkpoint.action_context_hash() != self.action_context_hash
            || checkpoint.subject_participant_identity() != self.subject_participant_identity
            || checkpoint.storage_instance_identity() != self.storage_instance_identity
        {
            return VerificationResult::refused(RefusalReason::WrongContext);
        }
        let canonical_checkpoint = match checkpoint.encode() {
            Ok(value) => value,
            Err(error) => return VerificationResult::refused(error.refusal_reason),
        };
        let checkpoint_hash = match checkpoint.checkpoint_hash() {
            Ok(value) => value,
            Err(error) => return VerificationResult::refused(error.refusal_reason),
        };
        VerificationResult::valid(VerifiedNamespaceFreshnessCheckpoint {
            checkpoint,
            checkpoint_hash,
            canonical_checkpoint,
        })
    }

    pub fn verify_vote_carrier(
        &self,
        verified_checkpoint: &VerifiedNamespaceFreshnessCheckpoint,
        expected_witness_participant_identity: ParticipantIdentity,
        canonical_vote_carrier: &[u8],
        limits: &CanonicalDecodeLimits,
    ) -> VerificationResult<ParticipantIdentity> {
        if expected_witness_participant_identity == self.subject_participant_identity
            || !self
                .external_witness_identities
                .contains(&expected_witness_participant_identity)
        {
            return VerificationResult::refused(RefusalReason::WrongContext);
        }
        let carrier = match SignedNamespaceFreshnessVote::decode(canonical_vote_carrier, limits) {
            Ok(value) => value,
            Err(error) => return VerificationResult::refused(error.refusal_reason),
        };
        let vote = carrier.vote();
        if vote.checkpoint_hash() != verified_checkpoint.checkpoint_hash()
            || vote.witness_participant_identity() != expected_witness_participant_identity
            || vote.suite_identifier() != self.suite_identifier
            || vote.ceremony_context_hash() != self.ceremony_context_hash
            || vote.action_context_hash() != self.action_context_hash
        {
            return VerificationResult::refused(RefusalReason::WrongContext);
        }
        let Some(roster_entry) = self.roster.entries.iter().find(|entry| {
            entry.participant_identity().ok() == Some(expected_witness_participant_identity)
        }) else {
            return VerificationResult::refused(RefusalReason::WrongContext);
        };
        let message = match vote.signature_message(self.roster_hash) {
            Ok(value) => value,
            Err(error) => return VerificationResult::refused(error.refusal_reason),
        };
        let Ok(public_key) =
            ml_dsa_65::PublicKey::try_from_bytes(roster_entry.signing_verification_key)
        else {
            return VerificationResult::refused(RefusalReason::InvalidSignature);
        };
        if !public_key.verify(
            message.as_bytes(),
            &carrier.signature,
            VOTE_SIGNATURE_CONTEXT,
        ) {
            return VerificationResult::refused(RefusalReason::InvalidSignature);
        }
        VerificationResult::valid(expected_witness_participant_identity)
    }

    pub fn verify_certificate(
        &self,
        verified_checkpoint: &VerifiedNamespaceFreshnessCheckpoint,
        canonical_vote_carriers: &[Vec<u8>],
        limits: &CanonicalDecodeLimits,
    ) -> VerificationResult<VerifiedNamespaceFreshnessCertificate> {
        if canonical_vote_carriers.len() < usize::from(FOUNDATION_PROFILE.state_witness_quorum)
            || canonical_vote_carriers.len() > self.external_witness_identities.len()
        {
            return VerificationResult::refused(RefusalReason::MissingPrerequisite);
        }
        let mut witness_participant_identities = Vec::with_capacity(canonical_vote_carriers.len());
        let mut previous_roster_position = None;
        for carrier in canonical_vote_carriers {
            let decoded = match SignedNamespaceFreshnessVote::decode(carrier, limits) {
                Ok(value) => value,
                Err(error) => return VerificationResult::refused(error.refusal_reason),
            };
            let witness_identity = decoded.vote().witness_participant_identity();
            let Some(roster_position) = self
                .external_witness_identities
                .iter()
                .position(|identity| *identity == witness_identity)
            else {
                return VerificationResult::refused(RefusalReason::WrongContext);
            };
            if previous_roster_position.is_some_and(|previous| previous >= roster_position) {
                return VerificationResult::refused(RefusalReason::Equivocation);
            }
            previous_roster_position = Some(roster_position);
            let verified_identity = match self
                .verify_vote_carrier(verified_checkpoint, witness_identity, carrier, limits)
                .into_result()
            {
                Ok(value) => value,
                Err(refusal_reason) => {
                    return VerificationResult::refused(refusal_reason);
                }
            };
            witness_participant_identities.push(verified_identity);
        }
        VerificationResult::valid(VerifiedNamespaceFreshnessCertificate {
            checkpoint: verified_checkpoint.checkpoint(),
            checkpoint_hash: verified_checkpoint.checkpoint_hash(),
            witness_participant_identities,
        })
    }
}

fn read_unsigned16(item: &CanonicalItem) -> SchemaResult<u16> {
    if item.item_type() != CanonicalItemType::Unsigned16 || item.canonical_bytes().len() != 2 {
        return Err(schema_error(
            RefusalReason::WrongTypeOrLength,
            "namespace freshness unsigned16 has the wrong type or length",
        ));
    }
    Ok(u16::from_le_bytes([
        item.canonical_bytes()[0],
        item.canonical_bytes()[1],
    ]))
}

fn read_unsigned64(item: &CanonicalItem) -> SchemaResult<u64> {
    if item.item_type() != CanonicalItemType::Unsigned64 || item.canonical_bytes().len() != 8 {
        return Err(schema_error(
            RefusalReason::WrongTypeOrLength,
            "namespace freshness unsigned64 has the wrong type or length",
        ));
    }
    let bytes: [u8; 8] = item.canonical_bytes().try_into().map_err(|_| {
        schema_error(
            RefusalReason::MalformedEncoding,
            "namespace freshness unsigned64 is malformed",
        )
    })?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_participant_identity(item: &CanonicalItem) -> SchemaResult<ParticipantIdentity> {
    if item.item_type() != CanonicalItemType::ParticipantIdentity
        || item.canonical_bytes().len() != ParticipantIdentity::BYTE_LENGTH
    {
        return Err(schema_error(
            RefusalReason::WrongTypeOrLength,
            "namespace freshness participant identity has the wrong type or length",
        ));
    }
    let bytes = item.canonical_bytes().try_into().map_err(|_| {
        schema_error(
            RefusalReason::MalformedEncoding,
            "namespace freshness participant identity is malformed",
        )
    })?;
    Ok(ParticipantIdentity::from_bytes(bytes))
}

fn read_optional_hash(item: &CanonicalItem) -> SchemaResult<Option<Hash512>> {
    if item.item_type() != CanonicalItemType::Optional {
        return Err(schema_error(
            RefusalReason::WrongTypeOrLength,
            "namespace freshness optional hash has the wrong type",
        ));
    }
    let bytes = item.canonical_bytes();
    if bytes.len() < 3
        || u16::from_le_bytes([bytes[0], bytes[1]]) != CanonicalItemType::Hash512.canonical_code()
    {
        return Err(schema_error(
            RefusalReason::WrongTypeOrLength,
            "namespace freshness optional hash has the wrong contained type",
        ));
    }
    match bytes[2] {
        0 if bytes.len() == 3 => Ok(None),
        1 if bytes.len() == 3 + Hash512::BYTE_LENGTH => {
            let hash_bytes = bytes[3..].try_into().map_err(|_| {
                schema_error(
                    RefusalReason::MalformedEncoding,
                    "namespace freshness optional hash is malformed",
                )
            })?;
            Ok(Some(Hash512::from_bytes(hash_bytes)))
        }
        _ => Err(schema_error(
            RefusalReason::MalformedEncoding,
            "namespace freshness optional hash is malformed",
        )),
    }
}

fn read_variable_bytes(item: &CanonicalItem) -> SchemaResult<&[u8]> {
    if item.item_type() != CanonicalItemType::RawBytes {
        return Err(schema_error(
            RefusalReason::WrongTypeOrLength,
            "namespace freshness variable bytes have the wrong type",
        ));
    }
    Ok(item.variable_value_bytes()?)
}

fn read_fixed_signature(
    item: &CanonicalItem,
) -> SchemaResult<[u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH]> {
    if item.item_type() != CanonicalItemType::RawBytes
        || item.canonical_bytes().len() != ML_DSA_65_SIGNATURE_BYTE_LENGTH
    {
        return Err(schema_error(
            RefusalReason::WrongTypeOrLength,
            "namespace freshness signature has the wrong type or length",
        ));
    }
    item.canonical_bytes().try_into().map_err(|_| {
        schema_error(
            RefusalReason::MalformedEncoding,
            "namespace freshness signature is malformed",
        )
    })
}

const fn schema_error(
    refusal_reason: RefusalReason,
    message: &'static str,
) -> FoundationSchemaError {
    FoundationSchemaError {
        refusal_reason,
        message,
    }
}

#[cfg(test)]
mod tests {
    use fips203::{
        ml_kem_768,
        traits::{KeyGen as KemKeyGen, SerDes as KemSerDes},
    };
    use fips204::{
        ml_dsa_65,
        traits::{KeyGen as SignatureKeyGen, SerDes as SignatureSerDes, Signer},
    };

    use super::*;
    use crate::foundation::RosterEntry;

    const SUBJECT_ROSTER_POSITION: usize = 0;

    struct TestFixture {
        action_context_hash: Hash512,
        ceremony_context_hash: Hash512,
        participant_identities: Vec<ParticipantIdentity>,
        roster: Roster,
        roster_hash: Hash512,
        signing_keys: Vec<ml_dsa_65::PrivateKey>,
        storage_recovery_identity: Hash512,
        suite_identifier: Hash512,
    }

    impl TestFixture {
        fn new() -> Self {
            let mut roster_entries =
                Vec::with_capacity(usize::from(FOUNDATION_PROFILE.participant_count));
            let mut signing_keys =
                Vec::with_capacity(usize::from(FOUNDATION_PROFILE.participant_count));
            for roster_position in 0..FOUNDATION_PROFILE.participant_count {
                let mut signing_seed = [0_u8; 32];
                signing_seed[0] =
                    u8::try_from(roster_position + 1).expect("roster position fits u8");
                signing_seed[31] =
                    u8::try_from(FOUNDATION_PROFILE.participant_count - roster_position)
                        .expect("reverse roster position fits u8");
                let (verification_key, signing_key) =
                    ml_dsa_65::KG::keygen_from_seed(&signing_seed);
                let mut mailbox_seed = [0x41_u8; 32];
                mailbox_seed[0] =
                    u8::try_from(roster_position + 1).expect("roster position fits u8");
                let mut mailbox_fallback_seed = [0x92_u8; 32];
                mailbox_fallback_seed[31] =
                    u8::try_from(FOUNDATION_PROFILE.participant_count - roster_position)
                        .expect("reverse roster position fits u8");
                let (mailbox_key, _) =
                    ml_kem_768::KG::keygen_from_seed(mailbox_seed, mailbox_fallback_seed);
                roster_entries.push(RosterEntry {
                    signing_verification_key: verification_key.into_bytes(),
                    mailbox_encapsulation_key: mailbox_key.into_bytes(),
                });
                signing_keys.push(signing_key);
            }
            let roster = Roster::new(roster_entries).expect("test roster");
            let participant_identities = roster
                .entries
                .iter()
                .map(|entry| entry.participant_identity().expect("participant identity"))
                .collect();
            let roster_hash = roster.roster_hash().expect("roster hash");
            Self {
                action_context_hash: hash(0x33),
                ceremony_context_hash: hash(0x22),
                participant_identities,
                roster,
                roster_hash,
                signing_keys,
                storage_recovery_identity: hash(0x44),
                suite_identifier: hash(0x11),
            }
        }

        fn verifier(&self) -> NamespaceFreshnessVerifier {
            NamespaceFreshnessVerifier::new(
                self.suite_identifier,
                self.ceremony_context_hash,
                self.action_context_hash,
                self.subject_identity(),
                self.storage_recovery_identity,
                &self.roster,
            )
            .expect("namespace freshness verifier")
        }

        fn subject_identity(&self) -> ParticipantIdentity {
            self.participant_identities[SUBJECT_ROSTER_POSITION]
        }

        fn sign_vote(
            &self,
            verified_checkpoint: &VerifiedNamespaceFreshnessCheckpoint,
            witness_roster_position: usize,
            signature_seed_byte: u8,
        ) -> Vec<u8> {
            let vote = NamespaceFreshnessVote::new(
                verified_checkpoint.checkpoint_hash(),
                self.participant_identities[witness_roster_position],
                self.suite_identifier,
                self.ceremony_context_hash,
                self.action_context_hash,
                0,
                None,
            );
            let message = vote
                .signature_message(self.roster_hash)
                .expect("vote signature message");
            let signature = self.signing_keys[witness_roster_position]
                .try_sign_with_seed(
                    &[signature_seed_byte; 32],
                    message.as_bytes(),
                    VOTE_SIGNATURE_CONTEXT,
                )
                .expect("namespace freshness vote signature");
            SignedNamespaceFreshnessVote::new(vote, signature)
                .encode()
                .expect("signed namespace freshness vote")
        }
    }

    fn hash(byte: u8) -> Hash512 {
        Hash512::from_bytes([byte; Hash512::BYTE_LENGTH])
    }

    #[test]
    fn checkpoint_canonical_encoding_binds_sequence_and_predecessor() {
        let fixture = TestFixture::new();
        let genesis = NamespaceFreshnessCheckpoint::new(
            fixture.suite_identifier,
            fixture.ceremony_context_hash,
            fixture.action_context_hash,
            fixture.subject_identity(),
            fixture.storage_recovery_identity,
            0,
            hash(0x55),
            None,
        )
        .expect("genesis checkpoint");
        let canonical = genesis.encode().expect("canonical checkpoint");
        assert_eq!(
            NamespaceFreshnessCheckpoint::decode(&canonical, &CanonicalDecodeLimits::default())
                .expect("checkpoint decodes"),
            genesis
        );
        assert_eq!(
            NamespaceFreshnessCheckpoint::new(
                fixture.suite_identifier,
                fixture.ceremony_context_hash,
                fixture.action_context_hash,
                fixture.subject_identity(),
                fixture.storage_recovery_identity,
                0,
                hash(0x55),
                Some(hash(0x66)),
            )
            .err()
            .map(|error| error.refusal_reason),
            Some(RefusalReason::MissingPrerequisite)
        );
        assert_eq!(
            NamespaceFreshnessCheckpoint::new(
                fixture.suite_identifier,
                fixture.ceremony_context_hash,
                fixture.action_context_hash,
                fixture.subject_identity(),
                fixture.storage_recovery_identity,
                1,
                hash(0x55),
                None,
            )
            .err()
            .map(|error| error.refusal_reason),
            Some(RefusalReason::MissingPrerequisite)
        );
    }

    #[test]
    fn certificate_verifies_every_ordered_external_vote() {
        let fixture = TestFixture::new();
        let verifier = fixture.verifier();
        let verified_checkpoint = verifier
            .prepare_checkpoint(0, hash(0x55), None)
            .into_result()
            .expect("verified checkpoint");
        let carriers = (1..=usize::from(FOUNDATION_PROFILE.state_witness_quorum))
            .map(|roster_position| {
                fixture.sign_vote(
                    &verified_checkpoint,
                    roster_position,
                    u8::try_from(roster_position).expect("roster position fits u8"),
                )
            })
            .collect::<Vec<_>>();
        let certificate = verifier
            .verify_certificate(
                &verified_checkpoint,
                &carriers,
                &CanonicalDecodeLimits::default(),
            )
            .into_result()
            .expect("verified certificate");
        assert_eq!(
            certificate.witness_participant_identities(),
            &fixture.participant_identities
                [1..=usize::from(FOUNDATION_PROFILE.state_witness_quorum)]
        );

        let mut invalid_extra = carriers;
        let mut forged = fixture.sign_vote(&verified_checkpoint, 8, 0x88);
        let last_byte = forged.last_mut().expect("signed carrier is nonempty");
        *last_byte ^= 1;
        invalid_extra.push(forged);
        assert_eq!(
            verifier
                .verify_certificate(
                    &verified_checkpoint,
                    &invalid_extra,
                    &CanonicalDecodeLimits::default(),
                )
                .into_result()
                .err(),
            Some(RefusalReason::InvalidSignature)
        );
    }

    #[test]
    fn certificate_rejects_reordered_or_wrong_checkpoint_votes() {
        let fixture = TestFixture::new();
        let verifier = fixture.verifier();
        let first_checkpoint = verifier
            .prepare_checkpoint(0, hash(0x55), None)
            .into_result()
            .expect("first checkpoint");
        let competing_checkpoint = verifier
            .prepare_checkpoint(0, hash(0x56), None)
            .into_result()
            .expect("competing checkpoint");
        let mut reordered = (1..=usize::from(FOUNDATION_PROFILE.state_witness_quorum))
            .map(|roster_position| {
                fixture.sign_vote(
                    &first_checkpoint,
                    roster_position,
                    u8::try_from(roster_position + 16).expect("seed fits u8"),
                )
            })
            .collect::<Vec<_>>();
        reordered.swap(0, 1);
        assert_eq!(
            verifier
                .verify_certificate(
                    &first_checkpoint,
                    &reordered,
                    &CanonicalDecodeLimits::default(),
                )
                .into_result()
                .err(),
            Some(RefusalReason::Equivocation)
        );

        let wrong_checkpoint_carriers = (1..=usize::from(FOUNDATION_PROFILE.state_witness_quorum))
            .map(|roster_position| {
                fixture.sign_vote(
                    &competing_checkpoint,
                    roster_position,
                    u8::try_from(roster_position + 32).expect("seed fits u8"),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            verifier
                .verify_certificate(
                    &first_checkpoint,
                    &wrong_checkpoint_carriers,
                    &CanonicalDecodeLimits::default(),
                )
                .into_result()
                .err(),
            Some(RefusalReason::WrongContext)
        );
    }
}
