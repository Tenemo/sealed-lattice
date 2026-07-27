use crate::foundation::{
    CanonicalCodecError, CanonicalCodecErrorKind, CanonicalItem, CanonicalItemType,
    FOUNDATION_PROFILE, FoundationObjectType, Hash512, ParticipantIdentity, RefusalReason,
    VerifiedBoardApplicationSource, derive_public_randomness_contribution_commitment,
    hash_foundation_tuple_512,
};

const PUBLIC_RANDOMNESS_COMMITMENT_ROOT_DOMAIN: &str =
    "sealed-lattice/setup/public-randomness-commitment-root/v1";
const PUBLIC_RANDOMNESS_SEED_DOMAIN: &str = "sealed-lattice/setup/public-randomness-seed/v1";
const SETUP_PROOF_CONTEXT_HASH_DOMAIN: &str = "sealed-lattice/setup/proof-context/v1";
const PUBLIC_RANDOMNESS_COMPONENT_BYTE_LENGTH: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::bgv) struct VerifiedSetupVerificationContext {
    protocol_version: u16,
    suite_identifier: Hash512,
    manifest_hash: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    roster_hash: Hash512,
}

impl VerifiedSetupVerificationContext {
    #[cfg(all(test, not(target_arch = "wasm32")))]
    pub(in crate::bgv) const fn for_exact_same_secret_evidence(
        suite_identifier: Hash512,
        manifest_hash: Hash512,
        ceremony_context_hash: Hash512,
        action_context_hash: Hash512,
        roster_hash: Hash512,
    ) -> Self {
        Self {
            protocol_version: FOUNDATION_PROFILE.protocol_version,
            suite_identifier,
            manifest_hash,
            ceremony_context_hash,
            action_context_hash,
            roster_hash,
        }
    }

    pub(in crate::bgv) const fn protocol_version(self) -> u16 {
        self.protocol_version
    }

    pub(in crate::bgv) const fn suite_identifier(self) -> Hash512 {
        self.suite_identifier
    }

    pub(in crate::bgv) const fn manifest_hash(self) -> Hash512 {
        self.manifest_hash
    }

    pub(in crate::bgv) const fn ceremony_context_hash(self) -> Hash512 {
        self.ceremony_context_hash
    }

    pub(in crate::bgv) const fn action_context_hash(self) -> Hash512 {
        self.action_context_hash
    }

    pub(in crate::bgv) const fn roster_hash(self) -> Hash512 {
        self.roster_hash
    }
}

/// Positive terminal for the complete roster's canonical-board randomness
/// transcript. It can only be built from board-verifier-owned application
/// sources; caller-provided carrier descriptions or seed bytes never enter the
/// constructor.
pub(in crate::bgv) struct VerifiedPublicRandomness {
    context: VerifiedSetupVerificationContext,
    ordered_participant_identities: Box<[ParticipantIdentity]>,
    ordered_setup_intent_object_hashes: Box<[Hash512]>,
    ordered_action_randomness_commitments: Box<[Hash512]>,
    ordered_commitment_object_hashes: Box<[Hash512]>,
    ordered_reveal_object_hashes: Box<[Hash512]>,
    public_setup_seed: Hash512,
    setup_proof_context_hash: Hash512,
}

impl VerifiedPublicRandomness {
    pub(in crate::bgv) const fn context(&self) -> VerifiedSetupVerificationContext {
        self.context
    }

    pub(in crate::bgv) fn ordered_participant_identities(&self) -> &[ParticipantIdentity] {
        &self.ordered_participant_identities
    }

    pub(in crate::bgv) fn ordered_setup_intent_object_hashes(&self) -> &[Hash512] {
        &self.ordered_setup_intent_object_hashes
    }

    pub(in crate::bgv) fn ordered_action_randomness_commitments(&self) -> &[Hash512] {
        &self.ordered_action_randomness_commitments
    }

    pub(in crate::bgv) fn ordered_commitment_object_hashes(&self) -> &[Hash512] {
        &self.ordered_commitment_object_hashes
    }

    pub(in crate::bgv) fn ordered_reveal_object_hashes(&self) -> &[Hash512] {
        &self.ordered_reveal_object_hashes
    }

    pub(in crate::bgv) const fn public_setup_seed(&self) -> Hash512 {
        self.public_setup_seed
    }

    pub(in crate::bgv) const fn setup_proof_context_hash(&self) -> Hash512 {
        self.setup_proof_context_hash
    }

    #[cfg(test)]
    pub(in crate::bgv) fn from_test_values(
        suite_identifier: Hash512,
        manifest_hash: Hash512,
        ceremony_context_hash: Hash512,
        action_context_hash: Hash512,
        roster_hash: Hash512,
        ordered_participant_identities: Vec<ParticipantIdentity>,
        public_setup_seed: Hash512,
    ) -> Self {
        let context = VerifiedSetupVerificationContext {
            protocol_version: FOUNDATION_PROFILE.protocol_version,
            suite_identifier,
            manifest_hash,
            ceremony_context_hash,
            action_context_hash,
            roster_hash,
        };
        let participant_count = ordered_participant_identities.len();
        let setup_proof_context_hash =
            derive_setup_proof_context_hash(context, public_setup_seed).unwrap();
        Self {
            context,
            ordered_participant_identities: ordered_participant_identities.into_boxed_slice(),
            ordered_setup_intent_object_hashes: vec![
                Hash512::from_bytes([0x41; 64]);
                participant_count
            ]
            .into_boxed_slice(),
            ordered_action_randomness_commitments: vec![
                Hash512::from_bytes([0x42; 64]);
                participant_count
            ]
            .into_boxed_slice(),
            ordered_commitment_object_hashes: vec![
                Hash512::from_bytes([0x43; 64]);
                participant_count
            ]
            .into_boxed_slice(),
            ordered_reveal_object_hashes: vec![Hash512::from_bytes([0x44; 64]); participant_count]
                .into_boxed_slice(),
            public_setup_seed,
            setup_proof_context_hash,
        }
    }

    #[cfg(all(test, not(target_arch = "wasm32")))]
    pub(in crate::bgv) fn from_exact_same_secret_evidence_values(
        context: VerifiedSetupVerificationContext,
        ordered_participant_identities: Vec<ParticipantIdentity>,
        ordered_action_randomness_commitments: Vec<Hash512>,
        public_setup_seed: Hash512,
    ) -> Result<Self, RefusalReason> {
        if ordered_participant_identities.len() != usize::from(FOUNDATION_PROFILE.participant_count)
            || ordered_action_randomness_commitments.len() != ordered_participant_identities.len()
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let participant_count = ordered_participant_identities.len();
        let setup_proof_context_hash = derive_setup_proof_context_hash(context, public_setup_seed)?;
        let distinct_hashes = |domain: u8| {
            (0..participant_count)
                .map(|participant_index| {
                    let mut bytes = [domain; Hash512::BYTE_LENGTH];
                    bytes[..8].copy_from_slice(&(participant_index as u64).to_le_bytes());
                    Hash512::from_bytes(bytes)
                })
                .collect::<Vec<_>>()
                .into_boxed_slice()
        };
        Ok(Self {
            context,
            ordered_participant_identities: ordered_participant_identities.into_boxed_slice(),
            ordered_setup_intent_object_hashes: distinct_hashes(0x41),
            ordered_action_randomness_commitments: ordered_action_randomness_commitments
                .into_boxed_slice(),
            ordered_commitment_object_hashes: distinct_hashes(0x43),
            ordered_reveal_object_hashes: distinct_hashes(0x44),
            public_setup_seed,
            setup_proof_context_hash,
        })
    }
}

pub(in crate::bgv) fn verify_public_randomness_board_sources(
    setup_intent_sources: Vec<VerifiedBoardApplicationSource>,
    commitment_sources: Vec<VerifiedBoardApplicationSource>,
    reveal_sources: Vec<VerifiedBoardApplicationSource>,
) -> Result<VerifiedPublicRandomness, RefusalReason> {
    let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
    if setup_intent_sources.len() != participant_count
        || commitment_sources.len() != participant_count
        || reveal_sources.len() != participant_count
    {
        return Err(RefusalReason::WrongTypeOrLength);
    }

    let first_setup_intent = &setup_intent_sources[0];
    let context = VerifiedSetupVerificationContext {
        protocol_version: FOUNDATION_PROFILE.protocol_version,
        suite_identifier: first_setup_intent.suite_identifier(),
        manifest_hash: first_setup_intent.manifest_hash(),
        ceremony_context_hash: first_setup_intent.ceremony_context_hash(),
        action_context_hash: first_setup_intent.action_context_hash(),
        roster_hash: first_setup_intent.roster_hash(),
    };

    let mut ordered_setup_intent_object_hashes = Vec::with_capacity(participant_count);
    let mut ordered_action_randomness_commitments = Vec::with_capacity(participant_count);
    for (roster_position, source) in setup_intent_sources.iter().enumerate() {
        require_source_coordinate(
            source,
            context,
            FoundationObjectType::SetupIntent,
            roster_position,
            None,
        )?;
        let payload = source.setup_intent_payload()?;
        ordered_setup_intent_object_hashes.push(source.object_hash());
        ordered_action_randomness_commitments.push(payload.action_randomness_commitment());
    }

    let mut ordered_commitment_object_hashes = Vec::with_capacity(participant_count);
    let mut ordered_contribution_commitments = Vec::with_capacity(participant_count);
    let mut ordered_participant_identities = Vec::with_capacity(participant_count);
    for (roster_position, source) in commitment_sources.iter().enumerate() {
        let expected_participant_identity = setup_intent_sources[roster_position]
            .producer_participant_identity()
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        require_source_coordinate(
            source,
            context,
            FoundationObjectType::PublicRandomnessCommitment,
            roster_position,
            Some(expected_participant_identity),
        )?;
        let payload = source.public_randomness_commitment_payload()?;
        if payload.ordered_setup_intent_object_hashes()
            != ordered_setup_intent_object_hashes.as_slice()
        {
            return Err(RefusalReason::WrongHashOrRoot);
        }
        ordered_commitment_object_hashes.push(source.object_hash());
        ordered_contribution_commitments.push(payload.contribution_commitment());
        ordered_participant_identities.push(expected_participant_identity);
    }

    let randomness_commitment_root =
        derive_randomness_commitment_root(context, &ordered_commitment_object_hashes)?;
    let mut ordered_reveal_object_hashes = Vec::with_capacity(participant_count);
    let mut ordered_contributions_and_salts = Vec::with_capacity(participant_count);
    for (roster_position, source) in reveal_sources.iter().enumerate() {
        let participant_identity = ordered_participant_identities[roster_position];
        require_source_coordinate(
            source,
            context,
            FoundationObjectType::PublicRandomnessReveal,
            roster_position,
            Some(participant_identity),
        )?;
        let payload = source.public_randomness_reveal_payload()?;
        if payload.contribution_commitment_object_hash()
            != ordered_commitment_object_hashes[roster_position]
        {
            return Err(RefusalReason::WrongHashOrRoot);
        }
        let contribution_and_salt = payload.contribution_and_salt();
        let contribution = <[u8; PUBLIC_RANDOMNESS_COMPONENT_BYTE_LENGTH]>::try_from(
            &contribution_and_salt[..PUBLIC_RANDOMNESS_COMPONENT_BYTE_LENGTH],
        )
        .map_err(|_| RefusalReason::WrongTypeOrLength)?;
        let salt = <[u8; PUBLIC_RANDOMNESS_COMPONENT_BYTE_LENGTH]>::try_from(
            &contribution_and_salt[PUBLIC_RANDOMNESS_COMPONENT_BYTE_LENGTH..],
        )
        .map_err(|_| RefusalReason::WrongTypeOrLength)?;
        let expected_commitment = derive_public_randomness_contribution_commitment(
            context.suite_identifier,
            context.ceremony_context_hash,
            context.action_context_hash,
            participant_identity,
            contribution,
            salt,
        )
        .map_err(|error| error.refusal_reason)?;
        if expected_commitment != ordered_contribution_commitments[roster_position] {
            return Err(RefusalReason::WrongHashOrRoot);
        }
        ordered_reveal_object_hashes.push(source.object_hash());
        ordered_contributions_and_salts.push(contribution_and_salt);
    }

    let public_setup_seed = derive_public_setup_seed(
        context,
        randomness_commitment_root,
        &ordered_contributions_and_salts,
    )?;
    let setup_proof_context_hash = derive_setup_proof_context_hash(context, public_setup_seed)?;
    Ok(VerifiedPublicRandomness {
        context,
        ordered_participant_identities: ordered_participant_identities.into_boxed_slice(),
        ordered_setup_intent_object_hashes: ordered_setup_intent_object_hashes.into_boxed_slice(),
        ordered_action_randomness_commitments: ordered_action_randomness_commitments
            .into_boxed_slice(),
        ordered_commitment_object_hashes: ordered_commitment_object_hashes.into_boxed_slice(),
        ordered_reveal_object_hashes: ordered_reveal_object_hashes.into_boxed_slice(),
        public_setup_seed,
        setup_proof_context_hash,
    })
}

fn require_source_coordinate(
    source: &VerifiedBoardApplicationSource,
    context: VerifiedSetupVerificationContext,
    expected_object_type: FoundationObjectType,
    expected_roster_position: usize,
    expected_participant_identity: Option<ParticipantIdentity>,
) -> Result<(), RefusalReason> {
    let expected_roster_position = u16::try_from(expected_roster_position)
        .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    let producer_participant_identity = source
        .producer_participant_identity()
        .ok_or(RefusalReason::WrongTypeOrLength)?;
    if source.suite_identifier() != context.suite_identifier
        || source.manifest_hash() != context.manifest_hash
        || source.ceremony_context_hash() != context.ceremony_context_hash
        || source.action_context_hash() != context.action_context_hash
        || source.roster_hash() != context.roster_hash
        || source.object_type() != expected_object_type
        || source.producer_roster_position() != Some(expected_roster_position)
        || source.producer_sequence() != 0
        || expected_participant_identity
            .is_some_and(|expected| expected != producer_participant_identity)
    {
        return Err(RefusalReason::WrongContext);
    }
    Ok(())
}

fn derive_randomness_commitment_root(
    context: VerifiedSetupVerificationContext,
    ordered_commitment_object_hashes: &[Hash512],
) -> Result<Hash512, RefusalReason> {
    let commitment_items = ordered_commitment_object_hashes
        .iter()
        .map(|object_hash| CanonicalItem::hash512(object_hash.into_bytes()))
        .collect::<Vec<_>>();
    hash_foundation_tuple_512(
        PUBLIC_RANDOMNESS_COMMITMENT_ROOT_DOMAIN,
        &[
            CanonicalItem::hash512(context.suite_identifier.into_bytes()),
            CanonicalItem::hash512(context.ceremony_context_hash.into_bytes()),
            CanonicalItem::hash512(context.action_context_hash.into_bytes()),
            CanonicalItem::hash512(context.roster_hash.into_bytes()),
            CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &commitment_items)
                .map_err(canonical_codec_refusal)?,
        ],
    )
    .map_err(canonical_codec_refusal)
}

fn derive_public_setup_seed(
    context: VerifiedSetupVerificationContext,
    randomness_commitment_root: Hash512,
    ordered_contributions_and_salts: &[[u8; Hash512::BYTE_LENGTH]],
) -> Result<Hash512, RefusalReason> {
    let reveal_items = ordered_contributions_and_salts
        .iter()
        .map(|contribution_and_salt| {
            CanonicalItem::variable_bytes(contribution_and_salt).map_err(canonical_codec_refusal)
        })
        .collect::<Result<Vec<_>, _>>()?;
    hash_foundation_tuple_512(
        PUBLIC_RANDOMNESS_SEED_DOMAIN,
        &[
            CanonicalItem::hash512(context.suite_identifier.into_bytes()),
            CanonicalItem::hash512(context.ceremony_context_hash.into_bytes()),
            CanonicalItem::hash512(context.action_context_hash.into_bytes()),
            CanonicalItem::hash512(randomness_commitment_root.into_bytes()),
            CanonicalItem::homogeneous_list(CanonicalItemType::RawBytes, &reveal_items)
                .map_err(canonical_codec_refusal)?,
        ],
    )
    .map_err(canonical_codec_refusal)
}

fn derive_setup_proof_context_hash(
    context: VerifiedSetupVerificationContext,
    public_setup_seed: Hash512,
) -> Result<Hash512, RefusalReason> {
    hash_foundation_tuple_512(
        SETUP_PROOF_CONTEXT_HASH_DOMAIN,
        &[
            CanonicalItem::unsigned16(context.protocol_version),
            CanonicalItem::hash512(context.suite_identifier.into_bytes()),
            CanonicalItem::hash512(context.ceremony_context_hash.into_bytes()),
            CanonicalItem::hash512(context.action_context_hash.into_bytes()),
            CanonicalItem::hash512(context.manifest_hash.into_bytes()),
            CanonicalItem::hash512(context.roster_hash.into_bytes()),
            CanonicalItem::hash512(public_setup_seed.into_bytes()),
        ],
    )
    .map_err(canonical_codec_refusal)
}

fn canonical_codec_refusal(error: CanonicalCodecError) -> RefusalReason {
    if error.kind == CanonicalCodecErrorKind::LimitExceeded {
        RefusalReason::OutsideSupportedProfile
    } else {
        RefusalReason::MalformedEncoding
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
    use crate::foundation::{
        CanonicalBoardLimits, CanonicalBoardVerifier, CanonicalDecodeLimits, CanonicalTuple,
        ObjectEnvelope, Roster, RosterEntry, SignedCarrier, signature_message,
    };

    const OBJECT_SIGNATURE_CONTEXT: &[u8] = b"sealed-lattice/object-signature/v1";

    struct RandomnessBoardFixture {
        context: VerifiedSetupVerificationContext,
        roster: Roster,
        roster_hash: Hash512,
        participant_identities: Vec<ParticipantIdentity>,
        signing_keys: Vec<ml_dsa_65::PrivateKey>,
    }

    impl RandomnessBoardFixture {
        fn new() -> Self {
            let mut entries = Vec::with_capacity(usize::from(FOUNDATION_PROFILE.participant_count));
            let mut signing_keys =
                Vec::with_capacity(usize::from(FOUNDATION_PROFILE.participant_count));
            for roster_position in 0..FOUNDATION_PROFILE.participant_count {
                let mut signing_seed = [0_u8; 32];
                signing_seed[0] = u8::try_from(roster_position + 1).unwrap();
                signing_seed[31] =
                    u8::try_from(FOUNDATION_PROFILE.participant_count - roster_position).unwrap();
                let (verification_key, signing_key) =
                    ml_dsa_65::KG::keygen_from_seed(&signing_seed);
                let mut mailbox_seed = [0x41_u8; 32];
                mailbox_seed[0] = u8::try_from(roster_position + 1).unwrap();
                let mut mailbox_fallback_seed = [0x92_u8; 32];
                mailbox_fallback_seed[31] =
                    u8::try_from(FOUNDATION_PROFILE.participant_count - roster_position).unwrap();
                let (mailbox_key, _) =
                    ml_kem_768::KG::keygen_from_seed(mailbox_seed, mailbox_fallback_seed);
                entries.push(RosterEntry {
                    roster_position,
                    signing_verification_key: verification_key.into_bytes(),
                    mailbox_encapsulation_key: mailbox_key.into_bytes(),
                });
                signing_keys.push(signing_key);
            }
            let roster = Roster::new(entries).expect("selected test roster");
            let roster_hash = roster.roster_hash().expect("test roster hash");
            let participant_identities = roster
                .entries
                .iter()
                .map(|entry| entry.participant_identity().expect("participant identity"))
                .collect();
            Self {
                context: VerifiedSetupVerificationContext {
                    protocol_version: FOUNDATION_PROFILE.protocol_version,
                    suite_identifier: Hash512::from_bytes([0x11; 64]),
                    manifest_hash: Hash512::from_bytes([0x18; 64]),
                    ceremony_context_hash: Hash512::from_bytes([0x22; 64]),
                    action_context_hash: Hash512::from_bytes([0x33; 64]),
                    roster_hash,
                },
                roster,
                roster_hash,
                participant_identities,
                signing_keys,
            }
        }

        fn envelope(
            &self,
            roster_position: usize,
            object_type: FoundationObjectType,
            prerequisites: Vec<Hash512>,
            payload_bytes: Vec<u8>,
        ) -> ObjectEnvelope {
            ObjectEnvelope {
                suite_id: self.context.suite_identifier,
                object_type,
                ceremony_context_hash: self.context.ceremony_context_hash,
                action_context_hash: self.context.action_context_hash,
                producer_participant_id: Some(self.participant_identities[roster_position]),
                producer_sequence: 0,
                ordered_prerequisite_hashes: prerequisites,
                payload_bytes,
            }
        }

        fn sign(
            &self,
            roster_position: usize,
            envelope: ObjectEnvelope,
            signature_seed_byte: u8,
        ) -> Vec<u8> {
            let message =
                signature_message(&envelope, self.roster_hash).expect("signature message derives");
            let signature = self.signing_keys[roster_position]
                .try_sign_with_seed(
                    &[signature_seed_byte; 32],
                    message.as_bytes(),
                    OBJECT_SIGNATURE_CONTEXT,
                )
                .expect("test carrier signs");
            SignedCarrier {
                envelope,
                signature,
            }
            .encode()
            .expect("signed carrier encodes")
        }

        fn verified_sources(
            &self,
            corrupted_commitment_position: Option<usize>,
        ) -> (
            Vec<VerifiedBoardApplicationSource>,
            Vec<VerifiedBoardApplicationSource>,
            Vec<VerifiedBoardApplicationSource>,
            Vec<[u8; Hash512::BYTE_LENGTH]>,
        ) {
            let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
            let setup_intent_carriers = (0..participant_count)
                .map(|roster_position| {
                    let payload = CanonicalTuple::new(
                        0x1200,
                        1,
                        vec![CanonicalItem::hash512(
                            [u8::try_from(roster_position + 1).unwrap(); 64],
                        )],
                    )
                    .encode()
                    .unwrap();
                    self.sign(
                        roster_position,
                        self.envelope(
                            roster_position,
                            FoundationObjectType::SetupIntent,
                            Vec::new(),
                            payload,
                        ),
                        0x21,
                    )
                })
                .collect::<Vec<_>>();
            let setup_intent_hashes = setup_intent_carriers
                .iter()
                .map(|carrier_bytes| {
                    SignedCarrier::decode(carrier_bytes, &CanonicalDecodeLimits::default())
                        .unwrap()
                        .envelope
                        .object_hash()
                        .unwrap()
                })
                .collect::<Vec<_>>();

            let contributions_and_salts = (0..participant_count)
                .map(|roster_position| {
                    let mut bytes = [0_u8; Hash512::BYTE_LENGTH];
                    for (byte_ordinal, byte) in bytes.iter_mut().enumerate() {
                        *byte =
                            u8::try_from((roster_position * 37 + byte_ordinal * 11) % 251).unwrap();
                    }
                    bytes
                })
                .collect::<Vec<_>>();
            let commitment_carriers = (0..participant_count)
                .map(|roster_position| {
                    let contribution = contributions_and_salts[roster_position][..32]
                        .try_into()
                        .unwrap();
                    let salt = contributions_and_salts[roster_position][32..]
                        .try_into()
                        .unwrap();
                    let mut contribution_commitment =
                        derive_public_randomness_contribution_commitment(
                            self.context.suite_identifier,
                            self.context.ceremony_context_hash,
                            self.context.action_context_hash,
                            self.participant_identities[roster_position],
                            contribution,
                            salt,
                        )
                        .unwrap();
                    if corrupted_commitment_position == Some(roster_position) {
                        let mut bytes = contribution_commitment.into_bytes();
                        bytes[17] ^= 1;
                        contribution_commitment = Hash512::from_bytes(bytes);
                    }
                    let payload = CanonicalTuple::new(
                        0x1201,
                        1,
                        vec![CanonicalItem::hash512(contribution_commitment.into_bytes())],
                    )
                    .encode()
                    .unwrap();
                    self.sign(
                        roster_position,
                        self.envelope(
                            roster_position,
                            FoundationObjectType::PublicRandomnessCommitment,
                            setup_intent_hashes.clone(),
                            payload,
                        ),
                        0x42,
                    )
                })
                .collect::<Vec<_>>();
            let commitment_hashes = commitment_carriers
                .iter()
                .map(|carrier_bytes| {
                    SignedCarrier::decode(carrier_bytes, &CanonicalDecodeLimits::default())
                        .unwrap()
                        .envelope
                        .object_hash()
                        .unwrap()
                })
                .collect::<Vec<_>>();
            let reveal_carriers = (0..participant_count)
                .map(|roster_position| {
                    let payload = CanonicalTuple::new(
                        0x1202,
                        1,
                        vec![
                            CanonicalItem::hash512(commitment_hashes[roster_position].into_bytes()),
                            CanonicalItem::fixed_bytes(contributions_and_salts[roster_position])
                                .unwrap(),
                        ],
                    )
                    .encode()
                    .unwrap();
                    self.sign(
                        roster_position,
                        self.envelope(
                            roster_position,
                            FoundationObjectType::PublicRandomnessReveal,
                            Vec::new(),
                            payload,
                        ),
                        0x63,
                    )
                })
                .collect::<Vec<_>>();

            let mut carriers = setup_intent_carriers;
            carriers.extend(commitment_carriers);
            carriers.extend(reveal_carriers);
            let mut verifier = CanonicalBoardVerifier::new(
                self.context.suite_identifier,
                self.context.ceremony_context_hash,
                self.context.action_context_hash,
                &self.roster,
                CanonicalBoardLimits {
                    maximum_ballot_attempts_per_participant: 4,
                    maximum_candidate_packages_per_action: 20,
                    maximum_retained_canonical_carrier_byte_length: 8 * 1024 * 1024,
                    maximum_unordered_carriers_per_batch: 64,
                    maximum_retained_transcript_objects: 64,
                },
                CanonicalDecodeLimits::default(),
            )
            .expect("board verifier");
            let batch = verifier
                .verify_unordered_carriers(&carriers)
                .into_result()
                .expect("complete randomness board verifies");
            let mut setup_intents = Vec::new();
            let mut commitments = Vec::new();
            let mut reveals = Vec::new();
            for object in batch.objects() {
                let source = VerifiedBoardApplicationSource::from_verifier(
                    &verifier,
                    self.context.manifest_hash,
                    object.clone(),
                );
                match source.object_type() {
                    FoundationObjectType::SetupIntent => setup_intents.push(source),
                    FoundationObjectType::PublicRandomnessCommitment => commitments.push(source),
                    FoundationObjectType::PublicRandomnessReveal => reveals.push(source),
                    _ => unreachable!(),
                }
            }
            let by_roster_position = |sources: &mut Vec<VerifiedBoardApplicationSource>| {
                sources.sort_by_key(VerifiedBoardApplicationSource::producer_roster_position)
            };
            by_roster_position(&mut setup_intents);
            by_roster_position(&mut commitments);
            by_roster_position(&mut reveals);
            (setup_intents, commitments, reveals, contributions_and_salts)
        }
    }

    #[test]
    fn complete_authenticated_roster_derives_one_seed_and_exact_object_catalogs() {
        let fixture = RandomnessBoardFixture::new();
        let (setup_intents, commitments, reveals, contributions_and_salts) =
            fixture.verified_sources(None);
        let expected_setup_hashes = setup_intents
            .iter()
            .map(VerifiedBoardApplicationSource::object_hash)
            .collect::<Vec<_>>();
        let expected_commitment_hashes = commitments
            .iter()
            .map(VerifiedBoardApplicationSource::object_hash)
            .collect::<Vec<_>>();
        let expected_action_randomness_commitments = (0..FOUNDATION_PROFILE.participant_count)
            .map(|roster_position| {
                Hash512::from_bytes([u8::try_from(roster_position + 1).unwrap(); 64])
            })
            .collect::<Vec<_>>();
        let expected_reveal_hashes = reveals
            .iter()
            .map(VerifiedBoardApplicationSource::object_hash)
            .collect::<Vec<_>>();
        let terminal = verify_public_randomness_board_sources(setup_intents, commitments, reveals)
            .expect("authenticated randomness terminal");
        assert_eq!(terminal.context(), fixture.context);
        assert_eq!(
            terminal.ordered_participant_identities(),
            fixture.participant_identities
        );
        assert_eq!(
            terminal.ordered_setup_intent_object_hashes(),
            expected_setup_hashes
        );
        assert_eq!(
            terminal.ordered_action_randomness_commitments(),
            expected_action_randomness_commitments
        );
        assert_eq!(
            terminal.ordered_commitment_object_hashes(),
            expected_commitment_hashes
        );
        assert_eq!(
            terminal.ordered_reveal_object_hashes(),
            expected_reveal_hashes
        );
        let expected_root =
            derive_randomness_commitment_root(fixture.context, &expected_commitment_hashes)
                .unwrap();
        let expected_public_setup_seed =
            derive_public_setup_seed(fixture.context, expected_root, &contributions_and_salts)
                .unwrap();
        assert_eq!(terminal.public_setup_seed(), expected_public_setup_seed);
        assert_eq!(
            terminal.setup_proof_context_hash(),
            derive_setup_proof_context_hash(fixture.context, expected_public_setup_seed).unwrap()
        );
    }

    #[test]
    fn randomness_terminal_rejects_missing_reordered_wrong_family_and_mismatched_opening() {
        let fixture = RandomnessBoardFixture::new();
        let (setup_intents, commitments, reveals, _) = fixture.verified_sources(None);

        let mut missing_reveals = reveals.clone();
        missing_reveals.pop();
        let Err(missing_reveal_error) = verify_public_randomness_board_sources(
            setup_intents.clone(),
            commitments.clone(),
            missing_reveals,
        ) else {
            panic!("missing reveal must refuse");
        };
        assert_eq!(missing_reveal_error, RefusalReason::WrongTypeOrLength);

        let mut reordered_commitments = commitments.clone();
        reordered_commitments.swap(0, 9);
        let Err(reordered_commitment_error) = verify_public_randomness_board_sources(
            setup_intents.clone(),
            reordered_commitments,
            reveals.clone(),
        ) else {
            panic!("reordered commitments must refuse");
        };
        assert_eq!(reordered_commitment_error, RefusalReason::WrongContext);

        let mut wrong_family_commitments = commitments;
        wrong_family_commitments[4] = reveals[4].clone();
        let Err(wrong_family_error) = verify_public_randomness_board_sources(
            setup_intents,
            wrong_family_commitments,
            reveals,
        ) else {
            panic!("wrong family must refuse");
        };
        assert_eq!(wrong_family_error, RefusalReason::WrongContext);

        let (setup_intents, commitments, reveals, _) = fixture.verified_sources(Some(7));
        let Err(commitment_opening_error) =
            verify_public_randomness_board_sources(setup_intents, commitments, reveals)
        else {
            panic!("commitment-opening mismatch must refuse");
        };
        assert_eq!(commitment_opening_error, RefusalReason::WrongHashOrRoot);
    }
}
