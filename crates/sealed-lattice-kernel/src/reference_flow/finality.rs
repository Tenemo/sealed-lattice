use crate::foundation::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalTuple, Hash512, RefusalReason,
};

use super::{
    ProtocolRefusal, ProtocolResult,
    canonical::{
        read_fixed_bytes, read_hash, read_u16, read_u64, read_variable_bytes, require_tuple,
    },
    field::{CORRUPTION_BOUND, PARTICIPANT_COUNT},
    protocol_oracle::protocol_oracle_512,
    roster_signature::{
        ROSTER_SIGNATURE_BYTE_LENGTH, RosterSignature, RosterSignatureRandomizer, RosterSigningKey,
        RosterVerificationKey, sign_roster_message, verify_roster_message,
    },
};

const COMPUTATION_TARGET_SCHEMA_IDENTIFIER: u16 = 0x0220;
const FINALITY_SIGNATURE_BODY_SCHEMA_IDENTIFIER: u16 = 0x0221;
const FINALITY_SIGNATURE_CARRIER_SCHEMA_IDENTIFIER: u16 = 0x0222;
const FINALITY_CERTIFICATE_SCHEMA_IDENTIFIER: u16 = 0x0223;
const FINALITY_SCHEMA_VERSION: u16 = 1;
const FINALITY_SIGNATURE_CONTEXT: &[u8] = b"sealed-lattice/direct-finality/v1";
pub(crate) const TOLERATED_INDEPENDENT_STATE_FAILURE_COUNT: usize = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FinalityPolicy {
    pub(crate) roster_count: u16,
    pub(crate) corruption_bound: u16,
    pub(crate) independent_state_failure_count: u16,
    pub(crate) quorum: u16,
}

impl FinalityPolicy {
    pub(crate) fn completion_profile() -> Self {
        let quorum = minimal_direct_finality_quorum(
            PARTICIPANT_COUNT,
            CORRUPTION_BOUND,
            TOLERATED_INDEPENDENT_STATE_FAILURE_COUNT,
        )
        .expect("the completion profile has a direct finality quorum");
        Self {
            roster_count: PARTICIPANT_COUNT as u16,
            corruption_bound: CORRUPTION_BOUND as u16,
            independent_state_failure_count: TOLERATED_INDEPENDENT_STATE_FAILURE_COUNT as u16,
            quorum: quorum as u16,
        }
    }

    fn verify(self) -> ProtocolResult<()> {
        let expected_quorum = minimal_direct_finality_quorum(
            usize::from(self.roster_count),
            usize::from(self.corruption_bound),
            usize::from(self.independent_state_failure_count),
        )
        .ok_or_else(|| {
            ProtocolRefusal::new(
                RefusalReason::OutsideSupportedProfile,
                "finality policy has no safe direct quorum",
            )
        })?;
        if usize::from(self.quorum) != expected_quorum {
            return Err(ProtocolRefusal::new(
                RefusalReason::WrongContext,
                "finality quorum is not the minimal safe direct quorum",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ComputationTarget {
    pub(crate) suite_identity: Hash512,
    pub(crate) build_identity: Hash512,
    pub(crate) action_identity: Hash512,
    pub(crate) predecessor_identity: Hash512,
    pub(crate) roster_identity: Hash512,
    pub(crate) circuit_identity: Hash512,
    pub(crate) compiler_identity: Hash512,
    pub(crate) output_schema_identity: Hash512,
    pub(crate) preparation_terminal_identity: Hash512,
    pub(crate) declaration_inventory_identity: Hash512,
    pub(crate) source_inventory_identity: Hash512,
    pub(crate) selected_source_identity: Hash512,
    pub(crate) public_input_identity: Hash512,
    pub(crate) activation_policy_identity: Hash512,
    pub(crate) finality_policy: FinalityPolicy,
    pub(crate) output_bit_count: u16,
    pub(crate) action_ordinal: u64,
    pub(crate) output_ordinal: u64,
}

impl ComputationTarget {
    pub(crate) fn encode(&self) -> ProtocolResult<Vec<u8>> {
        self.finality_policy.verify()?;
        if usize::from(self.finality_policy.roster_count) != PARTICIPANT_COUNT
            || usize::from(self.finality_policy.corruption_bound) != CORRUPTION_BOUND
            || self.output_bit_count != 1
        {
            return Err(ProtocolRefusal::new(
                RefusalReason::OutsideSupportedProfile,
                "computation target is outside the vertical completion profile",
            ));
        }
        Ok(CanonicalTuple::new(
            COMPUTATION_TARGET_SCHEMA_IDENTIFIER,
            FINALITY_SCHEMA_VERSION,
            vec![
                hash_item(self.suite_identity),
                hash_item(self.build_identity),
                hash_item(self.action_identity),
                hash_item(self.predecessor_identity),
                hash_item(self.roster_identity),
                hash_item(self.circuit_identity),
                hash_item(self.compiler_identity),
                hash_item(self.output_schema_identity),
                hash_item(self.preparation_terminal_identity),
                hash_item(self.declaration_inventory_identity),
                hash_item(self.source_inventory_identity),
                hash_item(self.selected_source_identity),
                hash_item(self.public_input_identity),
                hash_item(self.activation_policy_identity),
                CanonicalItem::unsigned16(self.finality_policy.roster_count),
                CanonicalItem::unsigned16(self.finality_policy.corruption_bound),
                CanonicalItem::unsigned16(self.finality_policy.independent_state_failure_count),
                CanonicalItem::unsigned16(self.finality_policy.quorum),
                CanonicalItem::unsigned16(self.output_bit_count),
                CanonicalItem::unsigned64(self.action_ordinal),
                CanonicalItem::unsigned64(self.output_ordinal),
            ],
        )
        .encode()?)
    }

    pub(crate) fn identity(&self) -> ProtocolResult<Hash512> {
        protocol_oracle_512(
            "sealed-lattice/protocol/computation-target/v1",
            &[CanonicalItem::variable_bytes(self.encode()?)?],
        )
    }

    pub(crate) fn decode(bytes: &[u8]) -> ProtocolResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, &CanonicalDecodeLimits::default())?;
        require_tuple(
            &tuple,
            COMPUTATION_TARGET_SCHEMA_IDENTIFIER,
            FINALITY_SCHEMA_VERSION,
            21,
        )?;
        let target = Self {
            suite_identity: read_hash(&tuple.items[0])?,
            build_identity: read_hash(&tuple.items[1])?,
            action_identity: read_hash(&tuple.items[2])?,
            predecessor_identity: read_hash(&tuple.items[3])?,
            roster_identity: read_hash(&tuple.items[4])?,
            circuit_identity: read_hash(&tuple.items[5])?,
            compiler_identity: read_hash(&tuple.items[6])?,
            output_schema_identity: read_hash(&tuple.items[7])?,
            preparation_terminal_identity: read_hash(&tuple.items[8])?,
            declaration_inventory_identity: read_hash(&tuple.items[9])?,
            source_inventory_identity: read_hash(&tuple.items[10])?,
            selected_source_identity: read_hash(&tuple.items[11])?,
            public_input_identity: read_hash(&tuple.items[12])?,
            activation_policy_identity: read_hash(&tuple.items[13])?,
            finality_policy: FinalityPolicy {
                roster_count: read_u16(&tuple.items[14])?,
                corruption_bound: read_u16(&tuple.items[15])?,
                independent_state_failure_count: read_u16(&tuple.items[16])?,
                quorum: read_u16(&tuple.items[17])?,
            },
            output_bit_count: read_u16(&tuple.items[18])?,
            action_ordinal: read_u64(&tuple.items[19])?,
            output_ordinal: read_u64(&tuple.items[20])?,
        };
        target.encode()?;
        Ok(target)
    }
}

pub(crate) struct FinalitySignature {
    target_identity: Hash512,
    signer_position: u16,
    body_bytes: Vec<u8>,
    signature_bytes: RosterSignature,
}

impl core::fmt::Debug for FinalitySignature {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("FinalitySignature")
            .field("target_identity", &self.target_identity)
            .field("signer_position", &self.signer_position)
            .finish_non_exhaustive()
    }
}

impl FinalitySignature {
    pub(crate) fn encode(&self) -> ProtocolResult<Vec<u8>> {
        Ok(CanonicalTuple::new(
            FINALITY_SIGNATURE_CARRIER_SCHEMA_IDENTIFIER,
            FINALITY_SCHEMA_VERSION,
            vec![
                CanonicalItem::variable_bytes(&self.body_bytes)?,
                CanonicalItem::fixed_bytes(self.signature_bytes)?,
            ],
        )
        .encode()?)
    }

    pub(crate) fn body_identity(&self) -> ProtocolResult<Hash512> {
        protocol_oracle_512(
            "sealed-lattice/protocol/finality-signature-body/v1",
            &[CanonicalItem::variable_bytes(&self.body_bytes)?],
        )
    }

    pub(crate) fn decode(carrier_bytes: &[u8]) -> ProtocolResult<Self> {
        let carrier = CanonicalTuple::decode(carrier_bytes, &CanonicalDecodeLimits::default())?;
        require_tuple(
            &carrier,
            FINALITY_SIGNATURE_CARRIER_SCHEMA_IDENTIFIER,
            FINALITY_SCHEMA_VERSION,
            2,
        )?;
        let body_bytes = read_variable_bytes(&carrier.items[0])?;
        let body = CanonicalTuple::decode(body_bytes, &CanonicalDecodeLimits::default())?;
        require_tuple(
            &body,
            FINALITY_SIGNATURE_BODY_SCHEMA_IDENTIFIER,
            FINALITY_SCHEMA_VERSION,
            2,
        )?;
        let target_identity = read_hash(&body.items[0])?;
        let signer_position = read_u16(&body.items[1])?;
        if usize::from(signer_position) >= PARTICIPANT_COUNT {
            return Err(ProtocolRefusal::new(
                RefusalReason::WrongContext,
                "finality signature signer is outside the roster",
            ));
        }
        Ok(Self {
            target_identity,
            signer_position,
            body_bytes: body_bytes.to_vec(),
            signature_bytes: read_fixed_bytes::<ROSTER_SIGNATURE_BYTE_LENGTH>(&carrier.items[1])?,
        })
    }
}

pub(crate) fn create_finality_signature(
    target: &ComputationTarget,
    signer_position: usize,
    signing_key_bytes: &RosterSigningKey,
    verification_key_bytes: &RosterVerificationKey,
    signature_randomizer: RosterSignatureRandomizer,
) -> ProtocolResult<FinalitySignature> {
    if signer_position >= PARTICIPANT_COUNT {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongContext,
            "finality signer position is outside the roster",
        ));
    }
    let target_identity = target.identity()?;
    let body_bytes = finality_signature_body(target_identity, signer_position as u16)?;
    let signature = sign_roster_message(
        FINALITY_SIGNATURE_CONTEXT,
        &body_bytes,
        signing_key_bytes,
        verification_key_bytes,
        signature_randomizer,
    )?;
    Ok(FinalitySignature {
        target_identity,
        signer_position: signer_position as u16,
        body_bytes,
        signature_bytes: signature,
    })
}

pub(crate) fn verify_finality_signature(
    target: &ComputationTarget,
    signature: &FinalitySignature,
    verification_key_bytes: &RosterVerificationKey,
) -> ProtocolResult<()> {
    if signature.target_identity != target.identity()?
        || usize::from(signature.signer_position) >= PARTICIPANT_COUNT
        || signature.body_bytes
            != finality_signature_body(signature.target_identity, signature.signer_position)?
    {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongContext,
            "finality signature does not bind the expected semantic target",
        ));
    }
    verify_roster_message(
        FINALITY_SIGNATURE_CONTEXT,
        &signature.body_bytes,
        &signature.signature_bytes,
        verification_key_bytes,
    )?;
    Ok(())
}

pub(crate) struct FinalityCertificate {
    target_identity: Hash512,
    finality_policy: FinalityPolicy,
    signer_positions: Vec<u16>,
    signature_body_identities: Vec<Hash512>,
    bytes: Vec<u8>,
}

pub(crate) struct VerifiedFinalityCertificate {
    target_identity: Hash512,
}

impl core::fmt::Debug for VerifiedFinalityCertificate {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("VerifiedFinalityCertificate")
            .field("target_identity", &self.target_identity)
            .finish_non_exhaustive()
    }
}

impl VerifiedFinalityCertificate {
    pub(crate) fn target_identity(&self) -> Hash512 {
        self.target_identity
    }
}

impl core::fmt::Debug for FinalityCertificate {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("FinalityCertificate")
            .field("target_identity", &self.target_identity)
            .field("signer_positions", &self.signer_positions)
            .finish()
    }
}

impl FinalityCertificate {
    pub(crate) fn encode(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn identity(&self) -> ProtocolResult<Hash512> {
        protocol_oracle_512(
            "sealed-lattice/protocol/finality-certificate/v1",
            &[CanonicalItem::variable_bytes(&self.bytes)?],
        )
    }

    pub(crate) fn target_identity(&self) -> Hash512 {
        self.target_identity
    }

    pub(crate) fn decode(bytes: &[u8]) -> ProtocolResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, &CanonicalDecodeLimits::default())?;
        if tuple.schema_identifier != FINALITY_CERTIFICATE_SCHEMA_IDENTIFIER
            || tuple.schema_version != FINALITY_SCHEMA_VERSION
            || tuple.items.len() < 5
        {
            return Err(ProtocolRefusal::new(
                RefusalReason::WrongTypeOrLength,
                "finality certificate has the wrong schema or header length",
            ));
        }
        let target_identity = read_hash(&tuple.items[0])?;
        let finality_policy = FinalityPolicy {
            roster_count: read_u16(&tuple.items[1])?,
            corruption_bound: read_u16(&tuple.items[2])?,
            independent_state_failure_count: read_u16(&tuple.items[3])?,
            quorum: read_u16(&tuple.items[4])?,
        };
        finality_policy.verify()?;
        let quorum = usize::from(finality_policy.quorum);
        if tuple.items.len() != 5 + quorum * 2 {
            return Err(ProtocolRefusal::new(
                RefusalReason::WrongTypeOrLength,
                "finality certificate has the wrong signer-entry count",
            ));
        }
        let mut signer_positions = Vec::with_capacity(quorum);
        let mut signature_body_identities = Vec::with_capacity(quorum);
        for entry in tuple.items[5..].chunks_exact(2) {
            let signer_position = read_u16(&entry[0])?;
            if usize::from(signer_position) >= usize::from(finality_policy.roster_count) {
                return Err(ProtocolRefusal::new(
                    RefusalReason::WrongContext,
                    "finality certificate signer is outside the roster",
                ));
            }
            signer_positions.push(signer_position);
            signature_body_identities.push(read_hash(&entry[1])?);
        }
        if signer_positions
            .windows(2)
            .any(|positions| positions[0] >= positions[1])
        {
            return Err(ProtocolRefusal::new(
                RefusalReason::DuplicateIdentity,
                "finality certificate signer positions are not canonical and distinct",
            ));
        }
        Ok(Self {
            target_identity,
            finality_policy,
            signer_positions,
            signature_body_identities,
            bytes: bytes.to_vec(),
        })
    }
}

pub(crate) fn create_finality_certificate(
    target: &ComputationTarget,
    signatures: &[FinalitySignature],
    roster_verification_keys: &[RosterVerificationKey],
) -> ProtocolResult<Option<FinalityCertificate>> {
    target.finality_policy.verify()?;
    if roster_verification_keys.len() != usize::from(target.finality_policy.roster_count) {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "finality roster key inventory is incomplete",
        ));
    }
    let mut valid_entries = Vec::new();
    for (position, verification_key) in roster_verification_keys.iter().enumerate() {
        if let Some(signature) = signatures.iter().find(|signature| {
            usize::from(signature.signer_position) == position
                && verify_finality_signature(target, signature, verification_key).is_ok()
        }) {
            valid_entries.push((position as u16, signature.body_identity()?));
        }
    }
    let quorum = usize::from(target.finality_policy.quorum);
    if valid_entries.len() < quorum {
        return Ok(None);
    }
    valid_entries.truncate(quorum);
    let signer_positions = valid_entries
        .iter()
        .map(|(position, _)| *position)
        .collect::<Vec<_>>();
    let signature_body_identities = valid_entries
        .iter()
        .map(|(_, identity)| *identity)
        .collect::<Vec<_>>();
    let target_identity = target.identity()?;
    let bytes = finality_certificate_bytes(
        target_identity,
        target.finality_policy,
        &signer_positions,
        &signature_body_identities,
    )?;
    Ok(Some(FinalityCertificate {
        target_identity,
        finality_policy: target.finality_policy,
        signer_positions,
        signature_body_identities,
        bytes,
    }))
}

pub(crate) fn verify_finality_certificate(
    target: &ComputationTarget,
    certificate: &FinalityCertificate,
    signatures: &[FinalitySignature],
    roster_verification_keys: &[RosterVerificationKey],
) -> ProtocolResult<Option<VerifiedFinalityCertificate>> {
    if certificate.target_identity != target.identity()?
        || certificate.finality_policy != target.finality_policy
        || certificate.signer_positions.len() != usize::from(target.finality_policy.quorum)
        || certificate.signature_body_identities.len() != usize::from(target.finality_policy.quorum)
        || roster_verification_keys.len() != usize::from(target.finality_policy.roster_count)
    {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongContext,
            "finality certificate does not match the target policy",
        ));
    }
    if certificate.bytes
        != finality_certificate_bytes(
            certificate.target_identity,
            certificate.finality_policy,
            &certificate.signer_positions,
            &certificate.signature_body_identities,
        )?
    {
        return Err(ProtocolRefusal::new(
            RefusalReason::MalformedEncoding,
            "finality certificate bytes do not match its semantic entries",
        ));
    }
    if certificate
        .signer_positions
        .windows(2)
        .any(|positions| positions[0] >= positions[1])
    {
        return Err(ProtocolRefusal::new(
            RefusalReason::DuplicateIdentity,
            "finality certificate signer positions are not canonical and distinct",
        ));
    }
    for (signer_position, expected_signature_body_identity) in certificate
        .signer_positions
        .iter()
        .zip(&certificate.signature_body_identities)
    {
        let position = usize::from(*signer_position);
        let Some(signature) = signatures.iter().find(|signature| {
            usize::from(signature.signer_position) == position
                && signature.body_identity().ok().as_ref() == Some(expected_signature_body_identity)
                && verify_finality_signature(target, signature, &roster_verification_keys[position])
                    .is_ok()
        }) else {
            return Ok(None);
        };
        verify_finality_signature(target, signature, &roster_verification_keys[position])?;
    }
    Ok(Some(VerifiedFinalityCertificate {
        target_identity: certificate.target_identity,
    }))
}

pub(crate) fn minimal_direct_finality_quorum(
    roster_count: usize,
    corruption_bound: usize,
    independent_state_failure_count: usize,
) -> Option<usize> {
    if roster_count == 0 || corruption_bound >= roster_count {
        return None;
    }
    let numerator = roster_count
        .checked_add(corruption_bound)?
        .checked_add(independent_state_failure_count)?
        .checked_add(1)?;
    let quorum = numerator.checked_add(1)? / 2;
    if quorum > roster_count {
        None
    } else {
        Some(quorum)
    }
}

fn finality_signature_body(
    target_identity: Hash512,
    signer_position: u16,
) -> ProtocolResult<Vec<u8>> {
    Ok(CanonicalTuple::new(
        FINALITY_SIGNATURE_BODY_SCHEMA_IDENTIFIER,
        FINALITY_SCHEMA_VERSION,
        vec![
            hash_item(target_identity),
            CanonicalItem::unsigned16(signer_position),
        ],
    )
    .encode()?)
}

fn finality_certificate_bytes(
    target_identity: Hash512,
    finality_policy: FinalityPolicy,
    signer_positions: &[u16],
    signature_body_identities: &[Hash512],
) -> ProtocolResult<Vec<u8>> {
    if signer_positions.len() != usize::from(finality_policy.quorum)
        || signature_body_identities.len() != signer_positions.len()
    {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "finality certificate entries do not match the quorum",
        ));
    }
    let mut items = Vec::with_capacity(5 + signer_positions.len() * 2);
    items.extend([
        hash_item(target_identity),
        CanonicalItem::unsigned16(finality_policy.roster_count),
        CanonicalItem::unsigned16(finality_policy.corruption_bound),
        CanonicalItem::unsigned16(finality_policy.independent_state_failure_count),
        CanonicalItem::unsigned16(finality_policy.quorum),
    ]);
    for (position, signature_body_identity) in
        signer_positions.iter().zip(signature_body_identities)
    {
        items.extend([
            CanonicalItem::unsigned16(*position),
            hash_item(*signature_body_identity),
        ]);
    }
    Ok(CanonicalTuple::new(
        FINALITY_CERTIFICATE_SCHEMA_IDENTIFIER,
        FINALITY_SCHEMA_VERSION,
        items,
    )
    .encode()?)
}

fn hash_item(hash: Hash512) -> CanonicalItem {
    CanonicalItem::hash512(hash.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference_flow::roster_signature::{
        ROSTER_KEY_GENERATION_SEED_BYTE_LENGTH, ROSTER_SIGNATURE_RANDOMIZER_BYTE_LENGTH,
        generate_roster_signature_keypair,
    };

    fn target(marker: u8) -> ComputationTarget {
        let hash = |offset| Hash512::from_bytes([marker.wrapping_add(offset); 64]);
        ComputationTarget {
            suite_identity: hash(1),
            build_identity: hash(2),
            action_identity: hash(3),
            predecessor_identity: hash(4),
            roster_identity: hash(5),
            circuit_identity: hash(6),
            compiler_identity: hash(7),
            output_schema_identity: hash(8),
            preparation_terminal_identity: hash(9),
            declaration_inventory_identity: hash(10),
            source_inventory_identity: hash(11),
            selected_source_identity: hash(12),
            public_input_identity: hash(13),
            activation_policy_identity: hash(14),
            finality_policy: FinalityPolicy::completion_profile(),
            output_bit_count: 1,
            action_ordinal: 4,
            output_ordinal: 0,
        }
    }

    fn roster_keys() -> Vec<(RosterVerificationKey, RosterSigningKey)> {
        (0_u8..PARTICIPANT_COUNT as u8)
            .map(|position| {
                generate_roster_signature_keypair(
                    [position.wrapping_add(1); ROSTER_KEY_GENERATION_SEED_BYTE_LENGTH],
                )
            })
            .collect()
    }

    fn signatures(
        target: &ComputationTarget,
        keys: &[(RosterVerificationKey, RosterSigningKey)],
        count: usize,
    ) -> Vec<FinalitySignature> {
        (0..count)
            .map(|position| {
                create_finality_signature(
                    target,
                    position,
                    &keys[position].1,
                    &keys[position].0,
                    [0xa0_u8.wrapping_add(position as u8); ROSTER_SIGNATURE_RANDOMIZER_BYTE_LENGTH],
                )
                .expect("test finality signature is valid")
            })
            .collect()
    }

    #[test]
    fn completion_direct_quorum_is_minimal_and_retains_stable_honest_intersection() {
        assert_eq!(minimal_direct_finality_quorum(10, 3, 1), Some(8));
        assert_eq!(2 * 8 - 10 - 3 - 1, 2);
        assert_eq!(2 * 7 - 10 - 3 - 1, 0);

        for roster_count in 3..=20 {
            let corruption_bound = (roster_count - 1) / 3;
            let quorum = minimal_direct_finality_quorum(roster_count, corruption_bound, 1)
                .expect("admitted roster has a quorum");
            assert!(2 * quorum - roster_count > corruption_bound + 1);
            if quorum > 0 {
                assert!(2 * (quorum - 1) <= roster_count + corruption_bound + 1);
            }
        }
    }

    #[test]
    fn eight_valid_semantic_signatures_create_and_verify_one_certificate() {
        let target = target(0x10);
        let keys = roster_keys();
        let verification_keys = keys.iter().map(|entry| entry.0).collect::<Vec<_>>();
        let signatures = signatures(&target, &keys, 8);
        assert!(!signatures[0].encode().unwrap().is_empty());
        assert_ne!(
            signatures[0].body_identity().unwrap(),
            target.identity().unwrap()
        );
        let certificate = create_finality_certificate(&target, &signatures, &verification_keys)
            .expect("certificate construction verifies inputs")
            .expect("eight signatures meet quorum");
        let verified =
            verify_finality_certificate(&target, &certificate, &signatures, &verification_keys)
                .expect("certificate is well formed")
                .expect("certificate carries every required signature");
        assert_eq!(verified.target_identity(), target.identity().unwrap());
        assert_eq!(certificate.target_identity(), target.identity().unwrap());
        assert!(!certificate.encode().is_empty());
        assert_ne!(certificate.identity().unwrap(), target.identity().unwrap());
        assert_eq!(
            FinalityCertificate::decode(certificate.encode())
                .unwrap()
                .encode(),
            certificate.encode()
        );
        assert_eq!(
            ComputationTarget::decode(&target.encode().unwrap()).unwrap(),
            target
        );
        assert_eq!(
            FinalitySignature::decode(&signatures[0].encode().unwrap())
                .unwrap()
                .body_identity()
                .unwrap(),
            signatures[0].body_identity().unwrap()
        );
    }

    #[test]
    fn seven_signatures_remain_pending_and_wrong_target_or_key_refuses() {
        let first_target = target(0x20);
        let second_target = target(0x30);
        let keys = roster_keys();
        let verification_keys = keys.iter().map(|entry| entry.0).collect::<Vec<_>>();
        let signatures = signatures(&first_target, &keys, 7);
        assert!(
            create_finality_certificate(&first_target, &signatures, &verification_keys)
                .expect("seven valid signatures are not malformed")
                .is_none()
        );
        assert!(verify_finality_signature(&second_target, &signatures[0], &keys[0].0).is_err());
        assert!(verify_finality_signature(&first_target, &signatures[0], &keys[1].0).is_err());
    }

    #[test]
    fn duplicate_carriers_do_not_count_twice_and_extra_signers_canonicalize() {
        let target = target(0x40);
        let keys = roster_keys();
        let verification_keys = keys.iter().map(|entry| entry.0).collect::<Vec<_>>();
        let mut signatures = signatures(&target, &keys, 10);
        signatures.push(
            create_finality_signature(
                &target,
                0,
                &keys[0].1,
                &keys[0].0,
                [0xee; ROSTER_SIGNATURE_RANDOMIZER_BYTE_LENGTH],
            )
            .expect("second corrupt carrier may be cryptographically valid"),
        );
        let certificate = create_finality_certificate(&target, &signatures, &verification_keys)
            .expect("valid carriers are accepted")
            .expect("ten positions meet quorum");
        assert_eq!(certificate.signer_positions, (0_u16..8).collect::<Vec<_>>());
    }
}
