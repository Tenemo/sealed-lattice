use core::fmt;

use crate::foundation::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, Hash512, Roster,
    hash_foundation_tuple_512,
};
use crate::tally_circuit::{
    TallyCircuitProfile, bit_width_for_maximum_value, compiler::compile_tally_circuit,
    encode_compiled_tally_circuit,
};

use super::preparation_parent::{ActionSignatureCarrier, ActionSignaturePurpose};
use super::roster::{require_roster_identity, signing_verification_key};
use super::source::{
    SOURCE_ORDINAL, SourceContext, SourceDeclaration, VerifiedSource, verify_source_carrier,
};

pub const COMPLETION_PROFILE_PARTICIPANT_COUNT: u16 = 10;
pub const COMPLETION_PROFILE_OPTION_COUNT: u16 = 10;
pub const FINALITY_TARGET_BODY_BYTE_LENGTH: usize = 1_058;
pub const OUTPUT_ORDINAL: u64 = 0;

const FINALITY_TARGET_SCHEMA_IDENTIFIER: u16 = 0x0209;
const FINALITY_TARGET_SCHEMA_VERSION: u16 = 5;
const FINALITY_TARGET_IDENTITY_DOMAIN: &str = "sealed-lattice/construction/finality-target/v3";
const SOURCE_INVENTORY_ROOT_DOMAIN: &str = "sealed-lattice/construction/source-inventory-root/v2";
const TALLY_COMPILER_IDENTITY_DOMAIN: &str =
    "sealed-lattice/construction/tally-compiler-identity/v1";
const TALLY_CIRCUIT_IDENTITY_DOMAIN: &str = "sealed-lattice/construction/tally-circuit-identity/v1";
const TALLY_OUTPUT_SCHEMA_IDENTITY_DOMAIN: &str =
    "sealed-lattice/construction/tally-output-schema-identity/v1";
const SOURCE_SELECTION_POLICY_IDENTITY_DOMAIN: &str =
    "sealed-lattice/construction/source-selection-policy-identity/v1";
const FINAL_ACTION_POLICY_IDENTITY_DOMAIN: &str =
    "sealed-lattice/construction/final-action-policy-identity/v2";
const FINALITY_POLICY_IDENTITY_DOMAIN: &str =
    "sealed-lattice/construction/finality-policy-identity/v2";
const MINIMUM_PARTICIPANT_COUNT: u16 = 3;
const MAXIMUM_PARTICIPANT_COUNT: u16 = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum FinalityTargetKind {
    Computation = 1,
    NoResult = 2,
}

impl FinalityTargetKind {
    fn from_u16(value: u16) -> Result<Self, FinalityError> {
        match value {
            1 => Ok(Self::Computation),
            2 => Ok(Self::NoResult),
            _ => Err(FinalityError::WrongTargetKind),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalityError {
    AuthenticatedBodyViolation,
    DuplicateSignature,
    DuplicateSourceIdentity,
    IncompleteNoResultAcknowledgements,
    InsufficientSignatures,
    InvalidCanonicalEncoding,
    InvalidSignature,
    UnsupportedSourceInventory,
    WrongContext,
    WrongItemTypeOrLength,
    WrongParticipantCount,
    WrongParticipantPosition,
    WrongQuorum,
    WrongSchema,
    WrongTargetKind,
}

impl fmt::Display for FinalityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AuthenticatedBodyViolation => {
                "authenticated source bytes violate their public relation"
            }
            Self::DuplicateSignature => "finality certificate contains a duplicate signer",
            Self::DuplicateSourceIdentity => "finality target contains a duplicate source identity",
            Self::IncompleteNoResultAcknowledgements => {
                "no-result release does not contain every roster acknowledgement"
            }
            Self::InsufficientSignatures => {
                "finality certificate does not contain the derived quorum"
            }
            Self::InvalidCanonicalEncoding => {
                "finality target or signature is not canonically encoded"
            }
            Self::InvalidSignature => "finality signature is invalid",
            Self::UnsupportedSourceInventory => {
                "source inventory contains positions outside the completion roster"
            }
            Self::WrongContext => "finality target has the wrong context",
            Self::WrongItemTypeOrLength => "finality field has the wrong type or length",
            Self::WrongParticipantCount => "finality participant count is not admitted",
            Self::WrongParticipantPosition => "finality participant position is invalid",
            Self::WrongQuorum => "finality quorum is not the derived minimum",
            Self::WrongSchema => "finality target has the wrong schema or version",
            Self::WrongTargetKind => "finality target has the wrong semantic branch",
        })
    }
}

impl std::error::Error for FinalityError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalityDerivationContext {
    pub participant_count: u16,
    pub runtime_identity: Hash512,
    pub candidate_build_identity: Hash512,
    pub action_proposal_identity: Hash512,
    pub action_definition_identity: Hash512,
    pub roster_identity: Hash512,
    pub preparation_attempt: u16,
    pub predecessor_identity: Hash512,
    pub verified_preparation_root: Hash512,
    pub top_count: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalityTargetContext {
    pub participant_count: u16,
    pub runtime_identity: Hash512,
    pub candidate_build_identity: Hash512,
    pub action_proposal_identity: Hash512,
    pub action_definition_identity: Hash512,
    pub roster_identity: Hash512,
    pub preparation_attempt: u16,
    pub predecessor_identity: Hash512,
    pub verified_preparation_root: Hash512,
    pub compiler_identity: Hash512,
    pub circuit_identity: Hash512,
    pub option_count: u16,
    pub output_schema_identity: Hash512,
    pub source_inventory_root: Hash512,
    pub source_submission_bitmap: u16,
    pub source_selection_policy_identity: Hash512,
    pub final_action_policy_identity: Hash512,
    pub top_count: u16,
    pub finality_policy_identity: Hash512,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalityTarget {
    context: FinalityTargetContext,
    target_kind: FinalityTargetKind,
    output_ordinal: u64,
    quorum: u16,
}

impl FinalityTarget {
    pub fn new(context: FinalityTargetContext) -> Result<Self, FinalityError> {
        validate_completion_profile(context.participant_count)?;
        let admitted_bitmap = (1_u16 << context.participant_count) - 1;
        if context.source_submission_bitmap & !admitted_bitmap != 0 {
            return Err(FinalityError::UnsupportedSourceInventory);
        }
        if context.option_count != COMPLETION_PROFILE_OPTION_COUNT
            || context.top_count == 0
            || context.top_count > context.option_count
        {
            return Err(FinalityError::WrongContext);
        }
        let semantic_bindings = derive_semantic_bindings(
            context.participant_count,
            context.option_count,
            context.top_count,
        )?;
        if context.compiler_identity != semantic_bindings.compiler_identity
            || context.circuit_identity != semantic_bindings.circuit_identity
            || context.output_schema_identity != semantic_bindings.output_schema_identity
            || context.source_selection_policy_identity
                != semantic_bindings.source_selection_policy_identity
            || context.final_action_policy_identity
                != semantic_bindings.final_action_policy_identity
            || context.finality_policy_identity != semantic_bindings.finality_policy_identity
        {
            return Err(FinalityError::WrongContext);
        }
        let target_kind = if context.source_submission_bitmap == 0 {
            FinalityTargetKind::NoResult
        } else {
            FinalityTargetKind::Computation
        };
        Ok(Self {
            context,
            target_kind,
            output_ordinal: OUTPUT_ORDINAL,
            quorum: direct_finality_quorum(context.participant_count)?,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, FinalityError> {
        let encoded = CanonicalTuple::new(
            FINALITY_TARGET_SCHEMA_IDENTIFIER,
            FINALITY_TARGET_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.context.participant_count),
                CanonicalItem::hash512(self.context.runtime_identity.into_bytes()),
                CanonicalItem::hash512(self.context.candidate_build_identity.into_bytes()),
                CanonicalItem::hash512(self.context.action_proposal_identity.into_bytes()),
                CanonicalItem::hash512(self.context.action_definition_identity.into_bytes()),
                CanonicalItem::hash512(self.context.roster_identity.into_bytes()),
                CanonicalItem::unsigned16(self.context.preparation_attempt),
                CanonicalItem::hash512(self.context.predecessor_identity.into_bytes()),
                CanonicalItem::hash512(self.context.verified_preparation_root.into_bytes()),
                CanonicalItem::hash512(self.context.compiler_identity.into_bytes()),
                CanonicalItem::hash512(self.context.circuit_identity.into_bytes()),
                CanonicalItem::unsigned16(self.context.option_count),
                CanonicalItem::unsigned16(self.context.top_count),
                CanonicalItem::hash512(self.context.output_schema_identity.into_bytes()),
                CanonicalItem::hash512(self.context.source_inventory_root.into_bytes()),
                CanonicalItem::unsigned16(self.context.source_submission_bitmap),
                CanonicalItem::hash512(self.context.source_selection_policy_identity.into_bytes()),
                CanonicalItem::hash512(self.context.final_action_policy_identity.into_bytes()),
                CanonicalItem::unsigned16(self.target_kind as u16),
                CanonicalItem::unsigned64(self.output_ordinal),
                CanonicalItem::hash512(self.context.finality_policy_identity.into_bytes()),
                CanonicalItem::unsigned16(self.quorum),
            ],
        )
        .encode()
        .map_err(|_| FinalityError::InvalidCanonicalEncoding)?;
        if encoded.len() != FINALITY_TARGET_BODY_BYTE_LENGTH {
            return Err(FinalityError::InvalidCanonicalEncoding);
        }
        Ok(encoded)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FinalityError> {
        if bytes.len() != FINALITY_TARGET_BODY_BYTE_LENGTH {
            return Err(FinalityError::WrongItemTypeOrLength);
        }
        let tuple = CanonicalTuple::decode(bytes, &CanonicalDecodeLimits::default())
            .map_err(|_| FinalityError::InvalidCanonicalEncoding)?;
        if tuple.schema_identifier != FINALITY_TARGET_SCHEMA_IDENTIFIER
            || tuple.schema_version != FINALITY_TARGET_SCHEMA_VERSION
            || tuple.items.len() != 22
        {
            return Err(FinalityError::WrongSchema);
        }
        let context = FinalityTargetContext {
            participant_count: read_unsigned16(&tuple.items[0])?,
            runtime_identity: read_hash512(&tuple.items[1])?,
            candidate_build_identity: read_hash512(&tuple.items[2])?,
            action_proposal_identity: read_hash512(&tuple.items[3])?,
            action_definition_identity: read_hash512(&tuple.items[4])?,
            roster_identity: read_hash512(&tuple.items[5])?,
            preparation_attempt: read_unsigned16(&tuple.items[6])?,
            predecessor_identity: read_hash512(&tuple.items[7])?,
            verified_preparation_root: read_hash512(&tuple.items[8])?,
            compiler_identity: read_hash512(&tuple.items[9])?,
            circuit_identity: read_hash512(&tuple.items[10])?,
            option_count: read_unsigned16(&tuple.items[11])?,
            top_count: read_unsigned16(&tuple.items[12])?,
            output_schema_identity: read_hash512(&tuple.items[13])?,
            source_inventory_root: read_hash512(&tuple.items[14])?,
            source_submission_bitmap: read_unsigned16(&tuple.items[15])?,
            source_selection_policy_identity: read_hash512(&tuple.items[16])?,
            final_action_policy_identity: read_hash512(&tuple.items[17])?,
            finality_policy_identity: read_hash512(&tuple.items[20])?,
        };
        let target_kind = FinalityTargetKind::from_u16(read_unsigned16(&tuple.items[18])?)?;
        let output_ordinal = read_unsigned64(&tuple.items[19])?;
        let quorum = read_unsigned16(&tuple.items[21])?;
        let target = Self::new(context)?;
        if target.target_kind != target_kind
            || output_ordinal != OUTPUT_ORDINAL
            || target.quorum != quorum
            || target.encode()?.as_slice() != bytes
        {
            return Err(FinalityError::WrongContext);
        }
        Ok(target)
    }

    pub fn body_identity(&self) -> Result<Hash512, FinalityError> {
        hash_foundation_tuple_512(
            FINALITY_TARGET_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(self.encode()?)
                .map_err(|_| FinalityError::InvalidCanonicalEncoding)?],
        )
        .map_err(|_| FinalityError::InvalidCanonicalEncoding)
    }

    pub const fn context(&self) -> FinalityTargetContext {
        self.context
    }

    pub const fn target_kind(&self) -> FinalityTargetKind {
        self.target_kind
    }

    pub const fn quorum(&self) -> u16 {
        self.quorum
    }
}

pub struct VerifiedFinalityTarget {
    pub target: FinalityTarget,
    pub target_body: Vec<u8>,
    pub target_identity: Hash512,
    pub source_body_identities: Vec<Hash512>,
    pub verified_sources: Vec<VerifiedSource>,
}

#[allow(clippy::too_many_arguments)]
pub fn derive_finality_target(
    context: FinalityDerivationContext,
    roster: &Roster,
    source_declarations: &[SourceDeclaration],
    source_bodies: &[Vec<u8>],
    source_signatures: &[Vec<u8>],
) -> Result<VerifiedFinalityTarget, FinalityError> {
    validate_completion_profile(context.participant_count)?;
    let semantic_bindings = derive_semantic_bindings(
        context.participant_count,
        COMPLETION_PROFILE_OPTION_COUNT,
        context.top_count,
    )?;
    if source_declarations.len() != usize::from(context.participant_count)
        || source_bodies.len() != usize::from(context.participant_count)
        || source_signatures.len() != usize::from(context.participant_count)
    {
        return Err(FinalityError::WrongContext);
    }
    require_roster_identity(roster, context.roster_identity)
        .map_err(|_| FinalityError::WrongContext)?;

    let mut source_body_identities = Vec::with_capacity(usize::from(context.participant_count));
    let mut verified_sources = Vec::with_capacity(usize::from(context.participant_count));
    let mut source_identity_bytes =
        Vec::with_capacity(usize::from(context.participant_count) * Hash512::BYTE_LENGTH);
    let mut source_submission_bitmap = 0_u16;
    for sender_position in 0..context.participant_count {
        let declaration = *source_declarations
            .get(usize::from(sender_position))
            .ok_or(FinalityError::WrongItemTypeOrLength)?;
        if declaration == SourceDeclaration::Submit {
            source_submission_bitmap |= 1_u16 << sender_position;
        }
        let verified = verify_source_carrier(
            SourceContext {
                participant_count: context.participant_count,
                action_proposal_identity: context.action_proposal_identity,
                roster_identity: context.roster_identity,
                preparation_attempt: context.preparation_attempt,
                predecessor_identity: context.predecessor_identity,
                verified_preparation_root: context.verified_preparation_root,
                sender_position,
                source_ordinal: SOURCE_ORDINAL,
            },
            Some(declaration),
            roster,
            source_bodies
                .get(usize::from(sender_position))
                .ok_or(FinalityError::WrongItemTypeOrLength)?,
            source_signatures
                .get(usize::from(sender_position))
                .ok_or(FinalityError::WrongItemTypeOrLength)?,
        )
        .map_err(|error| match error {
            super::source::SourceError::AuthenticatedBodyViolation => {
                FinalityError::AuthenticatedBodyViolation
            }
            _ => FinalityError::InvalidSignature,
        })?;
        if source_body_identities.contains(&verified.body_identity) {
            return Err(FinalityError::DuplicateSourceIdentity);
        }
        source_identity_bytes.extend_from_slice(verified.body_identity.as_bytes());
        source_body_identities.push(verified.body_identity);
        verified_sources.push(verified);
    }

    let source_inventory_root = hash_foundation_tuple_512(
        SOURCE_INVENTORY_ROOT_DOMAIN,
        &[
            CanonicalItem::hash512(context.action_proposal_identity.into_bytes()),
            CanonicalItem::hash512(context.roster_identity.into_bytes()),
            CanonicalItem::unsigned16(context.preparation_attempt),
            CanonicalItem::hash512(context.predecessor_identity.into_bytes()),
            CanonicalItem::hash512(context.verified_preparation_root.into_bytes()),
            CanonicalItem::fixed_bytes(source_identity_bytes)
                .map_err(|_| FinalityError::InvalidCanonicalEncoding)?,
            CanonicalItem::unsigned16(source_submission_bitmap),
        ],
    )
    .map_err(|_| FinalityError::InvalidCanonicalEncoding)?;
    let target = FinalityTarget::new(FinalityTargetContext {
        participant_count: context.participant_count,
        runtime_identity: context.runtime_identity,
        candidate_build_identity: context.candidate_build_identity,
        action_proposal_identity: context.action_proposal_identity,
        action_definition_identity: context.action_definition_identity,
        roster_identity: context.roster_identity,
        preparation_attempt: context.preparation_attempt,
        predecessor_identity: context.predecessor_identity,
        verified_preparation_root: context.verified_preparation_root,
        compiler_identity: semantic_bindings.compiler_identity,
        circuit_identity: semantic_bindings.circuit_identity,
        option_count: COMPLETION_PROFILE_OPTION_COUNT,
        output_schema_identity: semantic_bindings.output_schema_identity,
        source_inventory_root,
        source_submission_bitmap,
        source_selection_policy_identity: semantic_bindings.source_selection_policy_identity,
        final_action_policy_identity: semantic_bindings.final_action_policy_identity,
        top_count: context.top_count,
        finality_policy_identity: semantic_bindings.finality_policy_identity,
    })?;
    let target_body = target.encode()?;
    let target_identity = target.body_identity()?;
    Ok(VerifiedFinalityTarget {
        target,
        target_body,
        target_identity,
        source_body_identities,
        verified_sources,
    })
}

pub fn encode_finality_signature_carrier(
    participant_count: u16,
    signer_position: u16,
    target_identity: Hash512,
    signature: &[u8],
) -> Result<Vec<u8>, FinalityError> {
    ActionSignatureCarrier::new(
        participant_count,
        signer_position,
        ActionSignaturePurpose::Finality,
        target_identity,
        signature,
    )
    .map_err(|_| FinalityError::InvalidCanonicalEncoding)?
    .encode()
    .map_err(|_| FinalityError::InvalidCanonicalEncoding)
}

pub fn encode_no_result_acknowledgement_carrier(
    participant_count: u16,
    signer_position: u16,
    target_identity: Hash512,
    signature: &[u8],
) -> Result<Vec<u8>, FinalityError> {
    ActionSignatureCarrier::new(
        participant_count,
        signer_position,
        ActionSignaturePurpose::NoResultAcknowledgement,
        target_identity,
        signature,
    )
    .map_err(|_| FinalityError::InvalidCanonicalEncoding)?
    .encode()
    .map_err(|_| FinalityError::InvalidCanonicalEncoding)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedFinalityCapability {
    pub target: FinalityTarget,
    pub target_identity: Hash512,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedNoResultReleaseCapability {
    pub finality: VerifiedFinalityCapability,
}

pub fn verify_finality_certificate(
    target: &FinalityTarget,
    roster: &Roster,
    signatures: &[(u16, Vec<u8>)],
) -> Result<VerifiedFinalityCapability, FinalityError> {
    let participant_count = target.context().participant_count;
    validate_completion_profile(participant_count)?;
    if signatures.len() > usize::from(participant_count) {
        return Err(FinalityError::WrongContext);
    }
    require_roster_identity(roster, target.context().roster_identity)
        .map_err(|_| FinalityError::WrongContext)?;
    let quorum = direct_finality_quorum(participant_count)?;
    if signatures.len() < usize::from(quorum) {
        return Err(FinalityError::InsufficientSignatures);
    }
    let target_identity = target.body_identity()?;
    let mut signer_bitmap = 0_u16;
    for (signer_position, signature_bytes) in signatures {
        validate_position(participant_count, *signer_position)?;
        let signer_mask = 1_u16 << *signer_position;
        if signer_bitmap & signer_mask != 0 {
            return Err(FinalityError::DuplicateSignature);
        }
        verify_finality_signature_for_identity(
            participant_count,
            roster,
            *signer_position,
            target_identity,
            signature_bytes,
        )?;
        signer_bitmap |= signer_mask;
    }
    Ok(VerifiedFinalityCapability {
        target: target.clone(),
        target_identity,
    })
}

pub fn verify_finality_signature(
    target: &FinalityTarget,
    roster: &Roster,
    signer_position: u16,
    signature_bytes: &[u8],
) -> Result<(), FinalityError> {
    let participant_count = target.context().participant_count;
    validate_completion_profile(participant_count)?;
    validate_position(participant_count, signer_position)?;
    require_roster_identity(roster, target.context().roster_identity)
        .map_err(|_| FinalityError::WrongContext)?;
    verify_finality_signature_for_identity(
        participant_count,
        roster,
        signer_position,
        target.body_identity()?,
        signature_bytes,
    )
}

pub fn verify_no_result_acknowledgement(
    target: &FinalityTarget,
    roster: &Roster,
    signer_position: u16,
    signature_bytes: &[u8],
) -> Result<(), FinalityError> {
    if target.target_kind() != FinalityTargetKind::NoResult {
        return Err(FinalityError::WrongTargetKind);
    }
    let participant_count = target.context().participant_count;
    validate_completion_profile(participant_count)?;
    validate_position(participant_count, signer_position)?;
    require_roster_identity(roster, target.context().roster_identity)
        .map_err(|_| FinalityError::WrongContext)?;
    verify_signature_for_identity(
        participant_count,
        roster,
        signer_position,
        ActionSignaturePurpose::NoResultAcknowledgement,
        target.body_identity()?,
        signature_bytes,
    )
}

pub fn verify_no_result_release(
    finality: VerifiedFinalityCapability,
    roster: &Roster,
    acknowledgements: &[(u16, Vec<u8>)],
) -> Result<VerifiedNoResultReleaseCapability, FinalityError> {
    if finality.target.target_kind() != FinalityTargetKind::NoResult {
        return Err(FinalityError::WrongTargetKind);
    }
    let participant_count = finality.target.context().participant_count;
    validate_completion_profile(participant_count)?;
    require_roster_identity(roster, finality.target.context().roster_identity)
        .map_err(|_| FinalityError::WrongContext)?;
    if acknowledgements.len() != usize::from(participant_count) {
        return Err(FinalityError::IncompleteNoResultAcknowledgements);
    }
    let mut signer_bitmap = 0_u16;
    for (signer_position, acknowledgement_bytes) in acknowledgements {
        validate_position(participant_count, *signer_position)?;
        let signer_mask = 1_u16 << *signer_position;
        if signer_bitmap & signer_mask != 0 {
            return Err(FinalityError::DuplicateSignature);
        }
        verify_signature_for_identity(
            participant_count,
            roster,
            *signer_position,
            ActionSignaturePurpose::NoResultAcknowledgement,
            finality.target_identity,
            acknowledgement_bytes,
        )?;
        signer_bitmap |= signer_mask;
    }
    let full_roster_bitmap = (1_u16 << participant_count) - 1;
    if signer_bitmap != full_roster_bitmap {
        return Err(FinalityError::IncompleteNoResultAcknowledgements);
    }
    Ok(VerifiedNoResultReleaseCapability { finality })
}

fn verify_finality_signature_for_identity(
    participant_count: u16,
    roster: &Roster,
    signer_position: u16,
    target_identity: Hash512,
    signature_bytes: &[u8],
) -> Result<(), FinalityError> {
    verify_signature_for_identity(
        participant_count,
        roster,
        signer_position,
        ActionSignaturePurpose::Finality,
        target_identity,
        signature_bytes,
    )
}

fn verify_signature_for_identity(
    participant_count: u16,
    roster: &Roster,
    signer_position: u16,
    purpose: ActionSignaturePurpose,
    target_identity: Hash512,
    signature_bytes: &[u8],
) -> Result<(), FinalityError> {
    let carrier = ActionSignatureCarrier::decode(participant_count, signature_bytes)
        .map_err(|_| FinalityError::InvalidSignature)?;
    let verification_key = signing_verification_key(roster, signer_position)
        .map_err(|_| FinalityError::WrongParticipantPosition)?;
    carrier
        .verify(signer_position, purpose, target_identity, verification_key)
        .map_err(|_| FinalityError::InvalidSignature)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SemanticBindings {
    compiler_identity: Hash512,
    circuit_identity: Hash512,
    output_schema_identity: Hash512,
    source_selection_policy_identity: Hash512,
    final_action_policy_identity: Hash512,
    finality_policy_identity: Hash512,
}

fn derive_semantic_bindings(
    participant_count: u16,
    option_count: u16,
    top_count: u16,
) -> Result<SemanticBindings, FinalityError> {
    validate_completion_profile(participant_count)?;
    if option_count != COMPLETION_PROFILE_OPTION_COUNT || !(1..=option_count).contains(&top_count) {
        return Err(FinalityError::WrongContext);
    }
    let compiler_identity = hash_foundation_tuple_512(
        TALLY_COMPILER_IDENTITY_DOMAIN,
        &[CanonicalItem::unsigned16(1)],
    )
    .map_err(|_| FinalityError::InvalidCanonicalEncoding)?;
    let profile = TallyCircuitProfile::new(participant_count, option_count, top_count)
        .map_err(|_| FinalityError::WrongContext)?;
    let circuit = compile_tally_circuit(profile).map_err(|_| FinalityError::WrongContext)?;
    let circuit_bytes = encode_compiled_tally_circuit(&circuit)
        .map_err(|_| FinalityError::InvalidCanonicalEncoding)?;
    let circuit_identity = hash_foundation_tuple_512(
        TALLY_CIRCUIT_IDENTITY_DOMAIN,
        &[
            CanonicalItem::hash512(compiler_identity.into_bytes()),
            CanonicalItem::unsigned16(participant_count),
            CanonicalItem::unsigned16(option_count),
            CanonicalItem::unsigned16(top_count),
            CanonicalItem::variable_bytes(circuit_bytes)
                .map_err(|_| FinalityError::InvalidCanonicalEncoding)?,
        ],
    )
    .map_err(|_| FinalityError::InvalidCanonicalEncoding)?;
    let option_position_bit_width =
        bit_width_for_maximum_value(usize::from(option_count - 1)).max(1);
    let output_bit_count = usize::from(participant_count)
        .checked_add(1)
        .and_then(|value| {
            value.checked_add(usize::from(top_count).checked_mul(option_position_bit_width)?)
        })
        .ok_or(FinalityError::InvalidCanonicalEncoding)?;
    let output_schema_identity = hash_foundation_tuple_512(
        TALLY_OUTPUT_SCHEMA_IDENTITY_DOMAIN,
        &[
            CanonicalItem::unsigned16(1),
            CanonicalItem::unsigned16(participant_count),
            CanonicalItem::unsigned16(option_count),
            CanonicalItem::unsigned16(top_count),
            CanonicalItem::unsigned16(participant_count),
            CanonicalItem::unsigned16(1),
            CanonicalItem::unsigned16(
                u16::try_from(option_position_bit_width)
                    .map_err(|_| FinalityError::InvalidCanonicalEncoding)?,
            ),
            CanonicalItem::unsigned16(
                u16::try_from(output_bit_count)
                    .map_err(|_| FinalityError::InvalidCanonicalEncoding)?,
            ),
            CanonicalItem::unsigned64(OUTPUT_ORDINAL),
        ],
    )
    .map_err(|_| FinalityError::InvalidCanonicalEncoding)?;
    let source_selection_policy_identity = hash_foundation_tuple_512(
        SOURCE_SELECTION_POLICY_IDENTITY_DOMAIN,
        &[
            CanonicalItem::unsigned16(1),
            CanonicalItem::unsigned16(participant_count),
            CanonicalItem::unsigned16(1),
        ],
    )
    .map_err(|_| FinalityError::InvalidCanonicalEncoding)?;
    let final_action_policy_identity = hash_foundation_tuple_512(
        FINAL_ACTION_POLICY_IDENTITY_DOMAIN,
        &[
            CanonicalItem::unsigned16(2),
            CanonicalItem::unsigned16(participant_count),
            CanonicalItem::unsigned16(participant_count),
            CanonicalItem::unsigned16(participant_count),
            CanonicalItem::unsigned16(0),
            CanonicalItem::unsigned64(OUTPUT_ORDINAL),
        ],
    )
    .map_err(|_| FinalityError::InvalidCanonicalEncoding)?;
    let finality_policy_identity = hash_foundation_tuple_512(
        FINALITY_POLICY_IDENTITY_DOMAIN,
        &[
            CanonicalItem::unsigned16(2),
            CanonicalItem::unsigned16(participant_count),
            CanonicalItem::unsigned16(static_fault_bound(participant_count)?),
            CanonicalItem::unsigned16(direct_finality_quorum(participant_count)?),
        ],
    )
    .map_err(|_| FinalityError::InvalidCanonicalEncoding)?;
    Ok(SemanticBindings {
        compiler_identity,
        circuit_identity,
        output_schema_identity,
        source_selection_policy_identity,
        final_action_policy_identity,
        finality_policy_identity,
    })
}

pub fn static_fault_bound(participant_count: u16) -> Result<u16, FinalityError> {
    validate_admitted_participant_count(participant_count)?;
    Ok((participant_count - 1) / 3)
}

pub fn direct_finality_quorum(participant_count: u16) -> Result<u16, FinalityError> {
    let fault_bound = static_fault_bound(participant_count)?;
    let numerator = participant_count
        .checked_add(fault_bound)
        .ok_or(FinalityError::WrongQuorum)?;
    numerator
        .checked_div(2)
        .and_then(|value| value.checked_add(1))
        .ok_or(FinalityError::WrongQuorum)
}

fn validate_admitted_participant_count(participant_count: u16) -> Result<(), FinalityError> {
    if !(MINIMUM_PARTICIPANT_COUNT..=MAXIMUM_PARTICIPANT_COUNT).contains(&participant_count) {
        return Err(FinalityError::WrongParticipantCount);
    }
    Ok(())
}

fn validate_completion_profile(participant_count: u16) -> Result<(), FinalityError> {
    validate_admitted_participant_count(participant_count)?;
    if participant_count != COMPLETION_PROFILE_PARTICIPANT_COUNT {
        return Err(FinalityError::WrongParticipantCount);
    }
    Ok(())
}

fn validate_position(participant_count: u16, position: u16) -> Result<(), FinalityError> {
    validate_admitted_participant_count(participant_count)?;
    if position >= participant_count {
        return Err(FinalityError::WrongParticipantPosition);
    }
    Ok(())
}

fn read_hash512(item: &CanonicalItem) -> Result<Hash512, FinalityError> {
    if item.item_type() != CanonicalItemType::Hash512 {
        return Err(FinalityError::WrongItemTypeOrLength);
    }
    Ok(Hash512::from_bytes(
        item.canonical_bytes()
            .try_into()
            .map_err(|_| FinalityError::WrongItemTypeOrLength)?,
    ))
}

fn read_unsigned16(item: &CanonicalItem) -> Result<u16, FinalityError> {
    if item.item_type() != CanonicalItemType::Unsigned16 {
        return Err(FinalityError::WrongItemTypeOrLength);
    }
    Ok(u16::from_le_bytes(
        item.canonical_bytes()
            .try_into()
            .map_err(|_| FinalityError::WrongItemTypeOrLength)?,
    ))
}

fn read_unsigned64(item: &CanonicalItem) -> Result<u64, FinalityError> {
    if item.item_type() != CanonicalItemType::Unsigned64 {
        return Err(FinalityError::WrongItemTypeOrLength);
    }
    Ok(u64::from_le_bytes(
        item.canonical_bytes()
            .try_into()
            .map_err(|_| FinalityError::WrongItemTypeOrLength)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: u8) -> Hash512 {
        Hash512::from_bytes([byte; Hash512::BYTE_LENGTH])
    }

    fn target(submission_bitmap: u16) -> FinalityTarget {
        let semantic_bindings = derive_semantic_bindings(
            COMPLETION_PROFILE_PARTICIPANT_COUNT,
            COMPLETION_PROFILE_OPTION_COUNT,
            1,
        )
        .expect("semantic bindings");
        FinalityTarget::new(FinalityTargetContext {
            participant_count: COMPLETION_PROFILE_PARTICIPANT_COUNT,
            runtime_identity: hash(1),
            candidate_build_identity: hash(2),
            action_proposal_identity: hash(3),
            action_definition_identity: hash(8),
            roster_identity: hash(4),
            preparation_attempt: 7,
            predecessor_identity: hash(5),
            verified_preparation_root: hash(6),
            compiler_identity: semantic_bindings.compiler_identity,
            circuit_identity: semantic_bindings.circuit_identity,
            option_count: COMPLETION_PROFILE_OPTION_COUNT,
            output_schema_identity: semantic_bindings.output_schema_identity,
            source_inventory_root: hash(7),
            source_submission_bitmap: submission_bitmap,
            source_selection_policy_identity: semantic_bindings.source_selection_policy_identity,
            final_action_policy_identity: semantic_bindings.final_action_policy_identity,
            top_count: 1,
            finality_policy_identity: semantic_bindings.finality_policy_identity,
        })
        .expect("valid finality target")
    }

    #[test]
    fn quorum_is_minimal_for_every_admitted_roster() {
        for participant_count in MINIMUM_PARTICIPANT_COUNT..=MAXIMUM_PARTICIPANT_COUNT {
            let fault_bound = static_fault_bound(participant_count).expect("fault bound");
            let quorum = direct_finality_quorum(participant_count).expect("quorum");
            let stable_intersection =
                i32::from(2 * quorum) - i32::from(participant_count) - i32::from(fault_bound);
            assert!(stable_intersection >= 1);
            let smaller = quorum - 1;
            let smaller_intersection =
                i32::from(2 * smaller) - i32::from(participant_count) - i32::from(fault_bound);
            assert!(smaller_intersection < 1);
        }
        assert_eq!(direct_finality_quorum(10), Ok(7));
    }

    #[test]
    fn quorum_six_has_the_completion_conflict_witness() {
        let left = [0_u16, 1, 2, 3, 4, 5];
        let right = [0_u16, 1, 2, 6, 7, 8];
        let intersection = left
            .iter()
            .filter(|position| right.contains(position))
            .copied()
            .collect::<Vec<_>>();
        assert_eq!(intersection, [0, 1, 2]);
    }

    #[test]
    fn three_malicious_participants_cannot_finalize_two_targets() {
        let roster_mask = (1_u16 << COMPLETION_PROFILE_PARTICIPANT_COUNT) - 1;
        let quorum_masks = (0_u16..=roster_mask)
            .filter(|mask| mask.count_ones() == 7)
            .collect::<Vec<_>>();
        let corrupt_masks = (0_u16..=roster_mask)
            .filter(|mask| mask.count_ones() == 3)
            .collect::<Vec<_>>();
        for left in &quorum_masks {
            for right in &quorum_masks {
                let intersection = left & right;
                for corrupt in &corrupt_masks {
                    let honest_intersection = intersection & !corrupt & roster_mask;
                    assert!(
                        honest_intersection.count_ones() >= 1,
                        "two completion quorums lost their honest intersection"
                    );
                }
            }
        }
    }

    #[test]
    fn target_round_trips_exact_computation_and_no_result_branches() {
        for (submission_bitmap, expected_kind) in [
            (0_u16, FinalityTargetKind::NoResult),
            (1_u16, FinalityTargetKind::Computation),
        ] {
            let target = target(submission_bitmap);
            let encoded = target.encode().expect("encodes");
            assert_eq!(encoded.len(), FINALITY_TARGET_BODY_BYTE_LENGTH);
            assert_eq!(FinalityTarget::decode(&encoded).expect("decodes"), target);
            assert_eq!(target.target_kind(), expected_kind);
            assert_eq!(target.quorum(), 7);
        }
    }

    #[test]
    fn target_binds_every_admitted_top_count() {
        let mut identities = Vec::new();
        for top_count in 1..=COMPLETION_PROFILE_PARTICIPANT_COUNT {
            let semantic_bindings = derive_semantic_bindings(
                COMPLETION_PROFILE_PARTICIPANT_COUNT,
                COMPLETION_PROFILE_OPTION_COUNT,
                top_count,
            )
            .expect("semantic bindings");
            let candidate = FinalityTarget::new(FinalityTargetContext {
                top_count,
                compiler_identity: semantic_bindings.compiler_identity,
                circuit_identity: semantic_bindings.circuit_identity,
                output_schema_identity: semantic_bindings.output_schema_identity,
                source_selection_policy_identity: semantic_bindings
                    .source_selection_policy_identity,
                final_action_policy_identity: semantic_bindings.final_action_policy_identity,
                finality_policy_identity: semantic_bindings.finality_policy_identity,
                ..target(1).context()
            })
            .expect("admitted top count");
            let encoded = candidate.encode().expect("encodes");
            assert_eq!(FinalityTarget::decode(&encoded), Ok(candidate.clone()));
            assert_eq!(candidate.context().top_count, top_count);
            identities.push(candidate.body_identity().expect("identity"));
        }
        identities.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        identities.dedup();
        assert_eq!(
            identities.len(),
            usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT)
        );

        for top_count in [0, COMPLETION_PROFILE_PARTICIPANT_COUNT + 1] {
            assert_eq!(
                FinalityTarget::new(FinalityTargetContext {
                    top_count,
                    ..target(1).context()
                }),
                Err(FinalityError::WrongContext)
            );
        }
    }

    #[test]
    fn target_recomputes_fixed_semantic_bindings_and_binds_external_identities() {
        let baseline = target(1);
        for candidate in [
            FinalityTargetContext {
                compiler_identity: hash(0xa1),
                ..baseline.context()
            },
            FinalityTargetContext {
                circuit_identity: hash(0xa2),
                ..baseline.context()
            },
            FinalityTargetContext {
                output_schema_identity: hash(0xa3),
                ..baseline.context()
            },
            FinalityTargetContext {
                source_selection_policy_identity: hash(0xa4),
                ..baseline.context()
            },
            FinalityTargetContext {
                final_action_policy_identity: hash(0xa5),
                ..baseline.context()
            },
            FinalityTargetContext {
                finality_policy_identity: hash(0xa6),
                ..baseline.context()
            },
            FinalityTargetContext {
                option_count: COMPLETION_PROFILE_OPTION_COUNT - 1,
                ..baseline.context()
            },
        ] {
            assert_eq!(
                FinalityTarget::new(candidate),
                Err(FinalityError::WrongContext)
            );
        }

        for changed in [
            FinalityTarget::new(FinalityTargetContext {
                candidate_build_identity: hash(0xb1),
                ..baseline.context()
            })
            .expect("changed build remains a valid distinct target"),
            FinalityTarget::new(FinalityTargetContext {
                action_definition_identity: hash(0xb2),
                ..baseline.context()
            })
            .expect("changed action definition remains a valid distinct target"),
        ] {
            assert_ne!(
                changed.body_identity().expect("changed identity"),
                baseline.body_identity().expect("baseline identity")
            );
        }
    }

    #[test]
    fn target_accepts_every_roster_submission_bitmap_and_refuses_mutation() {
        for submission_bitmap in 0_u16..(1_u16 << COMPLETION_PROFILE_PARTICIPANT_COUNT) {
            let target = target(submission_bitmap);
            assert_eq!(target.context().source_submission_bitmap, submission_bitmap);
            assert_eq!(
                target.target_kind(),
                if submission_bitmap == 0 {
                    FinalityTargetKind::NoResult
                } else {
                    FinalityTargetKind::Computation
                }
            );
        }
        let context = FinalityTargetContext {
            source_submission_bitmap: 1 << COMPLETION_PROFILE_PARTICIPANT_COUNT,
            ..target(0).context()
        };
        assert_eq!(
            FinalityTarget::new(context),
            Err(FinalityError::UnsupportedSourceInventory)
        );
        let mut encoded = target(1).encode().expect("encodes");
        *encoded.last_mut().expect("last byte") ^= 1;
        assert!(FinalityTarget::decode(&encoded).is_err());

        let context = FinalityTargetContext {
            top_count: 0,
            ..target(0).context()
        };
        assert_eq!(
            FinalityTarget::new(context),
            Err(FinalityError::WrongContext)
        );
    }
}
