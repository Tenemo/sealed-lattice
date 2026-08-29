//! Unactivated direct-MPC realization of the one-AND finality cutout.
//!
//! Every continuation type in this module is minted by a positive verifier or
//! by a participant producer that consumes positively verified local custody.
//! The module is not a suite and does not authorize production dispatch.

use core::fmt;

use zeroize::{Zeroize, Zeroizing};

use crate::{
    foundation::{
        ActionContext, CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION,
        CanonicalCodecError, CanonicalCodecErrorKind, CanonicalDecodeLimits, CanonicalItem,
        CanonicalItemType, CanonicalTuple, FOUNDATION_PROFILE, Hash512, RefusalReason, Roster,
        derive_foundation_roster_parameters, hash_foundation_tuple_512,
    },
    tally_preparation::{
        DIRECT_MPC_CURSOR_CHECKPOINT_KEY_BYTE_LENGTH, DirectMpcCursorError,
        DirectMpcJoinedSubsetMaster, DirectMpcParticipantCursor, DirectMpcPrimeFieldElement,
        DirectMpcPrimeFieldError, DirectMpcPrssContext,
        LocallyJoinedPseudorandomZeroSharingSeedMasters320, evaluate_prime_field_polynomial,
        interpolate_consecutive_prime_field_values,
    },
};

use super::{
    ComputationTargetBody, FragmentError, FragmentVerification, PreEvaluationFinalityScope,
    RequiredEvent, SelectionState, StateOutputIntent, VerifiedFragmentTerminal,
    VerifiedTargetFinality, decode_domain_tuple, encode_domain_tuple, event_domain,
    hash_encoded_object, one_and_circuit_identity, read_fixed_bytes, read_hash, read_signature,
    read_u16, read_variable_bytes, verify_no_result, verify_signature,
    verify_state_output_certificate, verify_target_finality_terminal,
};

const CANDIDATE_IDENTITY_DOMAIN: &str = "sealed-lattice/v1/direct-mpc-one-and/candidate-identity";
const SEED_TERMINAL_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/seed-terminal-identity";
const PREPARATION_SHARE_BODY_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/preparation-share-body";
const PREPARATION_SHARE_CARRIER_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/preparation-share-carrier";
const PREPARATION_TRANSCRIPT_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/preparation-transcript";
const PREPARATION_TRANSCRIPT_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/preparation-transcript-identity";
const PREPARATION_TERMINAL_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/preparation-terminal-identity";
const INPUT_SHARE_COMMITMENT_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/input-share-commitment";
const INPUT_SOURCE_MANIFEST_BODY_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/input-source-manifest-body";
const INPUT_SOURCE_MANIFEST_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/input-source-manifest-identity";
const INPUT_SOURCE_MANIFEST_CARRIER_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/input-source-manifest-carrier";
const INPUT_SHARE_DELIVERY_BODY_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/input-share-delivery-body";
const INPUT_SHARE_DELIVERY_CARRIER_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/input-share-delivery-carrier";
const INPUT_SHARE_ACKNOWLEDGEMENT_BODY_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/input-share-acknowledgement-body";
const INPUT_SHARE_ACKNOWLEDGEMENT_CARRIER_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/input-share-acknowledgement-carrier";
const INPUT_SOURCE_TRANSCRIPT_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/input-source-transcript";
const INPUT_SOURCE_TRANSCRIPT_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/input-source-transcript-identity";
const INPUT_SOURCE_ROOT_DOMAIN: &str = "sealed-lattice/v1/direct-mpc-one-and/input-source-root";
const DECLARATION_BODY_DOMAIN: &str = "sealed-lattice/v1/direct-mpc-one-and/declaration-body";
const DECLARATION_CARRIER_DOMAIN: &str = "sealed-lattice/v1/direct-mpc-one-and/declaration-carrier";
const SELECTED_SET_TRANSCRIPT_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/selected-set-transcript";
const SELECTED_SET_TRANSCRIPT_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/selected-set-transcript-identity";
const SELECTED_SET_ROOT_DOMAIN: &str = "sealed-lattice/v1/direct-mpc-one-and/selected-set-root";
const ACTIVATION_SHARE_BODY_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/activation-share-body";
const ACTIVATION_SHARE_CARRIER_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/activation-share-carrier";
const ACTIVATION_TRANSCRIPT_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/activation-transcript";
const ACTIVATION_TRANSCRIPT_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/activation-transcript-identity";
const OUTPUT_SHARE_BODY_DOMAIN: &str = "sealed-lattice/v1/direct-mpc-one-and/output-share-body";
const OUTPUT_SHARE_CARRIER_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/output-share-carrier";
const OUTPUT_TRANSCRIPT_DOMAIN: &str = "sealed-lattice/v1/direct-mpc-one-and/output-transcript";
const OUTPUT_TRANSCRIPT_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/output-transcript-identity";
const RESULT_IDENTITY_DOMAIN: &str = "sealed-lattice/v1/direct-mpc-one-and/result-identity";
const VERIFICATION_BUNDLE_DOMAIN: &str = "sealed-lattice/v1/direct-mpc-one-and/verification-bundle";
const VERIFICATION_RESPONSE_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/verification-response";
const AUTHORIZED_PHASE_TERMINAL_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/authorized-phase-terminal";
const PHASE_ENDORSEMENT_BODY_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/phase-endorsement-body";
const PHASE_ENDORSEMENT_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/phase-endorsement-identity";
const PHASE_ENDORSEMENT_CARRIER_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/phase-endorsement-carrier";
const AUTHORIZED_PHASE_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/authorized-phase-identity";

const PREPARATION_SHARE_SIGNATURE_CONTEXT: &[u8] =
    b"sealed-lattice/v1/direct-mpc-one-and/preparation-share";
const INPUT_SOURCE_MANIFEST_SIGNATURE_CONTEXT: &[u8] =
    b"sealed-lattice/v1/direct-mpc-one-and/input-source-manifest";
const INPUT_SHARE_DELIVERY_SIGNATURE_CONTEXT: &[u8] =
    b"sealed-lattice/v1/direct-mpc-one-and/input-share-delivery";
const INPUT_SHARE_ACKNOWLEDGEMENT_SIGNATURE_CONTEXT: &[u8] =
    b"sealed-lattice/v1/direct-mpc-one-and/input-share-acknowledgement";
const DECLARATION_SIGNATURE_CONTEXT: &[u8] = b"sealed-lattice/v1/direct-mpc-one-and/declaration";
const ACTIVATION_SHARE_SIGNATURE_CONTEXT: &[u8] =
    b"sealed-lattice/v1/direct-mpc-one-and/activation-share";
const OUTPUT_SHARE_SIGNATURE_CONTEXT: &[u8] = b"sealed-lattice/v1/direct-mpc-one-and/output-share";
const PREPARATION_TERMINAL_OPERATION_KIND: &str = "direct-mpc-preparation-terminal";
const INPUT_SOURCE_TERMINAL_OPERATION_KIND: &str = "direct-mpc-input-source-terminal";
const SELECTED_SET_TERMINAL_OPERATION_KIND: &str = "direct-mpc-selected-set-terminal";
const ACTIVATION_TERMINAL_OPERATION_KIND: &str = "direct-mpc-activation-terminal";
const OUTPUT_TERMINAL_OPERATION_KIND: &str = "direct-mpc-output-terminal";
const ORDINARY_PREPARATION_FIELD_COUNT: u64 = 3;
const ZERO_PREPARATION_FIELD_COUNT: u64 = 1;
const SHARING_DEGREE: usize = FOUNDATION_PROFILE.active_fault_bound as usize;
const PRODUCT_OPENING_DEGREE: usize = SHARING_DEGREE * 2;
const PREPARATION_SHARE_CARRIER_ITEM_COUNT: usize = 3;
const AUTHORIZED_PHASE_FIXED_ITEM_COUNT: usize = 2;
const PHASE_ENDORSEMENT_CARRIER_ITEM_COUNT: usize = 3;
const SIGNED_CARRIER_ITEM_COUNT: usize = 3;
const INPUT_SHARE_COMMITMENT_SALT_BYTE_LENGTH: usize = Hash512::BYTE_LENGTH;
const MAXIMUM_BUNDLE_BYTE_LENGTH: usize = FOUNDATION_PROFILE.maximum_copied_buffer_byte_length;
const MAXIMUM_BUNDLE_ITEM_COUNT: usize = 16;
const MAXIMUM_BUNDLE_ITEM_BYTE_LENGTH: usize = 2 * 1024 * 1024;
const MAXIMUM_BUNDLE_CUMULATIVE_BYTE_LENGTH: usize = 16 * 1024 * 1024;
const MAXIMUM_CEREMONY_EVENT_COUNT: usize = 4;
const VERIFICATION_BUNDLE_FIXED_ITEM_COUNT: usize = 10;

const VERIFICATION_STATUS_PENDING: u16 = 1;
const VERIFICATION_STATUS_NO_RESULT: u16 = 2;
const VERIFICATION_STATUS_CLEAR_RESULT: u16 = 3;
const VERIFICATION_STATUS_ABORT: u16 = 4;
const VERIFICATION_STATUS_REFUSED: u16 = 5;

const NEXT_EVENT_NONE: u16 = 0;
const NEXT_EVENT_PREPARATION_TERMINAL: u16 = 1;
const NEXT_EVENT_INPUT_SOURCE_TERMINAL: u16 = 2;
const NEXT_EVENT_SELECTED_SET_TERMINAL: u16 = 3;
const NEXT_EVENT_NO_RESULT_TERMINAL: u16 = 4;
const NEXT_EVENT_COMPUTATION_TARGET: u16 = 5;
const NEXT_EVENT_TARGET_FINALITY: u16 = 6;
const NEXT_EVENT_ACTIVATION_TERMINAL: u16 = 7;
const NEXT_EVENT_OUTPUT_TERMINAL: u16 = 8;

const ABORT_REASON_NONE: u16 = 0;
const ABORT_REASON_AUTHENTICATED_PREPARATION_INCONSISTENCY: u16 = 1;
const ABORT_REASON_AUTHENTICATED_ACTIVATION_INCONSISTENCY: u16 = 2;
const ABORT_REASON_AUTHENTICATED_OUTPUT_INCONSISTENCY: u16 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
enum DirectMpcOneAndError {
    Canonical(CanonicalCodecError),
    Refusal(RefusalReason),
    Chronology(FragmentError),
    Cursor(DirectMpcCursorError),
    PrimeField(DirectMpcPrimeFieldError),
    WrongContext,
    WrongObject,
    WrongCount,
    WrongOrder,
    DuplicateIdentity,
    MissingPrerequisite,
    MissingInputSource,
    ConsumedState,
    ArithmeticOverflow,
}

impl DirectMpcOneAndError {
    fn refusal_reason(&self) -> RefusalReason {
        match self {
            Self::Canonical(error) => {
                if error.kind == CanonicalCodecErrorKind::LimitExceeded {
                    RefusalReason::OutsideSupportedProfile
                } else {
                    RefusalReason::MalformedEncoding
                }
            }
            Self::Refusal(refusal_reason) => *refusal_reason,
            Self::Chronology(error) => error.refusal_reason(),
            Self::Cursor(_) | Self::ArithmeticOverflow => RefusalReason::WrongContext,
            Self::PrimeField(_) => RefusalReason::InvalidArithmeticRelation,
            Self::WrongContext => RefusalReason::WrongContext,
            Self::WrongObject | Self::WrongCount | Self::WrongOrder => {
                RefusalReason::WrongTypeOrLength
            }
            Self::DuplicateIdentity => RefusalReason::DuplicateIdentity,
            Self::MissingPrerequisite | Self::MissingInputSource => {
                RefusalReason::MissingPrerequisite
            }
            Self::ConsumedState => RefusalReason::ConsumedState,
        }
    }
}

impl fmt::Display for DirectMpcOneAndError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}", self)
    }
}

impl std::error::Error for DirectMpcOneAndError {}

impl From<CanonicalCodecError> for DirectMpcOneAndError {
    fn from(error: CanonicalCodecError) -> Self {
        Self::Canonical(error)
    }
}

impl From<FragmentError> for DirectMpcOneAndError {
    fn from(error: FragmentError) -> Self {
        Self::Chronology(error)
    }
}

impl From<DirectMpcCursorError> for DirectMpcOneAndError {
    fn from(error: DirectMpcCursorError) -> Self {
        Self::Cursor(error)
    }
}

impl From<DirectMpcPrimeFieldError> for DirectMpcOneAndError {
    fn from(error: DirectMpcPrimeFieldError) -> Self {
        Self::PrimeField(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectMpcOneAndContext {
    suite_identity: Hash512,
    action_context_identity: Hash512,
    roster_identity: Hash512,
    participant_count: u16,
    preparation_context_identity: Hash512,
    seed_terminal_identity: Hash512,
    circuit_identity: Hash512,
    candidate_identity: Hash512,
}

impl DirectMpcOneAndContext {
    fn from_public_transcript(
        suite_identity: Hash512,
        action_context_identity: Hash512,
        roster: &Roster,
        preparation_context_identity: Hash512,
        seed_terminal_identity: Hash512,
    ) -> Result<Self, DirectMpcOneAndError> {
        roster
            .validate()
            .map_err(|_| DirectMpcOneAndError::WrongContext)?;
        let roster_identity = roster
            .roster_hash()
            .map_err(|_| DirectMpcOneAndError::WrongContext)?;
        let participant_count = u16::try_from(roster.entries.len())
            .map_err(|_| DirectMpcOneAndError::ArithmeticOverflow)?;
        Self::new_from_identities(
            suite_identity,
            action_context_identity,
            roster_identity,
            participant_count,
            preparation_context_identity,
            seed_terminal_identity,
        )
    }

    fn from_verified_seed_custody(
        action_context: &ActionContext,
        roster: &Roster,
        joined_seed_masters: &LocallyJoinedPseudorandomZeroSharingSeedMasters320,
    ) -> Result<Self, DirectMpcOneAndError> {
        roster
            .validate()
            .map_err(|_| DirectMpcOneAndError::WrongContext)?;
        let roster_identity = roster
            .roster_hash()
            .map_err(|_| DirectMpcOneAndError::WrongContext)?;
        let preparation_context = joined_seed_masters.preparation_context();
        if roster_identity != action_context.roster_hash()
            || preparation_context.roster_hash() != roster_identity
            || preparation_context.action_context_hash() != action_context.context_hash()
        {
            return Err(DirectMpcOneAndError::WrongContext);
        }
        let participant_count = u16::try_from(roster.entries.len())
            .map_err(|_| DirectMpcOneAndError::ArithmeticOverflow)?;
        if preparation_context.participant_count() != participant_count {
            return Err(DirectMpcOneAndError::WrongContext);
        }
        let preparation_context_identity = preparation_context.identity();
        let seed_terminal_identity = derive_seed_terminal_identity(joined_seed_masters)?;
        Self::new(
            action_context,
            roster_identity,
            participant_count,
            preparation_context_identity,
            seed_terminal_identity,
        )
    }

    #[cfg(test)]
    fn for_test(
        action_context: &ActionContext,
        roster: &Roster,
        preparation_context_identity: Hash512,
        seed_terminal_identity: Hash512,
    ) -> Result<Self, DirectMpcOneAndError> {
        roster
            .validate()
            .map_err(|_| DirectMpcOneAndError::WrongContext)?;
        let roster_identity = roster
            .roster_hash()
            .map_err(|_| DirectMpcOneAndError::WrongContext)?;
        if roster_identity != action_context.roster_hash() {
            return Err(DirectMpcOneAndError::WrongContext);
        }
        let participant_count = u16::try_from(roster.entries.len())
            .map_err(|_| DirectMpcOneAndError::ArithmeticOverflow)?;
        Self::new(
            action_context,
            roster_identity,
            participant_count,
            preparation_context_identity,
            seed_terminal_identity,
        )
    }

    fn new(
        action_context: &ActionContext,
        roster_identity: Hash512,
        participant_count: u16,
        preparation_context_identity: Hash512,
        seed_terminal_identity: Hash512,
    ) -> Result<Self, DirectMpcOneAndError> {
        Self::new_from_identities(
            action_context.suite_id(),
            action_context.context_hash(),
            roster_identity,
            participant_count,
            preparation_context_identity,
            seed_terminal_identity,
        )
    }

    fn new_from_identities(
        suite_identity: Hash512,
        action_context_identity: Hash512,
        roster_identity: Hash512,
        participant_count: u16,
        preparation_context_identity: Hash512,
        seed_terminal_identity: Hash512,
    ) -> Result<Self, DirectMpcOneAndError> {
        let roster_parameters = derive_foundation_roster_parameters(participant_count)
            .ok_or(DirectMpcOneAndError::WrongContext)?;
        if roster_parameters.active_fault_bound != FOUNDATION_PROFILE.active_fault_bound
            || roster_parameters.reconstruction_threshold
                != FOUNDATION_PROFILE.reconstruction_threshold
            || roster_parameters.finality_quorum != FOUNDATION_PROFILE.finality_quorum
            || roster_parameters.state_witness_quorum != FOUNDATION_PROFILE.state_witness_quorum
        {
            return Err(DirectMpcOneAndError::WrongContext);
        }
        let circuit_identity = one_and_circuit_identity()?;
        let candidate_identity = hash_foundation_tuple_512(
            CANDIDATE_IDENTITY_DOMAIN,
            &[
                CanonicalItem::hash512(suite_identity.into_bytes()),
                CanonicalItem::hash512(action_context_identity.into_bytes()),
                CanonicalItem::hash512(roster_identity.into_bytes()),
                CanonicalItem::hash512(preparation_context_identity.into_bytes()),
                CanonicalItem::hash512(seed_terminal_identity.into_bytes()),
                CanonicalItem::hash512(circuit_identity.into_bytes()),
            ],
        )?;
        Ok(Self {
            suite_identity,
            action_context_identity,
            roster_identity,
            participant_count,
            preparation_context_identity,
            seed_terminal_identity,
            circuit_identity,
            candidate_identity,
        })
    }

    fn prss_context(self) -> DirectMpcPrssContext {
        DirectMpcPrssContext::new(
            self.candidate_identity,
            self.preparation_context_identity,
            self.seed_terminal_identity,
            self.participant_count,
            ORDINARY_PREPARATION_FIELD_COUNT,
            ZERO_PREPARATION_FIELD_COUNT,
        )
    }
}

fn derive_seed_terminal_identity(
    joined_seed_masters: &LocallyJoinedPseudorandomZeroSharingSeedMasters320,
) -> Result<Hash512, DirectMpcOneAndError> {
    Ok(hash_foundation_tuple_512(
        SEED_TERMINAL_IDENTITY_DOMAIN,
        &[
            CanonicalItem::hash512(joined_seed_masters.parameter_identity().into_bytes()),
            CanonicalItem::hash512(
                joined_seed_masters
                    .preparation_context()
                    .identity()
                    .into_bytes(),
            ),
            CanonicalItem::hash512(joined_seed_masters.root_terminal_identity().into_bytes()),
            CanonicalItem::hash512(
                joined_seed_masters
                    .root_terminal_certificate_identity()
                    .into_bytes(),
            ),
            CanonicalItem::hash512(joined_seed_masters.receipt_terminal_identity().into_bytes()),
            CanonicalItem::hash512(
                joined_seed_masters
                    .receipt_terminal_certificate_identity()
                    .into_bytes(),
            ),
        ],
    )?)
}

struct DirectMpcOneAndInputSourceMaterial {
    context: DirectMpcOneAndContext,
    source_position: u16,
    manifest_body: DirectMpcInputSourceManifestBody,
    delivery_bodies: Box<[DirectMpcInputShareDeliveryBody]>,
}

impl DirectMpcOneAndInputSourceMaterial {
    fn new(
        context: DirectMpcOneAndContext,
        source_position: u16,
        protected_input: bool,
        nonconstant_coefficients: [DirectMpcPrimeFieldElement; SHARING_DEGREE],
        commitment_salts: Box<[[u8; INPUT_SHARE_COMMITMENT_SALT_BYTE_LENGTH]]>,
    ) -> Result<Self, DirectMpcOneAndError> {
        if source_position >= context.participant_count
            || commitment_salts.len() != usize::from(context.participant_count)
        {
            return Err(DirectMpcOneAndError::WrongCount);
        }
        let input_value = if protected_input {
            DirectMpcPrimeFieldElement::ONE
        } else {
            DirectMpcPrimeFieldElement::ZERO
        };
        let mut coefficients = Vec::with_capacity(SHARING_DEGREE + 1);
        coefficients.push(input_value);
        coefficients.extend(nonconstant_coefficients);
        let shares = (0..context.participant_count)
            .map(|participant_position| {
                Ok(evaluate_prime_field_polynomial(
                    &coefficients,
                    DirectMpcPrimeFieldElement::from_u16(
                        participant_position
                            .checked_add(1)
                            .ok_or(DirectMpcOneAndError::ArithmeticOverflow)?,
                    ),
                ))
            })
            .collect::<Result<Vec<_>, DirectMpcOneAndError>>()?;
        let commitments = shares
            .iter()
            .copied()
            .zip(commitment_salts.iter())
            .enumerate()
            .map(|(recipient_position, (share, salt))| {
                derive_input_share_commitment(
                    context,
                    source_position,
                    u16::try_from(recipient_position)
                        .map_err(|_| DirectMpcOneAndError::ArithmeticOverflow)?,
                    share,
                    *salt,
                )
            })
            .collect::<Result<Vec<_>, DirectMpcOneAndError>>()?;
        let manifest_body = DirectMpcInputSourceManifestBody {
            candidate_identity: context.candidate_identity,
            action_context_identity: context.action_context_identity,
            participant_count: context.participant_count,
            source_position,
            commitments: commitments.into_boxed_slice(),
        };
        let manifest_identity = manifest_body.identity()?;
        let delivery_bodies = shares
            .into_iter()
            .zip(commitment_salts.into_vec())
            .enumerate()
            .map(|(recipient_position, (share, commitment_salt))| {
                Ok(DirectMpcInputShareDeliveryBody {
                    candidate_identity: context.candidate_identity,
                    manifest_identity,
                    source_position,
                    recipient_position: u16::try_from(recipient_position)
                        .map_err(|_| DirectMpcOneAndError::ArithmeticOverflow)?,
                    share,
                    commitment_salt,
                })
            })
            .collect::<Result<Vec<_>, DirectMpcOneAndError>>()?
            .into_boxed_slice();
        Ok(Self {
            context,
            source_position,
            manifest_body,
            delivery_bodies,
        })
    }

    fn manifest_body_bytes(&self) -> Result<Vec<u8>, DirectMpcOneAndError> {
        self.manifest_body.canonical_bytes()
    }

    fn delivery_body_bytes(
        &self,
        recipient_position: u16,
    ) -> Result<Zeroizing<Vec<u8>>, DirectMpcOneAndError> {
        let delivery = self
            .delivery_bodies
            .get(usize::from(recipient_position))
            .ok_or(DirectMpcOneAndError::WrongContext)?;
        Ok(Zeroizing::new(delivery.canonical_bytes()?))
    }
}

impl Drop for DirectMpcOneAndInputSourceMaterial {
    fn drop(&mut self) {
        for delivery in &mut self.delivery_bodies {
            delivery.share.zeroize();
            delivery.commitment_salt.zeroize();
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DirectMpcInputSourceManifestBody {
    candidate_identity: Hash512,
    action_context_identity: Hash512,
    participant_count: u16,
    source_position: u16,
    commitments: Box<[Hash512]>,
}

impl DirectMpcInputSourceManifestBody {
    fn canonical_bytes(&self) -> Result<Vec<u8>, DirectMpcOneAndError> {
        let mut items = Vec::with_capacity(self.commitments.len() + 4);
        items.push(CanonicalItem::hash512(self.candidate_identity.into_bytes()));
        items.push(CanonicalItem::hash512(
            self.action_context_identity.into_bytes(),
        ));
        items.push(CanonicalItem::unsigned16(self.participant_count));
        items.push(CanonicalItem::unsigned16(self.source_position));
        for commitment in &self.commitments {
            items.push(CanonicalItem::hash512(commitment.into_bytes()));
        }
        Ok(encode_domain_tuple(
            INPUT_SOURCE_MANIFEST_BODY_DOMAIN,
            items,
        )?)
    }

    fn identity(&self) -> Result<Hash512, DirectMpcOneAndError> {
        Ok(hash_encoded_object(
            INPUT_SOURCE_MANIFEST_IDENTITY_DOMAIN,
            &self.canonical_bytes()?,
        )?)
    }

    fn decode(bytes: &[u8]) -> Result<Self, DirectMpcOneAndError> {
        let tuple = decode_domain_tuple(bytes, INPUT_SOURCE_MANIFEST_BODY_DOMAIN)?;
        if tuple.items.len() < 5 {
            return Err(DirectMpcOneAndError::WrongCount);
        }
        let participant_count = read_u16(&tuple.items[3])?;
        if tuple.items.len() != usize::from(participant_count) + 5 {
            return Err(DirectMpcOneAndError::WrongCount);
        }
        let commitments = tuple.items[5..]
            .iter()
            .map(read_hash)
            .collect::<Result<Vec<_>, _>>()?
            .into_boxed_slice();
        Ok(Self {
            candidate_identity: read_hash(&tuple.items[1])?,
            action_context_identity: read_hash(&tuple.items[2])?,
            participant_count,
            source_position: read_u16(&tuple.items[4])?,
            commitments,
        })
    }
}

#[derive(Clone, PartialEq, Eq)]
struct DirectMpcInputShareDeliveryBody {
    candidate_identity: Hash512,
    manifest_identity: Hash512,
    source_position: u16,
    recipient_position: u16,
    share: DirectMpcPrimeFieldElement,
    commitment_salt: [u8; INPUT_SHARE_COMMITMENT_SALT_BYTE_LENGTH],
}

impl DirectMpcInputShareDeliveryBody {
    fn canonical_bytes(&self) -> Result<Vec<u8>, DirectMpcOneAndError> {
        Ok(encode_domain_tuple(
            INPUT_SHARE_DELIVERY_BODY_DOMAIN,
            vec![
                CanonicalItem::hash512(self.candidate_identity.into_bytes()),
                CanonicalItem::hash512(self.manifest_identity.into_bytes()),
                CanonicalItem::unsigned16(self.source_position),
                CanonicalItem::unsigned16(self.recipient_position),
                CanonicalItem::fixed_bytes(self.share.canonical_bytes())?,
                CanonicalItem::fixed_bytes(self.commitment_salt)?,
            ],
        )?)
    }

    fn decode(bytes: &[u8]) -> Result<Self, DirectMpcOneAndError> {
        let tuple = decode_domain_tuple(bytes, INPUT_SHARE_DELIVERY_BODY_DOMAIN)?;
        if tuple.items.len() != 7 {
            return Err(DirectMpcOneAndError::WrongCount);
        }
        Ok(Self {
            candidate_identity: read_hash(&tuple.items[1])?,
            manifest_identity: read_hash(&tuple.items[2])?,
            source_position: read_u16(&tuple.items[3])?,
            recipient_position: read_u16(&tuple.items[4])?,
            share: DirectMpcPrimeFieldElement::from_canonical_bytes(&read_fixed_bytes::<3>(
                &tuple.items[5],
            )?)?,
            commitment_salt: read_fixed_bytes(&tuple.items[6])?,
        })
    }
}

impl fmt::Debug for DirectMpcInputShareDeliveryBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DirectMpcInputShareDeliveryBody")
            .field("candidate_identity", &self.candidate_identity)
            .field("manifest_identity", &self.manifest_identity)
            .field("source_position", &self.source_position)
            .field("recipient_position", &self.recipient_position)
            .field("share", &"[redacted]")
            .field("commitment_salt", &"[redacted]")
            .finish()
    }
}

impl Zeroize for DirectMpcInputShareDeliveryBody {
    fn zeroize(&mut self) {
        self.share.zeroize();
        self.commitment_salt.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VerifiedDirectMpcInputSourceManifest {
    body: DirectMpcInputSourceManifestBody,
    identity: Hash512,
}

fn verify_input_source_manifest(
    context: DirectMpcOneAndContext,
    roster: &Roster,
    carrier_bytes: &[u8],
) -> Result<VerifiedDirectMpcInputSourceManifest, DirectMpcOneAndError> {
    let carrier = decode_domain_tuple(carrier_bytes, INPUT_SOURCE_MANIFEST_CARRIER_DOMAIN)?;
    if carrier.items.len() != SIGNED_CARRIER_ITEM_COUNT {
        return Err(DirectMpcOneAndError::WrongCount);
    }
    let body_bytes = read_variable_bytes(&carrier.items[1])?;
    let body = DirectMpcInputSourceManifestBody::decode(body_bytes)?;
    if body.candidate_identity != context.candidate_identity
        || body.action_context_identity != context.action_context_identity
        || body.participant_count != context.participant_count
        || body.source_position >= context.participant_count
        || body.commitments.len() != usize::from(context.participant_count)
    {
        return Err(DirectMpcOneAndError::WrongContext);
    }
    let signature = read_signature(&carrier.items[2])?;
    verify_signature(
        roster,
        body.source_position,
        body_bytes,
        &signature,
        INPUT_SOURCE_MANIFEST_SIGNATURE_CONTEXT,
    )?;
    let identity = body.identity()?;
    Ok(VerifiedDirectMpcInputSourceManifest { body, identity })
}

struct VerifiedDirectMpcInputShare {
    context: DirectMpcOneAndContext,
    manifest_identity: Hash512,
    source_position: u16,
    recipient_position: u16,
    commitment: Hash512,
    share: DirectMpcPrimeFieldElement,
}

impl VerifiedDirectMpcInputShare {
    fn acknowledgement_body(&self) -> DirectMpcInputShareAcknowledgementBody {
        DirectMpcInputShareAcknowledgementBody {
            candidate_identity: self.context.candidate_identity,
            manifest_identity: self.manifest_identity,
            source_position: self.source_position,
            recipient_position: self.recipient_position,
            commitment: self.commitment,
        }
    }
}

impl Drop for VerifiedDirectMpcInputShare {
    fn drop(&mut self) {
        self.share.zeroize();
    }
}

fn verify_input_share_delivery(
    context: DirectMpcOneAndContext,
    roster: &Roster,
    manifest_carrier_bytes: &[u8],
    expected_recipient_position: u16,
    delivery_carrier_bytes: &[u8],
) -> Result<VerifiedDirectMpcInputShare, DirectMpcOneAndError> {
    let manifest = verify_input_source_manifest(context, roster, manifest_carrier_bytes)?;
    if expected_recipient_position >= context.participant_count {
        return Err(DirectMpcOneAndError::WrongContext);
    }
    let carrier = decode_domain_tuple(delivery_carrier_bytes, INPUT_SHARE_DELIVERY_CARRIER_DOMAIN)?;
    if carrier.items.len() != SIGNED_CARRIER_ITEM_COUNT {
        return Err(DirectMpcOneAndError::WrongCount);
    }
    let body_bytes = read_variable_bytes(&carrier.items[1])?;
    let body = Zeroizing::new(DirectMpcInputShareDeliveryBody::decode(body_bytes)?);
    if body.candidate_identity != context.candidate_identity
        || body.manifest_identity != manifest.identity
        || body.source_position != manifest.body.source_position
        || body.recipient_position != expected_recipient_position
    {
        return Err(DirectMpcOneAndError::WrongContext);
    }
    let signature = read_signature(&carrier.items[2])?;
    verify_signature(
        roster,
        body.source_position,
        body_bytes,
        &signature,
        INPUT_SHARE_DELIVERY_SIGNATURE_CONTEXT,
    )?;
    let commitment = derive_input_share_commitment(
        context,
        body.source_position,
        body.recipient_position,
        body.share,
        body.commitment_salt,
    )?;
    if manifest.body.commitments[usize::from(body.recipient_position)] != commitment {
        return Err(DirectMpcOneAndError::WrongContext);
    }
    Ok(VerifiedDirectMpcInputShare {
        context,
        manifest_identity: manifest.identity,
        source_position: body.source_position,
        recipient_position: body.recipient_position,
        commitment,
        share: body.share,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectMpcInputShareAcknowledgementBody {
    candidate_identity: Hash512,
    manifest_identity: Hash512,
    source_position: u16,
    recipient_position: u16,
    commitment: Hash512,
}

impl DirectMpcInputShareAcknowledgementBody {
    fn canonical_bytes(self) -> Result<Vec<u8>, DirectMpcOneAndError> {
        Ok(encode_domain_tuple(
            INPUT_SHARE_ACKNOWLEDGEMENT_BODY_DOMAIN,
            vec![
                CanonicalItem::hash512(self.candidate_identity.into_bytes()),
                CanonicalItem::hash512(self.manifest_identity.into_bytes()),
                CanonicalItem::unsigned16(self.source_position),
                CanonicalItem::unsigned16(self.recipient_position),
                CanonicalItem::hash512(self.commitment.into_bytes()),
            ],
        )?)
    }

    fn decode(bytes: &[u8]) -> Result<Self, DirectMpcOneAndError> {
        let tuple = decode_domain_tuple(bytes, INPUT_SHARE_ACKNOWLEDGEMENT_BODY_DOMAIN)?;
        if tuple.items.len() != 6 {
            return Err(DirectMpcOneAndError::WrongCount);
        }
        Ok(Self {
            candidate_identity: read_hash(&tuple.items[1])?,
            manifest_identity: read_hash(&tuple.items[2])?,
            source_position: read_u16(&tuple.items[3])?,
            recipient_position: read_u16(&tuple.items[4])?,
            commitment: read_hash(&tuple.items[5])?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VerifiedDirectMpcInputSource {
    context: DirectMpcOneAndContext,
    preparation_identity: Hash512,
    manifest_identity: Hash512,
    source_position: u16,
    root: Hash512,
}

fn verify_input_source_terminal(
    context: DirectMpcOneAndContext,
    preparation: &VerifiedDirectMpcOneAndPreparation,
    roster: &Roster,
    terminal_bytes: Option<&[u8]>,
) -> Result<Option<VerifiedDirectMpcInputSource>, DirectMpcOneAndError> {
    let Some(terminal_bytes) = terminal_bytes else {
        return Ok(None);
    };
    if preparation.context != context {
        return Err(DirectMpcOneAndError::WrongContext);
    }
    let semantic_body = authorized_phase_semantic_body(terminal_bytes)?;
    let transcript = decode_domain_tuple(&semantic_body, INPUT_SOURCE_TRANSCRIPT_DOMAIN)?;
    let expected_item_count = usize::from(context.participant_count)
        .checked_add(2)
        .ok_or(DirectMpcOneAndError::ArithmeticOverflow)?;
    if transcript.items.len() != expected_item_count {
        return Err(DirectMpcOneAndError::WrongCount);
    }
    let manifest_carrier_bytes = read_variable_bytes(&transcript.items[1])?;
    let manifest = verify_input_source_manifest(context, roster, manifest_carrier_bytes)?;
    let mut normalized_items = Vec::with_capacity(expected_item_count - 1);
    normalized_items.push(CanonicalItem::variable_bytes(
        &manifest.body.canonical_bytes()?,
    )?);
    for (expected_position, acknowledgement_item) in transcript.items[2..].iter().enumerate() {
        let carrier = decode_domain_tuple(
            read_variable_bytes(acknowledgement_item)?,
            INPUT_SHARE_ACKNOWLEDGEMENT_CARRIER_DOMAIN,
        )?;
        if carrier.items.len() != SIGNED_CARRIER_ITEM_COUNT {
            return Err(DirectMpcOneAndError::WrongCount);
        }
        let body_bytes = read_variable_bytes(&carrier.items[1])?;
        let body = DirectMpcInputShareAcknowledgementBody::decode(body_bytes)?;
        if body.candidate_identity != context.candidate_identity
            || body.manifest_identity != manifest.identity
            || body.source_position != manifest.body.source_position
            || usize::from(body.recipient_position) != expected_position
            || body.commitment != manifest.body.commitments[expected_position]
        {
            return Err(DirectMpcOneAndError::WrongContext);
        }
        let signature = read_signature(&carrier.items[2])?;
        verify_signature(
            roster,
            body.recipient_position,
            body_bytes,
            &signature,
            INPUT_SHARE_ACKNOWLEDGEMENT_SIGNATURE_CONTEXT,
        )?;
        normalized_items.push(CanonicalItem::variable_bytes(body_bytes)?);
    }
    let transcript_identity =
        hash_foundation_tuple_512(INPUT_SOURCE_TRANSCRIPT_IDENTITY_DOMAIN, &normalized_items)?;
    verify_authorized_phase_terminal(
        context,
        roster,
        INPUT_SOURCE_TERMINAL_OPERATION_KIND,
        context.seed_terminal_identity,
        preparation.identity,
        transcript_identity,
        terminal_bytes,
    )?;
    let root = hash_foundation_tuple_512(
        INPUT_SOURCE_ROOT_DOMAIN,
        &[
            CanonicalItem::hash512(context.candidate_identity.into_bytes()),
            CanonicalItem::hash512(preparation.identity.into_bytes()),
            CanonicalItem::hash512(manifest.identity.into_bytes()),
            CanonicalItem::hash512(transcript_identity.into_bytes()),
        ],
    )?;
    Ok(Some(VerifiedDirectMpcInputSource {
        context,
        preparation_identity: preparation.identity,
        manifest_identity: manifest.identity,
        source_position: manifest.body.source_position,
        root,
    }))
}

fn derive_input_share_commitment(
    context: DirectMpcOneAndContext,
    source_position: u16,
    recipient_position: u16,
    share: DirectMpcPrimeFieldElement,
    commitment_salt: [u8; INPUT_SHARE_COMMITMENT_SALT_BYTE_LENGTH],
) -> Result<Hash512, DirectMpcOneAndError> {
    Ok(hash_foundation_tuple_512(
        INPUT_SHARE_COMMITMENT_DOMAIN,
        &[
            CanonicalItem::hash512(context.candidate_identity.into_bytes()),
            CanonicalItem::hash512(context.action_context_identity.into_bytes()),
            CanonicalItem::unsigned16(source_position),
            CanonicalItem::unsigned16(recipient_position),
            CanonicalItem::fixed_bytes(share.canonical_bytes())?,
            CanonicalItem::fixed_bytes(commitment_salt)?,
        ],
    )?)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectMpcOneAndDeclarationBody {
    candidate_identity: Hash512,
    action_context_identity: Hash512,
    participant_position: u16,
    submits_input: bool,
    input_source_root: Hash512,
}

impl DirectMpcOneAndDeclarationBody {
    fn submit(
        context: DirectMpcOneAndContext,
        participant_position: u16,
        input_source_root: Hash512,
    ) -> Result<Self, DirectMpcOneAndError> {
        if participant_position >= context.participant_count {
            return Err(DirectMpcOneAndError::WrongContext);
        }
        Ok(Self {
            candidate_identity: context.candidate_identity,
            action_context_identity: context.action_context_identity,
            participant_position,
            submits_input: true,
            input_source_root,
        })
    }

    fn abstain(
        context: DirectMpcOneAndContext,
        participant_position: u16,
    ) -> Result<Self, DirectMpcOneAndError> {
        if participant_position >= context.participant_count {
            return Err(DirectMpcOneAndError::WrongContext);
        }
        Ok(Self {
            candidate_identity: context.candidate_identity,
            action_context_identity: context.action_context_identity,
            participant_position,
            submits_input: false,
            input_source_root: zero_hash(),
        })
    }

    fn canonical_bytes(self) -> Result<Vec<u8>, DirectMpcOneAndError> {
        Ok(encode_domain_tuple(
            DECLARATION_BODY_DOMAIN,
            vec![
                CanonicalItem::hash512(self.candidate_identity.into_bytes()),
                CanonicalItem::hash512(self.action_context_identity.into_bytes()),
                CanonicalItem::unsigned16(self.participant_position),
                CanonicalItem::boolean(self.submits_input),
                CanonicalItem::hash512(self.input_source_root.into_bytes()),
            ],
        )?)
    }

    fn decode(bytes: &[u8]) -> Result<Self, DirectMpcOneAndError> {
        let tuple = decode_domain_tuple(bytes, DECLARATION_BODY_DOMAIN)?;
        if tuple.items.len() != 6 {
            return Err(DirectMpcOneAndError::WrongCount);
        }
        let submits_input = read_boolean(&tuple.items[4])?;
        let input_source_root = read_hash(&tuple.items[5])?;
        if !submits_input && input_source_root != zero_hash() {
            return Err(DirectMpcOneAndError::WrongContext);
        }
        Ok(Self {
            candidate_identity: read_hash(&tuple.items[1])?,
            action_context_identity: read_hash(&tuple.items[2])?,
            participant_position: read_u16(&tuple.items[3])?,
            submits_input,
            input_source_root,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DirectMpcOneAndSelectionState {
    AllAbstained,
    Nonempty {
        input_source: Box<VerifiedDirectMpcInputSource>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VerifiedDirectMpcOneAndSelectedSet {
    context: DirectMpcOneAndContext,
    preparation_identity: Hash512,
    identity: Hash512,
    root: Hash512,
    state: DirectMpcOneAndSelectionState,
}

fn verify_selected_set_terminal(
    context: DirectMpcOneAndContext,
    preparation: &VerifiedDirectMpcOneAndPreparation,
    input_source: Option<&VerifiedDirectMpcInputSource>,
    roster: &Roster,
    terminal_bytes: Option<&[u8]>,
) -> Result<Option<VerifiedDirectMpcOneAndSelectedSet>, DirectMpcOneAndError> {
    let Some(terminal_bytes) = terminal_bytes else {
        return Ok(None);
    };
    if preparation.context != context
        || input_source.is_some_and(|source| {
            source.context != context || source.preparation_identity != preparation.identity
        })
    {
        return Err(DirectMpcOneAndError::WrongContext);
    }
    let semantic_body = authorized_phase_semantic_body(terminal_bytes)?;
    let transcript = decode_domain_tuple(&semantic_body, SELECTED_SET_TRANSCRIPT_DOMAIN)?;
    let expected_item_count = usize::from(context.participant_count)
        .checked_add(1)
        .ok_or(DirectMpcOneAndError::ArithmeticOverflow)?;
    if transcript.items.len() != expected_item_count {
        return Err(DirectMpcOneAndError::WrongCount);
    }
    let mut normalized_items = Vec::with_capacity(usize::from(context.participant_count));
    let mut missing_input_source_submission_count = 0_usize;
    for (expected_position, declaration_item) in transcript.items[1..].iter().enumerate() {
        let carrier = decode_domain_tuple(
            read_variable_bytes(declaration_item)?,
            DECLARATION_CARRIER_DOMAIN,
        )?;
        if carrier.items.len() != SIGNED_CARRIER_ITEM_COUNT {
            return Err(DirectMpcOneAndError::WrongCount);
        }
        let body_bytes = read_variable_bytes(&carrier.items[1])?;
        let body = DirectMpcOneAndDeclarationBody::decode(body_bytes)?;
        let expected_position = u16::try_from(expected_position)
            .map_err(|_| DirectMpcOneAndError::ArithmeticOverflow)?;
        let signature = read_signature(&carrier.items[2])?;
        verify_signature(
            roster,
            body.participant_position,
            body_bytes,
            &signature,
            DECLARATION_SIGNATURE_CONTEXT,
        )?;
        let expected_submission = input_source
            .filter(|source| source.source_position == expected_position)
            .map(|source| source.root);
        if input_source.is_none() && body.submits_input {
            missing_input_source_submission_count = missing_input_source_submission_count
                .checked_add(1)
                .ok_or(DirectMpcOneAndError::ArithmeticOverflow)?;
        }
        if body.candidate_identity != context.candidate_identity
            || body.action_context_identity != context.action_context_identity
            || body.participant_position != expected_position
            || (input_source.is_some()
                && (body.submits_input != expected_submission.is_some()
                    || body.input_source_root != expected_submission.unwrap_or_else(zero_hash)))
            || (input_source.is_none()
                && !body.submits_input
                && body.input_source_root != zero_hash())
        {
            return Err(DirectMpcOneAndError::WrongContext);
        }
        normalized_items.push(CanonicalItem::variable_bytes(body_bytes)?);
    }
    let transcript_identity =
        hash_foundation_tuple_512(SELECTED_SET_TRANSCRIPT_IDENTITY_DOMAIN, &normalized_items)?;
    let authorized = verify_authorized_phase_terminal(
        context,
        roster,
        SELECTED_SET_TERMINAL_OPERATION_KIND,
        context.action_context_identity,
        preparation.identity,
        transcript_identity,
        terminal_bytes,
    )?;
    if missing_input_source_submission_count != 0 {
        return if missing_input_source_submission_count == 1 {
            Err(DirectMpcOneAndError::MissingInputSource)
        } else {
            Err(DirectMpcOneAndError::WrongContext)
        };
    }
    let root = hash_foundation_tuple_512(
        SELECTED_SET_ROOT_DOMAIN,
        &[
            CanonicalItem::hash512(context.candidate_identity.into_bytes()),
            CanonicalItem::hash512(preparation.identity.into_bytes()),
            CanonicalItem::hash512(transcript_identity.into_bytes()),
        ],
    )?;
    let state = match input_source {
        Some(source) => DirectMpcOneAndSelectionState::Nonempty {
            input_source: Box::new(source.clone()),
        },
        None => DirectMpcOneAndSelectionState::AllAbstained,
    };
    Ok(Some(VerifiedDirectMpcOneAndSelectedSet {
        context,
        preparation_identity: preparation.identity,
        identity: authorized.identity,
        root,
        state,
    }))
}

fn zero_hash() -> Hash512 {
    Hash512::from_bytes([0; Hash512::BYTE_LENGTH])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectMpcOneAndTarget {
    scope: PreEvaluationFinalityScope,
    body: ComputationTargetBody,
    identity: Hash512,
}

fn derive_direct_mpc_one_and_target(
    action_context: &ActionContext,
    roster: &Roster,
    preparation: &VerifiedDirectMpcOneAndPreparation,
    selected_set: &VerifiedDirectMpcOneAndSelectedSet,
) -> Result<Option<DirectMpcOneAndTarget>, DirectMpcOneAndError> {
    if action_context.suite_id() != preparation.context.suite_identity
        || action_context.context_hash() != preparation.context.action_context_identity
        || action_context.roster_hash() != preparation.context.roster_identity
    {
        return Err(DirectMpcOneAndError::WrongContext);
    }
    derive_direct_mpc_one_and_target_from_context(roster, preparation, selected_set)
}

fn derive_direct_mpc_one_and_target_from_context(
    roster: &Roster,
    preparation: &VerifiedDirectMpcOneAndPreparation,
    selected_set: &VerifiedDirectMpcOneAndSelectedSet,
) -> Result<Option<DirectMpcOneAndTarget>, DirectMpcOneAndError> {
    if preparation.context != selected_set.context
        || selected_set.preparation_identity != preparation.identity
    {
        return Err(DirectMpcOneAndError::WrongContext);
    }
    let DirectMpcOneAndSelectionState::Nonempty { input_source } = &selected_set.state else {
        return Ok(None);
    };
    let context = preparation.context;
    let scope = PreEvaluationFinalityScope::new_from_identities(
        context.suite_identity,
        context.action_context_identity,
        context.roster_identity,
        roster,
        preparation.identity,
        selected_set.root,
        SelectionState::Nonempty {
            input_source_root: input_source.root,
            activation_holder_position: input_source.source_position,
            garbling_contributor_position: input_source.source_position,
        },
    )?;
    if scope.suite_identity != preparation.context.suite_identity
        || scope.action_context_identity != preparation.context.action_context_identity
        || scope.roster_identity != preparation.context.roster_identity
        || scope.circuit_identity != preparation.context.circuit_identity
    {
        return Err(DirectMpcOneAndError::WrongContext);
    }
    let body = ComputationTargetBody::new(scope)?;
    let identity = body.identity()?;
    Ok(Some(DirectMpcOneAndTarget {
        scope,
        body,
        identity,
    }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectMpcActivationShareBody {
    candidate_identity: Hash512,
    target_identity: Hash512,
    finality_identity: Hash512,
    preparation_identity: Hash512,
    input_source_root: Hash512,
    manifest_identity: Hash512,
    participant_position: u16,
    opened_input_difference: DirectMpcPrimeFieldElement,
    opened_public_input_difference: DirectMpcPrimeFieldElement,
}

impl DirectMpcActivationShareBody {
    fn canonical_bytes(self) -> Result<Vec<u8>, DirectMpcOneAndError> {
        Ok(encode_domain_tuple(
            ACTIVATION_SHARE_BODY_DOMAIN,
            vec![
                CanonicalItem::hash512(self.candidate_identity.into_bytes()),
                CanonicalItem::hash512(self.target_identity.into_bytes()),
                CanonicalItem::hash512(self.finality_identity.into_bytes()),
                CanonicalItem::hash512(self.preparation_identity.into_bytes()),
                CanonicalItem::hash512(self.input_source_root.into_bytes()),
                CanonicalItem::hash512(self.manifest_identity.into_bytes()),
                CanonicalItem::unsigned16(self.participant_position),
                CanonicalItem::fixed_bytes(self.opened_input_difference.canonical_bytes())?,
                CanonicalItem::fixed_bytes(self.opened_public_input_difference.canonical_bytes())?,
            ],
        )?)
    }

    fn decode(bytes: &[u8]) -> Result<Self, DirectMpcOneAndError> {
        let tuple = decode_domain_tuple(bytes, ACTIVATION_SHARE_BODY_DOMAIN)?;
        if tuple.items.len() != 10 {
            return Err(DirectMpcOneAndError::WrongCount);
        }
        Ok(Self {
            candidate_identity: read_hash(&tuple.items[1])?,
            target_identity: read_hash(&tuple.items[2])?,
            finality_identity: read_hash(&tuple.items[3])?,
            preparation_identity: read_hash(&tuple.items[4])?,
            input_source_root: read_hash(&tuple.items[5])?,
            manifest_identity: read_hash(&tuple.items[6])?,
            participant_position: read_u16(&tuple.items[7])?,
            opened_input_difference: DirectMpcPrimeFieldElement::from_canonical_bytes(
                &read_fixed_bytes::<3>(&tuple.items[8])?,
            )?,
            opened_public_input_difference: DirectMpcPrimeFieldElement::from_canonical_bytes(
                &read_fixed_bytes::<3>(&tuple.items[9])?,
            )?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VerifiedDirectMpcOneAndActivation {
    context: DirectMpcOneAndContext,
    target_identity: Hash512,
    finality_identity: Hash512,
    preparation_identity: Hash512,
    input_source_root: Hash512,
    manifest_identity: Hash512,
    identity: Hash512,
    opened_input_difference: DirectMpcPrimeFieldElement,
    opened_public_input_difference: DirectMpcPrimeFieldElement,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DirectMpcActivationVerification {
    Verified(Box<VerifiedDirectMpcOneAndActivation>),
    Burn { terminal_identity: Hash512 },
}

fn verify_activation_terminal(
    context: DirectMpcOneAndContext,
    preparation: &VerifiedDirectMpcOneAndPreparation,
    selected_set: &VerifiedDirectMpcOneAndSelectedSet,
    target: DirectMpcOneAndTarget,
    finality: VerifiedTargetFinality,
    roster: &Roster,
    terminal_bytes: &[u8],
) -> Result<DirectMpcActivationVerification, DirectMpcOneAndError> {
    let DirectMpcOneAndSelectionState::Nonempty { input_source } = &selected_set.state else {
        return Err(DirectMpcOneAndError::MissingPrerequisite);
    };
    if preparation.context != context
        || selected_set.context != context
        || target.scope.preparation_terminal_identity != preparation.identity
        || finality.target_identity != target.identity
    {
        return Err(DirectMpcOneAndError::WrongContext);
    }
    let semantic_body = authorized_phase_semantic_body(terminal_bytes)?;
    let transcript = decode_domain_tuple(&semantic_body, ACTIVATION_TRANSCRIPT_DOMAIN)?;
    let expected_item_count = usize::from(context.participant_count)
        .checked_add(1)
        .ok_or(DirectMpcOneAndError::ArithmeticOverflow)?;
    if transcript.items.len() != expected_item_count {
        return Err(DirectMpcOneAndError::WrongCount);
    }
    let mut input_differences = Vec::with_capacity(usize::from(context.participant_count));
    let mut public_input_differences = Vec::with_capacity(usize::from(context.participant_count));
    let mut normalized_items = Vec::with_capacity(usize::from(context.participant_count));
    for (expected_position, share_item) in transcript.items[1..].iter().enumerate() {
        let carrier = decode_domain_tuple(
            read_variable_bytes(share_item)?,
            ACTIVATION_SHARE_CARRIER_DOMAIN,
        )?;
        if carrier.items.len() != SIGNED_CARRIER_ITEM_COUNT {
            return Err(DirectMpcOneAndError::WrongCount);
        }
        let body_bytes = read_variable_bytes(&carrier.items[1])?;
        let body = DirectMpcActivationShareBody::decode(body_bytes)?;
        if body.candidate_identity != context.candidate_identity
            || body.target_identity != target.identity
            || body.finality_identity != finality.finality_identity
            || body.preparation_identity != preparation.identity
            || body.input_source_root != input_source.root
            || body.manifest_identity != input_source.manifest_identity
            || usize::from(body.participant_position) != expected_position
        {
            return Err(DirectMpcOneAndError::WrongContext);
        }
        let signature = read_signature(&carrier.items[2])?;
        verify_signature(
            roster,
            body.participant_position,
            body_bytes,
            &signature,
            ACTIVATION_SHARE_SIGNATURE_CONTEXT,
        )?;
        input_differences.push(body.opened_input_difference);
        public_input_differences.push(body.opened_public_input_difference);
        normalized_items.push(CanonicalItem::variable_bytes(body_bytes)?);
    }
    let transcript_identity =
        hash_foundation_tuple_512(ACTIVATION_TRANSCRIPT_IDENTITY_DOMAIN, &normalized_items)?;
    let authorized = verify_authorized_phase_terminal(
        context,
        roster,
        ACTIVATION_TERMINAL_OPERATION_KIND,
        preparation.identity,
        finality.finality_identity,
        transcript_identity,
        terminal_bytes,
    )?;
    let Some(opened_input_difference) =
        exact_codeword_constant(&input_differences, SHARING_DEGREE)?
    else {
        return Ok(DirectMpcActivationVerification::Burn {
            terminal_identity: authorized.identity,
        });
    };
    let Some(opened_public_input_difference) =
        exact_codeword_constant(&public_input_differences, SHARING_DEGREE)?
    else {
        return Ok(DirectMpcActivationVerification::Burn {
            terminal_identity: authorized.identity,
        });
    };
    Ok(DirectMpcActivationVerification::Verified(Box::new(
        VerifiedDirectMpcOneAndActivation {
            context,
            target_identity: target.identity,
            finality_identity: finality.finality_identity,
            preparation_identity: preparation.identity,
            input_source_root: input_source.root,
            manifest_identity: input_source.manifest_identity,
            identity: authorized.identity,
            opened_input_difference,
            opened_public_input_difference,
        },
    )))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectMpcOutputShareBody {
    candidate_identity: Hash512,
    target_identity: Hash512,
    activation_identity: Hash512,
    participant_position: u16,
    output_share: DirectMpcPrimeFieldElement,
}

impl DirectMpcOutputShareBody {
    fn canonical_bytes(self) -> Result<Vec<u8>, DirectMpcOneAndError> {
        Ok(encode_domain_tuple(
            OUTPUT_SHARE_BODY_DOMAIN,
            vec![
                CanonicalItem::hash512(self.candidate_identity.into_bytes()),
                CanonicalItem::hash512(self.target_identity.into_bytes()),
                CanonicalItem::hash512(self.activation_identity.into_bytes()),
                CanonicalItem::unsigned16(self.participant_position),
                CanonicalItem::fixed_bytes(self.output_share.canonical_bytes())?,
            ],
        )?)
    }

    fn decode(bytes: &[u8]) -> Result<Self, DirectMpcOneAndError> {
        let tuple = decode_domain_tuple(bytes, OUTPUT_SHARE_BODY_DOMAIN)?;
        if tuple.items.len() != 6 {
            return Err(DirectMpcOneAndError::WrongCount);
        }
        Ok(Self {
            candidate_identity: read_hash(&tuple.items[1])?,
            target_identity: read_hash(&tuple.items[2])?,
            activation_identity: read_hash(&tuple.items[3])?,
            participant_position: read_u16(&tuple.items[4])?,
            output_share: DirectMpcPrimeFieldElement::from_canonical_bytes(
                &read_fixed_bytes::<3>(&tuple.items[5])?,
            )?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectMpcOutputVerification {
    ClearResult {
        result_identity: Hash512,
        result: bool,
    },
    Burn {
        terminal_identity: Hash512,
    },
}

fn verify_output_terminal(
    context: DirectMpcOneAndContext,
    activation: VerifiedDirectMpcOneAndActivation,
    roster: &Roster,
    terminal_bytes: &[u8],
) -> Result<DirectMpcOutputVerification, DirectMpcOneAndError> {
    if activation.context != context {
        return Err(DirectMpcOneAndError::WrongContext);
    }
    let semantic_body = authorized_phase_semantic_body(terminal_bytes)?;
    let transcript = decode_domain_tuple(&semantic_body, OUTPUT_TRANSCRIPT_DOMAIN)?;
    let expected_item_count = usize::from(context.participant_count)
        .checked_add(1)
        .ok_or(DirectMpcOneAndError::ArithmeticOverflow)?;
    if transcript.items.len() != expected_item_count {
        return Err(DirectMpcOneAndError::WrongCount);
    }
    let mut output_shares = Vec::with_capacity(usize::from(context.participant_count));
    let mut normalized_items = Vec::with_capacity(usize::from(context.participant_count));
    for (expected_position, share_item) in transcript.items[1..].iter().enumerate() {
        let carrier = decode_domain_tuple(
            read_variable_bytes(share_item)?,
            OUTPUT_SHARE_CARRIER_DOMAIN,
        )?;
        if carrier.items.len() != SIGNED_CARRIER_ITEM_COUNT {
            return Err(DirectMpcOneAndError::WrongCount);
        }
        let body_bytes = read_variable_bytes(&carrier.items[1])?;
        let body = DirectMpcOutputShareBody::decode(body_bytes)?;
        if body.candidate_identity != context.candidate_identity
            || body.target_identity != activation.target_identity
            || body.activation_identity != activation.identity
            || usize::from(body.participant_position) != expected_position
        {
            return Err(DirectMpcOneAndError::WrongContext);
        }
        let signature = read_signature(&carrier.items[2])?;
        verify_signature(
            roster,
            body.participant_position,
            body_bytes,
            &signature,
            OUTPUT_SHARE_SIGNATURE_CONTEXT,
        )?;
        output_shares.push(body.output_share);
        normalized_items.push(CanonicalItem::variable_bytes(body_bytes)?);
    }
    let transcript_identity =
        hash_foundation_tuple_512(OUTPUT_TRANSCRIPT_IDENTITY_DOMAIN, &normalized_items)?;
    let authorized = verify_authorized_phase_terminal(
        context,
        roster,
        OUTPUT_TERMINAL_OPERATION_KIND,
        activation.preparation_identity,
        activation.identity,
        transcript_identity,
        terminal_bytes,
    )?;
    let Some(output_value) = exact_codeword_constant(&output_shares, SHARING_DEGREE)? else {
        return Ok(DirectMpcOutputVerification::Burn {
            terminal_identity: authorized.identity,
        });
    };
    let result = match output_value {
        DirectMpcPrimeFieldElement::ZERO => false,
        DirectMpcPrimeFieldElement::ONE => true,
        _ => {
            return Ok(DirectMpcOutputVerification::Burn {
                terminal_identity: authorized.identity,
            });
        }
    };
    let result_identity = hash_foundation_tuple_512(
        RESULT_IDENTITY_DOMAIN,
        &[
            CanonicalItem::hash512(activation.target_identity.into_bytes()),
            CanonicalItem::hash512(activation.identity.into_bytes()),
            CanonicalItem::hash512(transcript_identity.into_bytes()),
            CanonicalItem::boolean(result),
        ],
    )?;
    Ok(DirectMpcOutputVerification::ClearResult {
        result_identity,
        result,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectMpcOneAndRequiredEvent {
    NoResultTerminal,
    ComputationTarget,
    TargetFinality,
    ActivationTerminal,
    OutputTerminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectMpcOneAndAbortReason {
    AuthenticatedActivationInconsistency,
    AuthenticatedOutputInconsistency,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerifiedDirectMpcOneAndTerminal {
    NoResult {
        selected_set_root: Hash512,
    },
    ClearResult {
        target_identity: Hash512,
        result_identity: Hash512,
        result: bool,
    },
    Abort {
        target_identity: Hash512,
        terminal_identity: Hash512,
        reason: DirectMpcOneAndAbortReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectMpcOneAndVerification {
    Pending {
        next_required: DirectMpcOneAndRequiredEvent,
    },
    Complete {
        terminal: VerifiedDirectMpcOneAndTerminal,
    },
    Refused {
        refusal_reason: RefusalReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DirectMpcOneAndVerificationBundle {
    suite_identity: Hash512,
    action_context_identity: Hash512,
    roster: Roster,
    preparation_context_identity: Hash512,
    seed_terminal_identity: Hash512,
    preparation_terminal: Option<Vec<u8>>,
    input_source_terminal: Option<Vec<u8>>,
    selected_set_terminal: Option<Vec<u8>>,
    ceremony_events: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectMpcOneAndVerificationResponse {
    status: u16,
    refusal_reason: u16,
    next_event: u16,
    abort_reason: u16,
    candidate_identity: Hash512,
    preparation_identity: Hash512,
    selected_set_root: Hash512,
    target_identity: Hash512,
    terminal_identity: Hash512,
    clear_result_present: bool,
    clear_result: bool,
}

impl DirectMpcOneAndVerificationResponse {
    fn for_context(context: DirectMpcOneAndContext) -> Self {
        Self {
            status: VERIFICATION_STATUS_PENDING,
            refusal_reason: 0,
            next_event: NEXT_EVENT_PREPARATION_TERMINAL,
            abort_reason: ABORT_REASON_NONE,
            candidate_identity: context.candidate_identity,
            preparation_identity: zero_hash(),
            selected_set_root: zero_hash(),
            target_identity: zero_hash(),
            terminal_identity: zero_hash(),
            clear_result_present: false,
            clear_result: false,
        }
    }

    fn refused(refusal_reason: RefusalReason) -> Self {
        Self {
            status: VERIFICATION_STATUS_REFUSED,
            refusal_reason: refusal_reason.canonical_code(),
            next_event: NEXT_EVENT_NONE,
            abort_reason: ABORT_REASON_NONE,
            candidate_identity: zero_hash(),
            preparation_identity: zero_hash(),
            selected_set_root: zero_hash(),
            target_identity: zero_hash(),
            terminal_identity: zero_hash(),
            clear_result_present: false,
            clear_result: false,
        }
    }

    fn canonical_bytes(self) -> Result<Vec<u8>, DirectMpcOneAndError> {
        Ok(encode_domain_tuple(
            VERIFICATION_RESPONSE_DOMAIN,
            vec![
                CanonicalItem::unsigned16(self.status),
                CanonicalItem::unsigned16(self.refusal_reason),
                CanonicalItem::unsigned16(self.next_event),
                CanonicalItem::unsigned16(self.abort_reason),
                CanonicalItem::hash512(self.candidate_identity.into_bytes()),
                CanonicalItem::hash512(self.preparation_identity.into_bytes()),
                CanonicalItem::hash512(self.selected_set_root.into_bytes()),
                CanonicalItem::hash512(self.target_identity.into_bytes()),
                CanonicalItem::hash512(self.terminal_identity.into_bytes()),
                CanonicalItem::boolean(self.clear_result_present),
                CanonicalItem::boolean(self.clear_result),
            ],
        )?)
    }
}

pub(crate) fn run_direct_mpc_one_and_verification_bundle(bytes: &[u8]) -> Vec<u8> {
    let response = match verify_direct_mpc_one_and_verification_bundle(bytes) {
        Ok(response) => response,
        Err(error) => DirectMpcOneAndVerificationResponse::refused(error.refusal_reason()),
    };
    response
        .canonical_bytes()
        .expect("fixed direct-MPC verification response must encode")
}

fn verify_direct_mpc_one_and_verification_bundle(
    bytes: &[u8],
) -> Result<DirectMpcOneAndVerificationResponse, DirectMpcOneAndError> {
    let bundle = decode_direct_mpc_one_and_verification_bundle(bytes)?;
    let context = DirectMpcOneAndContext::from_public_transcript(
        bundle.suite_identity,
        bundle.action_context_identity,
        &bundle.roster,
        bundle.preparation_context_identity,
        bundle.seed_terminal_identity,
    )?;
    let mut response = DirectMpcOneAndVerificationResponse::for_context(context);
    let (preparation_verification, preparation) = verify_preparation_terminal(
        context,
        &bundle.roster,
        bundle.preparation_terminal.as_deref(),
    )?;
    let preparation = match preparation_verification {
        DirectMpcPreparationVerification::Pending => return Ok(response),
        DirectMpcPreparationVerification::Burn { terminal_identity } => {
            response.status = VERIFICATION_STATUS_ABORT;
            response.next_event = NEXT_EVENT_NONE;
            response.abort_reason = ABORT_REASON_AUTHENTICATED_PREPARATION_INCONSISTENCY;
            response.terminal_identity = terminal_identity;
            return Ok(response);
        }
        DirectMpcPreparationVerification::Verified => {
            preparation.ok_or(DirectMpcOneAndError::MissingPrerequisite)?
        }
    };
    response.preparation_identity = preparation.identity;
    response.next_event = NEXT_EVENT_SELECTED_SET_TERMINAL;

    let input_source = verify_input_source_terminal(
        context,
        &preparation,
        &bundle.roster,
        bundle.input_source_terminal.as_deref(),
    )?;
    let selected_set = match verify_selected_set_terminal(
        context,
        &preparation,
        input_source.as_ref(),
        &bundle.roster,
        bundle.selected_set_terminal.as_deref(),
    ) {
        Err(DirectMpcOneAndError::MissingInputSource) if bundle.input_source_terminal.is_none() => {
            response.next_event = NEXT_EVENT_INPUT_SOURCE_TERMINAL;
            return Ok(response);
        }
        result => result?,
    };
    let Some(selected_set) = selected_set else {
        return Ok(response);
    };
    response.selected_set_root = selected_set.root;
    if let Some(target) =
        derive_direct_mpc_one_and_target_from_context(&bundle.roster, &preparation, &selected_set)?
    {
        response.target_identity = target.identity;
    }

    match verify_direct_mpc_one_and_ceremony_from_context(
        &bundle.roster,
        &preparation,
        &selected_set,
        &bundle.ceremony_events,
    ) {
        DirectMpcOneAndVerification::Pending { next_required } => {
            response.next_event = match next_required {
                DirectMpcOneAndRequiredEvent::NoResultTerminal => NEXT_EVENT_NO_RESULT_TERMINAL,
                DirectMpcOneAndRequiredEvent::ComputationTarget => NEXT_EVENT_COMPUTATION_TARGET,
                DirectMpcOneAndRequiredEvent::TargetFinality => NEXT_EVENT_TARGET_FINALITY,
                DirectMpcOneAndRequiredEvent::ActivationTerminal => NEXT_EVENT_ACTIVATION_TERMINAL,
                DirectMpcOneAndRequiredEvent::OutputTerminal => NEXT_EVENT_OUTPUT_TERMINAL,
            };
        }
        DirectMpcOneAndVerification::Complete { terminal } => match terminal {
            VerifiedDirectMpcOneAndTerminal::NoResult { selected_set_root } => {
                response.status = VERIFICATION_STATUS_NO_RESULT;
                response.next_event = NEXT_EVENT_NONE;
                response.selected_set_root = selected_set_root;
            }
            VerifiedDirectMpcOneAndTerminal::ClearResult {
                target_identity,
                result_identity,
                result,
            } => {
                response.status = VERIFICATION_STATUS_CLEAR_RESULT;
                response.next_event = NEXT_EVENT_NONE;
                response.target_identity = target_identity;
                response.terminal_identity = result_identity;
                response.clear_result_present = true;
                response.clear_result = result;
            }
            VerifiedDirectMpcOneAndTerminal::Abort {
                target_identity,
                terminal_identity,
                reason,
            } => {
                response.status = VERIFICATION_STATUS_ABORT;
                response.next_event = NEXT_EVENT_NONE;
                response.target_identity = target_identity;
                response.terminal_identity = terminal_identity;
                response.abort_reason = match reason {
                    DirectMpcOneAndAbortReason::AuthenticatedActivationInconsistency => {
                        ABORT_REASON_AUTHENTICATED_ACTIVATION_INCONSISTENCY
                    }
                    DirectMpcOneAndAbortReason::AuthenticatedOutputInconsistency => {
                        ABORT_REASON_AUTHENTICATED_OUTPUT_INCONSISTENCY
                    }
                };
            }
        },
        DirectMpcOneAndVerification::Refused { refusal_reason } => {
            return Ok(DirectMpcOneAndVerificationResponse::refused(refusal_reason));
        }
    }
    Ok(response)
}

fn decode_direct_mpc_one_and_verification_bundle(
    bytes: &[u8],
) -> Result<DirectMpcOneAndVerificationBundle, DirectMpcOneAndError> {
    let tuple = CanonicalTuple::decode(bytes, &verification_bundle_decode_limits())?;
    if tuple.schema_identifier != CANONICAL_TUPLE_SCHEMA_IDENTIFIER
        || tuple.schema_version != CANONICAL_TUPLE_VERSION
        || tuple.items.len() < VERIFICATION_BUNDLE_FIXED_ITEM_COUNT
        || tuple.items[0].item_type() != CanonicalItemType::Ascii
        || tuple.items[0].variable_value_bytes()? != VERIFICATION_BUNDLE_DOMAIN.as_bytes()
    {
        return Err(DirectMpcOneAndError::WrongObject);
    }
    let event_count = usize::from(read_u16(&tuple.items[9])?);
    if event_count > MAXIMUM_CEREMONY_EVENT_COUNT {
        return Err(DirectMpcOneAndError::Refusal(
            RefusalReason::OutsideSupportedProfile,
        ));
    }
    if tuple.items.len()
        != VERIFICATION_BUNDLE_FIXED_ITEM_COUNT
            .checked_add(event_count)
            .ok_or(DirectMpcOneAndError::ArithmeticOverflow)?
    {
        return Err(DirectMpcOneAndError::WrongCount);
    }
    let roster_bytes = read_variable_bytes(&tuple.items[3])?;
    let roster = Roster::decode(roster_bytes, &verification_roster_decode_limits())
        .map_err(|error| DirectMpcOneAndError::Refusal(error.refusal_reason))?;
    if roster
        .encode()
        .map_err(|error| DirectMpcOneAndError::Refusal(error.refusal_reason))?
        != roster_bytes
    {
        return Err(DirectMpcOneAndError::WrongObject);
    }
    let ceremony_events = tuple.items[VERIFICATION_BUNDLE_FIXED_ITEM_COUNT..]
        .iter()
        .map(|item| Ok(read_variable_bytes(item)?.to_vec()))
        .collect::<Result<Vec<_>, DirectMpcOneAndError>>()?;
    Ok(DirectMpcOneAndVerificationBundle {
        suite_identity: read_hash(&tuple.items[1])?,
        action_context_identity: read_hash(&tuple.items[2])?,
        roster,
        preparation_context_identity: read_hash(&tuple.items[4])?,
        seed_terminal_identity: read_hash(&tuple.items[5])?,
        preparation_terminal: read_optional_bundle_event(&tuple.items[6])?,
        input_source_terminal: read_optional_bundle_event(&tuple.items[7])?,
        selected_set_terminal: read_optional_bundle_event(&tuple.items[8])?,
        ceremony_events,
    })
}

fn read_optional_bundle_event(
    item: &CanonicalItem,
) -> Result<Option<Vec<u8>>, DirectMpcOneAndError> {
    let bytes = read_variable_bytes(item)?;
    Ok((!bytes.is_empty()).then(|| bytes.to_vec()))
}

const fn verification_bundle_decode_limits() -> CanonicalDecodeLimits {
    CanonicalDecodeLimits {
        maximum_tuple_byte_length: MAXIMUM_BUNDLE_BYTE_LENGTH,
        maximum_item_count: MAXIMUM_BUNDLE_ITEM_COUNT,
        maximum_item_byte_length: MAXIMUM_BUNDLE_ITEM_BYTE_LENGTH,
        maximum_nesting_depth: 1,
        maximum_cumulative_work_byte_length: MAXIMUM_BUNDLE_CUMULATIVE_BYTE_LENGTH,
        maximum_cumulative_allocation_byte_length: MAXIMUM_BUNDLE_CUMULATIVE_BYTE_LENGTH,
    }
}

const fn verification_roster_decode_limits() -> CanonicalDecodeLimits {
    CanonicalDecodeLimits {
        maximum_tuple_byte_length: MAXIMUM_BUNDLE_ITEM_BYTE_LENGTH,
        maximum_item_count: 64,
        maximum_item_byte_length: MAXIMUM_BUNDLE_ITEM_BYTE_LENGTH,
        maximum_nesting_depth: 4,
        maximum_cumulative_work_byte_length: 8 * 1024 * 1024,
        maximum_cumulative_allocation_byte_length: 8 * 1024 * 1024,
    }
}

fn verify_direct_mpc_one_and_ceremony(
    action_context: &ActionContext,
    roster: &Roster,
    preparation: &VerifiedDirectMpcOneAndPreparation,
    selected_set: &VerifiedDirectMpcOneAndSelectedSet,
    event_bytes: &[Vec<u8>],
) -> DirectMpcOneAndVerification {
    if action_context.suite_id() != preparation.context.suite_identity
        || action_context.context_hash() != preparation.context.action_context_identity
        || action_context.roster_hash() != preparation.context.roster_identity
    {
        return DirectMpcOneAndVerification::Refused {
            refusal_reason: RefusalReason::WrongContext,
        };
    }
    verify_direct_mpc_one_and_ceremony_from_context(roster, preparation, selected_set, event_bytes)
}

fn verify_direct_mpc_one_and_ceremony_from_context(
    roster: &Roster,
    preparation: &VerifiedDirectMpcOneAndPreparation,
    selected_set: &VerifiedDirectMpcOneAndSelectedSet,
    event_bytes: &[Vec<u8>],
) -> DirectMpcOneAndVerification {
    match verify_direct_mpc_one_and_ceremony_inner(roster, preparation, selected_set, event_bytes) {
        Ok(verification) => verification,
        Err(error) => DirectMpcOneAndVerification::Refused {
            refusal_reason: error.refusal_reason(),
        },
    }
}

fn verify_direct_mpc_one_and_ceremony_inner(
    roster: &Roster,
    preparation: &VerifiedDirectMpcOneAndPreparation,
    selected_set: &VerifiedDirectMpcOneAndSelectedSet,
    event_bytes: &[Vec<u8>],
) -> Result<DirectMpcOneAndVerification, DirectMpcOneAndError> {
    let context = preparation.context;
    if selected_set.context != context
        || selected_set.preparation_identity != preparation.identity
        || roster
            .roster_hash()
            .map_err(|_| DirectMpcOneAndError::WrongContext)?
            != context.roster_identity
    {
        return Err(DirectMpcOneAndError::WrongContext);
    }
    match &selected_set.state {
        DirectMpcOneAndSelectionState::AllAbstained => {
            let scope = PreEvaluationFinalityScope::new_from_identities(
                context.suite_identity,
                context.action_context_identity,
                context.roster_identity,
                roster,
                preparation.identity,
                selected_set.root,
                SelectionState::AllAbstained,
            )?;
            match verify_no_result(scope, event_bytes)? {
                FragmentVerification::Pending {
                    next_required: RequiredEvent::NoResultTerminal,
                } => Ok(DirectMpcOneAndVerification::Pending {
                    next_required: DirectMpcOneAndRequiredEvent::NoResultTerminal,
                }),
                FragmentVerification::Complete {
                    terminal: VerifiedFragmentTerminal::NoResult { selected_set_root },
                } => Ok(DirectMpcOneAndVerification::Complete {
                    terminal: VerifiedDirectMpcOneAndTerminal::NoResult { selected_set_root },
                }),
                FragmentVerification::Refused { refusal_reason } => {
                    Ok(DirectMpcOneAndVerification::Refused { refusal_reason })
                }
                _ => Err(DirectMpcOneAndError::WrongObject),
            }
        }
        DirectMpcOneAndSelectionState::Nonempty { .. } => {
            let target =
                derive_direct_mpc_one_and_target_from_context(roster, preparation, selected_set)?
                    .ok_or(DirectMpcOneAndError::MissingPrerequisite)?;
            let Some(target_bytes) = event_bytes.first() else {
                return Ok(DirectMpcOneAndVerification::Pending {
                    next_required: DirectMpcOneAndRequiredEvent::ComputationTarget,
                });
            };
            reject_early_online_event(target_bytes)?;
            ComputationTargetBody::verify_bytes(target.scope, target_bytes)?;
            let Some(finality_bytes) = event_bytes.get(1) else {
                return Ok(DirectMpcOneAndVerification::Pending {
                    next_required: DirectMpcOneAndRequiredEvent::TargetFinality,
                });
            };
            reject_early_online_event(finality_bytes)?;
            let finality =
                verify_target_finality_terminal(target.scope, target.body, roster, finality_bytes)?;
            let Some(activation_bytes) = event_bytes.get(2) else {
                return Ok(DirectMpcOneAndVerification::Pending {
                    next_required: DirectMpcOneAndRequiredEvent::ActivationTerminal,
                });
            };
            require_authorized_phase_semantic_domain(
                activation_bytes,
                ACTIVATION_TRANSCRIPT_DOMAIN,
            )?;
            let activation = match verify_activation_terminal(
                context,
                preparation,
                selected_set,
                target,
                finality,
                roster,
                activation_bytes,
            )? {
                DirectMpcActivationVerification::Verified(activation) => *activation,
                DirectMpcActivationVerification::Burn { terminal_identity } => {
                    return Ok(DirectMpcOneAndVerification::Complete {
                        terminal: VerifiedDirectMpcOneAndTerminal::Abort {
                            target_identity: target.identity,
                            terminal_identity,
                            reason:
                                DirectMpcOneAndAbortReason::AuthenticatedActivationInconsistency,
                        },
                    });
                }
            };
            let Some(output_bytes) = event_bytes.get(3) else {
                return Ok(DirectMpcOneAndVerification::Pending {
                    next_required: DirectMpcOneAndRequiredEvent::OutputTerminal,
                });
            };
            require_authorized_phase_semantic_domain(output_bytes, OUTPUT_TRANSCRIPT_DOMAIN)?;
            let output = verify_output_terminal(context, activation, roster, output_bytes)?;
            if event_bytes.len() > 4 {
                return Err(DirectMpcOneAndError::ConsumedState);
            }
            match output {
                DirectMpcOutputVerification::ClearResult {
                    result_identity,
                    result,
                } => Ok(DirectMpcOneAndVerification::Complete {
                    terminal: VerifiedDirectMpcOneAndTerminal::ClearResult {
                        target_identity: target.identity,
                        result_identity,
                        result,
                    },
                }),
                DirectMpcOutputVerification::Burn { terminal_identity } => {
                    Ok(DirectMpcOneAndVerification::Complete {
                        terminal: VerifiedDirectMpcOneAndTerminal::Abort {
                            target_identity: target.identity,
                            terminal_identity,
                            reason: DirectMpcOneAndAbortReason::AuthenticatedOutputInconsistency,
                        },
                    })
                }
            }
        }
    }
}

fn reject_early_online_event(bytes: &[u8]) -> Result<(), DirectMpcOneAndError> {
    if event_domain(bytes).ok().as_deref() == Some(AUTHORIZED_PHASE_TERMINAL_DOMAIN) {
        let semantic_body = authorized_phase_semantic_body(bytes)?;
        let semantic_domain = event_domain(&semantic_body)?;
        if semantic_domain == ACTIVATION_TRANSCRIPT_DOMAIN
            || semantic_domain == OUTPUT_TRANSCRIPT_DOMAIN
        {
            return Err(DirectMpcOneAndError::MissingPrerequisite);
        }
    }
    Ok(())
}

fn require_authorized_phase_semantic_domain(
    bytes: &[u8],
    expected_domain: &str,
) -> Result<(), DirectMpcOneAndError> {
    if event_domain(bytes)? != AUTHORIZED_PHASE_TERMINAL_DOMAIN {
        return Err(DirectMpcOneAndError::WrongObject);
    }
    let semantic_body = authorized_phase_semantic_body(bytes)?;
    let actual_domain = event_domain(&semantic_body)?;
    if actual_domain == expected_domain {
        return Ok(());
    }
    if actual_domain == ACTIVATION_TRANSCRIPT_DOMAIN || actual_domain == OUTPUT_TRANSCRIPT_DOMAIN {
        return Err(DirectMpcOneAndError::MissingPrerequisite);
    }
    Err(DirectMpcOneAndError::WrongObject)
}

struct DirectMpcOneAndPreparationCursor {
    context: DirectMpcOneAndContext,
    participant_position: u16,
    subset_masters: Box<[DirectMpcJoinedSubsetMaster]>,
    cursor: DirectMpcParticipantCursor,
}

impl DirectMpcOneAndPreparationCursor {
    fn from_verified_seed_custody(
        context: DirectMpcOneAndContext,
        joined_seed_masters: &LocallyJoinedPseudorandomZeroSharingSeedMasters320,
        checkpoint_authentication_key: [u8; DIRECT_MPC_CURSOR_CHECKPOINT_KEY_BYTE_LENGTH],
    ) -> Result<Self, DirectMpcOneAndError> {
        validate_joined_seed_context(context, joined_seed_masters)?;
        let participant_position = joined_seed_masters.participant_position();
        let subset_masters = joined_seed_masters
            .subset_masters()
            .iter()
            .enumerate()
            .map(|(master_position, master)| {
                let scope = master.scope();
                if scope.parameter_identity() != joined_seed_masters.parameter_identity()
                    || scope.preparation_context_identity() != context.preparation_context_identity
                {
                    return Err(DirectMpcCursorError::SubsetMasterScopeMismatch {
                        master_position,
                    }
                    .into());
                }
                Ok(DirectMpcJoinedSubsetMaster::from_verified_joined_seed_master(master))
            })
            .collect::<Result<Vec<_>, DirectMpcOneAndError>>()?
            .into_boxed_slice();
        let cursor = DirectMpcParticipantCursor::new(
            context.prss_context(),
            participant_position,
            &subset_masters,
            checkpoint_authentication_key,
        )?;
        Ok(Self {
            context,
            participant_position,
            subset_masters,
            cursor,
        })
    }

    #[cfg(test)]
    fn from_test_subset_masters(
        context: DirectMpcOneAndContext,
        participant_position: u16,
        subset_masters: Box<[DirectMpcJoinedSubsetMaster]>,
        checkpoint_authentication_key: [u8; DIRECT_MPC_CURSOR_CHECKPOINT_KEY_BYTE_LENGTH],
    ) -> Result<Self, DirectMpcOneAndError> {
        let cursor = DirectMpcParticipantCursor::new(
            context.prss_context(),
            participant_position,
            &subset_masters,
            checkpoint_authentication_key,
        )?;
        Ok(Self {
            context,
            participant_position,
            subset_masters,
            cursor,
        })
    }

    fn restore_from_checkpoint_with_verified_seed_custody(
        context: DirectMpcOneAndContext,
        joined_seed_masters: &LocallyJoinedPseudorandomZeroSharingSeedMasters320,
        checkpoint_authentication_key: [u8; DIRECT_MPC_CURSOR_CHECKPOINT_KEY_BYTE_LENGTH],
        checkpoint_bytes: &[u8],
    ) -> Result<Self, DirectMpcOneAndError> {
        validate_joined_seed_context(context, joined_seed_masters)?;
        let participant_position = joined_seed_masters.participant_position();
        let subset_masters = joined_seed_masters
            .subset_masters()
            .iter()
            .map(DirectMpcJoinedSubsetMaster::from_verified_joined_seed_master)
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let cursor = DirectMpcParticipantCursor::restore_from_checkpoint(
            context.prss_context(),
            participant_position,
            &subset_masters,
            checkpoint_authentication_key,
            checkpoint_bytes,
        )?;
        Ok(Self {
            context,
            participant_position,
            subset_masters,
            cursor,
        })
    }

    #[cfg(test)]
    fn restore_from_test_checkpoint(
        context: DirectMpcOneAndContext,
        participant_position: u16,
        subset_masters: Box<[DirectMpcJoinedSubsetMaster]>,
        checkpoint_authentication_key: [u8; DIRECT_MPC_CURSOR_CHECKPOINT_KEY_BYTE_LENGTH],
        checkpoint_bytes: &[u8],
    ) -> Result<Self, DirectMpcOneAndError> {
        let cursor = DirectMpcParticipantCursor::restore_from_checkpoint(
            context.prss_context(),
            participant_position,
            &subset_masters,
            checkpoint_authentication_key,
            checkpoint_bytes,
        )?;
        Ok(Self {
            context,
            participant_position,
            subset_masters,
            cursor,
        })
    }

    fn step(&mut self) -> Result<bool, DirectMpcOneAndError> {
        Ok(self.cursor.step(&self.subset_masters)?)
    }

    fn checkpoint_bytes(&self) -> Result<Zeroizing<Vec<u8>>, DirectMpcOneAndError> {
        Ok(self.cursor.checkpoint_bytes()?)
    }

    fn finish(self) -> Result<DirectMpcOneAndPreparedParticipant, DirectMpcOneAndError> {
        let output = self.cursor.verified_output()?;
        if output.ordinary_values().len() != ORDINARY_PREPARATION_FIELD_COUNT as usize
            || output.zero_values().len() != ZERO_PREPARATION_FIELD_COUNT as usize
        {
            return Err(DirectMpcOneAndError::WrongCount);
        }
        Ok(DirectMpcOneAndPreparedParticipant {
            context: self.context,
            participant_position: self.participant_position,
            multiplicand_mask_share: output.ordinary_values()[0],
            multiplier_mask_share: output.ordinary_values()[1],
            uncorrected_product_mask_share: output.ordinary_values()[2],
            degree_six_zero_share: output.zero_values()[0],
        })
    }
}

fn validate_joined_seed_context(
    context: DirectMpcOneAndContext,
    joined_seed_masters: &LocallyJoinedPseudorandomZeroSharingSeedMasters320,
) -> Result<(), DirectMpcOneAndError> {
    if joined_seed_masters.preparation_context().identity() != context.preparation_context_identity
        || derive_seed_terminal_identity(joined_seed_masters)? != context.seed_terminal_identity
        || joined_seed_masters
            .preparation_context()
            .participant_count()
            != context.participant_count
    {
        return Err(DirectMpcOneAndError::WrongContext);
    }
    Ok(())
}

struct DirectMpcOneAndPreparedParticipant {
    context: DirectMpcOneAndContext,
    participant_position: u16,
    multiplicand_mask_share: DirectMpcPrimeFieldElement,
    multiplier_mask_share: DirectMpcPrimeFieldElement,
    uncorrected_product_mask_share: DirectMpcPrimeFieldElement,
    degree_six_zero_share: DirectMpcPrimeFieldElement,
}

impl DirectMpcOneAndPreparedParticipant {
    fn preparation_share_body(&self) -> DirectMpcPreparationShareBody {
        DirectMpcPreparationShareBody {
            candidate_identity: self.context.candidate_identity,
            seed_terminal_identity: self.context.seed_terminal_identity,
            participant_position: self.participant_position,
            opened_product_difference: self
                .multiplicand_mask_share
                .multiply(self.multiplier_mask_share)
                .subtract(self.uncorrected_product_mask_share)
                .add(self.degree_six_zero_share),
        }
    }

    fn accept_preparation(
        mut self,
        preparation: VerifiedDirectMpcOneAndPreparation,
    ) -> Result<DirectMpcOneAndOnlineParticipant, DirectMpcOneAndError> {
        if preparation.context != self.context
            || preparation.opened_product_differences[usize::from(self.participant_position)]
                != self.preparation_share_body().opened_product_difference
        {
            return Err(DirectMpcOneAndError::WrongContext);
        }
        let corrected_product_mask_share = self
            .uncorrected_product_mask_share
            .add(preparation.product_correction);
        self.uncorrected_product_mask_share.zeroize();
        self.degree_six_zero_share.zeroize();
        Ok(DirectMpcOneAndOnlineParticipant {
            context: self.context,
            participant_position: self.participant_position,
            preparation_identity: preparation.identity,
            multiplicand_mask_share: self.multiplicand_mask_share,
            multiplier_mask_share: self.multiplier_mask_share,
            corrected_product_mask_share,
        })
    }
}

impl Drop for DirectMpcOneAndPreparedParticipant {
    fn drop(&mut self) {
        self.multiplicand_mask_share.zeroize();
        self.multiplier_mask_share.zeroize();
        self.uncorrected_product_mask_share.zeroize();
        self.degree_six_zero_share.zeroize();
    }
}

struct DirectMpcOneAndOnlineParticipant {
    context: DirectMpcOneAndContext,
    participant_position: u16,
    preparation_identity: Hash512,
    multiplicand_mask_share: DirectMpcPrimeFieldElement,
    multiplier_mask_share: DirectMpcPrimeFieldElement,
    corrected_product_mask_share: DirectMpcPrimeFieldElement,
}

impl DirectMpcOneAndOnlineParticipant {
    fn activation_share_body(
        &self,
        input_share: &VerifiedDirectMpcInputShare,
        input_source: &VerifiedDirectMpcInputSource,
        target: DirectMpcOneAndTarget,
        finality: VerifiedTargetFinality,
    ) -> Result<DirectMpcActivationShareBody, DirectMpcOneAndError> {
        if input_share.context != self.context
            || input_source.context != self.context
            || input_share.recipient_position != self.participant_position
            || input_share.manifest_identity != input_source.manifest_identity
            || input_share.source_position != input_source.source_position
            || input_source.preparation_identity != self.preparation_identity
            || target.identity != finality.target_identity
            || target.scope.preparation_terminal_identity != self.preparation_identity
        {
            return Err(DirectMpcOneAndError::WrongContext);
        }
        Ok(DirectMpcActivationShareBody {
            candidate_identity: self.context.candidate_identity,
            target_identity: target.identity,
            finality_identity: finality.finality_identity,
            preparation_identity: self.preparation_identity,
            input_source_root: input_source.root,
            manifest_identity: input_source.manifest_identity,
            participant_position: self.participant_position,
            opened_input_difference: input_share.share.subtract(self.multiplicand_mask_share),
            opened_public_input_difference: DirectMpcPrimeFieldElement::ONE
                .subtract(self.multiplier_mask_share),
        })
    }

    fn output_share_body(
        &self,
        activation: VerifiedDirectMpcOneAndActivation,
    ) -> Result<DirectMpcOutputShareBody, DirectMpcOneAndError> {
        if activation.context != self.context
            || activation.preparation_identity != self.preparation_identity
        {
            return Err(DirectMpcOneAndError::WrongContext);
        }
        let output_share = self
            .corrected_product_mask_share
            .add(
                activation
                    .opened_input_difference
                    .multiply(self.multiplier_mask_share),
            )
            .add(
                activation
                    .opened_public_input_difference
                    .multiply(self.multiplicand_mask_share),
            )
            .add(
                activation
                    .opened_input_difference
                    .multiply(activation.opened_public_input_difference),
            );
        Ok(DirectMpcOutputShareBody {
            candidate_identity: self.context.candidate_identity,
            target_identity: activation.target_identity,
            activation_identity: activation.identity,
            participant_position: self.participant_position,
            output_share,
        })
    }
}

impl Drop for DirectMpcOneAndOnlineParticipant {
    fn drop(&mut self) {
        self.multiplicand_mask_share.zeroize();
        self.multiplier_mask_share.zeroize();
        self.corrected_product_mask_share.zeroize();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectMpcPreparationShareBody {
    candidate_identity: Hash512,
    seed_terminal_identity: Hash512,
    participant_position: u16,
    opened_product_difference: DirectMpcPrimeFieldElement,
}

impl DirectMpcPreparationShareBody {
    fn canonical_bytes(self) -> Result<Vec<u8>, DirectMpcOneAndError> {
        Ok(encode_domain_tuple(
            PREPARATION_SHARE_BODY_DOMAIN,
            vec![
                CanonicalItem::hash512(self.candidate_identity.into_bytes()),
                CanonicalItem::hash512(self.seed_terminal_identity.into_bytes()),
                CanonicalItem::unsigned16(self.participant_position),
                CanonicalItem::fixed_bytes(self.opened_product_difference.canonical_bytes())?,
            ],
        )?)
    }

    fn decode(bytes: &[u8]) -> Result<Self, DirectMpcOneAndError> {
        let tuple = decode_domain_tuple(bytes, PREPARATION_SHARE_BODY_DOMAIN)?;
        if tuple.items.len() != 5 {
            return Err(DirectMpcOneAndError::WrongCount);
        }
        Ok(Self {
            candidate_identity: read_hash(&tuple.items[1])?,
            seed_terminal_identity: read_hash(&tuple.items[2])?,
            participant_position: read_u16(&tuple.items[3])?,
            opened_product_difference: DirectMpcPrimeFieldElement::from_canonical_bytes(
                &read_fixed_bytes::<3>(&tuple.items[4])?,
            )?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VerifiedDirectMpcOneAndPreparation {
    context: DirectMpcOneAndContext,
    identity: Hash512,
    product_correction: DirectMpcPrimeFieldElement,
    opened_product_differences: Box<[DirectMpcPrimeFieldElement]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectMpcPreparationVerification {
    Pending,
    Verified,
    Burn { terminal_identity: Hash512 },
}

fn verify_preparation_terminal(
    context: DirectMpcOneAndContext,
    roster: &Roster,
    terminal_bytes: Option<&[u8]>,
) -> Result<
    (
        DirectMpcPreparationVerification,
        Option<VerifiedDirectMpcOneAndPreparation>,
    ),
    DirectMpcOneAndError,
> {
    let Some(terminal_bytes) = terminal_bytes else {
        return Ok((DirectMpcPreparationVerification::Pending, None));
    };
    let semantic_body = authorized_phase_semantic_body(terminal_bytes)?;
    let transcript = decode_domain_tuple(&semantic_body, PREPARATION_TRANSCRIPT_DOMAIN)?;
    let expected_item_count = usize::from(context.participant_count)
        .checked_add(3)
        .ok_or(DirectMpcOneAndError::ArithmeticOverflow)?;
    if transcript.items.len() != expected_item_count {
        return Err(DirectMpcOneAndError::WrongCount);
    }
    require_hash(&transcript.items[1], context.candidate_identity)?;
    require_hash(&transcript.items[2], context.seed_terminal_identity)?;
    let mut opened_values = Vec::with_capacity(usize::from(context.participant_count));
    let mut transcript_identity_items = Vec::with_capacity(expected_item_count - 1);
    transcript_identity_items.push(CanonicalItem::hash512(
        context.candidate_identity.into_bytes(),
    ));
    transcript_identity_items.push(CanonicalItem::hash512(
        context.seed_terminal_identity.into_bytes(),
    ));
    for (expected_position, carrier_item) in transcript.items[3..].iter().enumerate() {
        let carrier = decode_domain_tuple(
            read_variable_bytes(carrier_item)?,
            PREPARATION_SHARE_CARRIER_DOMAIN,
        )?;
        if carrier.items.len() != PREPARATION_SHARE_CARRIER_ITEM_COUNT {
            return Err(DirectMpcOneAndError::WrongCount);
        }
        let body_bytes = read_variable_bytes(&carrier.items[1])?;
        let body = DirectMpcPreparationShareBody::decode(body_bytes)?;
        if body.candidate_identity != context.candidate_identity
            || body.seed_terminal_identity != context.seed_terminal_identity
            || usize::from(body.participant_position) != expected_position
        {
            return Err(DirectMpcOneAndError::WrongContext);
        }
        let signature = read_signature(&carrier.items[2])?;
        verify_signature(
            roster,
            body.participant_position,
            body_bytes,
            &signature,
            PREPARATION_SHARE_SIGNATURE_CONTEXT,
        )?;
        transcript_identity_items.push(CanonicalItem::variable_bytes(body_bytes)?);
        opened_values.push(body.opened_product_difference);
    }
    let transcript_identity = hash_foundation_tuple_512(
        PREPARATION_TRANSCRIPT_IDENTITY_DOMAIN,
        &transcript_identity_items,
    )?;
    let authorized = verify_authorized_phase_terminal(
        context,
        roster,
        PREPARATION_TERMINAL_OPERATION_KIND,
        context.seed_terminal_identity,
        context.seed_terminal_identity,
        transcript_identity,
        terminal_bytes,
    )?;
    let Some(product_correction) = exact_codeword_constant(&opened_values, PRODUCT_OPENING_DEGREE)?
    else {
        return Ok((
            DirectMpcPreparationVerification::Burn {
                terminal_identity: authorized.identity,
            },
            None,
        ));
    };
    let identity = hash_foundation_tuple_512(
        PREPARATION_TERMINAL_IDENTITY_DOMAIN,
        &[
            CanonicalItem::hash512(context.candidate_identity.into_bytes()),
            CanonicalItem::hash512(context.seed_terminal_identity.into_bytes()),
            CanonicalItem::hash512(transcript_identity.into_bytes()),
            CanonicalItem::fixed_bytes(product_correction.canonical_bytes())?,
        ],
    )?;
    Ok((
        DirectMpcPreparationVerification::Verified,
        Some(VerifiedDirectMpcOneAndPreparation {
            context,
            identity,
            product_correction,
            opened_product_differences: opened_values.into_boxed_slice(),
        }),
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VerifiedAuthorizedPhaseTerminal {
    identity: Hash512,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PhaseEndorsementBody {
    operation_kind: &'static str,
    predecessor_identity: Hash512,
    semantic_body_identity: Hash512,
    subject_position: u16,
}

impl PhaseEndorsementBody {
    fn canonical_bytes(self) -> Result<Vec<u8>, DirectMpcOneAndError> {
        Ok(encode_domain_tuple(
            PHASE_ENDORSEMENT_BODY_DOMAIN,
            vec![
                CanonicalItem::nonempty_ascii(self.operation_kind)?,
                CanonicalItem::hash512(self.predecessor_identity.into_bytes()),
                CanonicalItem::hash512(self.semantic_body_identity.into_bytes()),
                CanonicalItem::unsigned16(self.subject_position),
            ],
        )?)
    }

    fn identity(self) -> Result<Hash512, DirectMpcOneAndError> {
        Ok(hash_encoded_object(
            PHASE_ENDORSEMENT_IDENTITY_DOMAIN,
            &self.canonical_bytes()?,
        )?)
    }
}

fn verify_authorized_phase_terminal(
    context: DirectMpcOneAndContext,
    roster: &Roster,
    operation_kind: &'static str,
    state_namespace_identity: Hash512,
    predecessor_identity: Hash512,
    semantic_body_identity: Hash512,
    terminal_bytes: &[u8],
) -> Result<VerifiedAuthorizedPhaseTerminal, DirectMpcOneAndError> {
    let tuple = decode_domain_tuple(terminal_bytes, AUTHORIZED_PHASE_TERMINAL_DOMAIN)?;
    let roster_parameters = derive_foundation_roster_parameters(context.participant_count)
        .ok_or(DirectMpcOneAndError::WrongContext)?;
    let expected_endorsement_count = usize::from(roster_parameters.finality_quorum);
    let expected_item_count = AUTHORIZED_PHASE_FIXED_ITEM_COUNT
        .checked_add(expected_endorsement_count)
        .ok_or(DirectMpcOneAndError::ArithmeticOverflow)?;
    if tuple.items.len() != expected_item_count {
        return Err(DirectMpcOneAndError::WrongCount);
    }
    let mut preceding_subject_position = None;
    for carrier_item in &tuple.items[2..] {
        let carrier = decode_domain_tuple(
            read_variable_bytes(carrier_item)?,
            PHASE_ENDORSEMENT_CARRIER_DOMAIN,
        )?;
        if carrier.items.len() != PHASE_ENDORSEMENT_CARRIER_ITEM_COUNT {
            return Err(DirectMpcOneAndError::WrongCount);
        }
        let subject_position = read_u16(&carrier.items[1])?;
        if subject_position >= context.participant_count {
            return Err(DirectMpcOneAndError::WrongContext);
        }
        if preceding_subject_position.is_some_and(|preceding| preceding >= subject_position) {
            return Err(if preceding_subject_position == Some(subject_position) {
                DirectMpcOneAndError::DuplicateIdentity
            } else {
                DirectMpcOneAndError::WrongOrder
            });
        }
        preceding_subject_position = Some(subject_position);
        let endorsement = PhaseEndorsementBody {
            operation_kind,
            predecessor_identity,
            semantic_body_identity,
            subject_position,
        };
        let intent = StateOutputIntent::new_with_namespace(
            context.suite_identity,
            context.action_context_identity,
            state_namespace_identity,
            context.participant_count,
            operation_kind,
            subject_position,
            predecessor_identity,
            endorsement.identity()?,
        )?;
        verify_state_output_certificate(intent, roster, read_variable_bytes(&carrier.items[2])?)?;
    }
    let identity = hash_foundation_tuple_512(
        AUTHORIZED_PHASE_IDENTITY_DOMAIN,
        &[
            CanonicalItem::nonempty_ascii(operation_kind)?,
            CanonicalItem::hash512(predecessor_identity.into_bytes()),
            CanonicalItem::hash512(semantic_body_identity.into_bytes()),
        ],
    )?;
    Ok(VerifiedAuthorizedPhaseTerminal { identity })
}

fn authorized_phase_semantic_body(terminal_bytes: &[u8]) -> Result<Vec<u8>, DirectMpcOneAndError> {
    let tuple = decode_domain_tuple(terminal_bytes, AUTHORIZED_PHASE_TERMINAL_DOMAIN)?;
    if tuple.items.len() < AUTHORIZED_PHASE_FIXED_ITEM_COUNT {
        return Err(DirectMpcOneAndError::WrongCount);
    }
    Ok(read_variable_bytes(&tuple.items[1])?.to_vec())
}

fn exact_codeword_constant(
    values: &[DirectMpcPrimeFieldElement],
    maximum_degree: usize,
) -> Result<Option<DirectMpcPrimeFieldElement>, DirectMpcOneAndError> {
    let coefficient_count = maximum_degree
        .checked_add(1)
        .ok_or(DirectMpcOneAndError::ArithmeticOverflow)?;
    if values.len() < coefficient_count {
        return Err(DirectMpcOneAndError::WrongCount);
    }
    let shifted_coefficients =
        interpolate_consecutive_prime_field_values(&values[..coefficient_count])?;
    for (position, expected) in values.iter().copied().enumerate() {
        let shifted_point = DirectMpcPrimeFieldElement::from_u64_reduced(position as u64);
        if evaluate_prime_field_polynomial(&shifted_coefficients, shifted_point) != expected {
            return Ok(None);
        }
    }
    let point_before_first_roster_position =
        DirectMpcPrimeFieldElement::ZERO.subtract(DirectMpcPrimeFieldElement::ONE);
    Ok(Some(evaluate_prime_field_polynomial(
        &shifted_coefficients,
        point_before_first_roster_position,
    )))
}

fn require_hash(item: &CanonicalItem, expected: Hash512) -> Result<(), DirectMpcOneAndError> {
    if read_hash(item)? != expected {
        return Err(DirectMpcOneAndError::WrongContext);
    }
    Ok(())
}

fn read_boolean(item: &CanonicalItem) -> Result<bool, DirectMpcOneAndError> {
    if item.item_type() != CanonicalItemType::Boolean {
        return Err(DirectMpcOneAndError::WrongObject);
    }
    match item.canonical_bytes() {
        [0] => Ok(false),
        [1] => Ok(true),
        _ => Err(DirectMpcOneAndError::WrongObject),
    }
}

#[cfg(test)]
mod tests;
