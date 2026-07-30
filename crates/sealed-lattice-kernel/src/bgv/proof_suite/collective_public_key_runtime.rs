//! Browser/WASM production lifecycle for the selected collective public key.
//!
//! Authenticated public-key-share material is decoded by Rust, aggregate
//! coefficients and every setup-polynomial root are recomputed here, and the
//! exact maskless relation is generated and verified through the common proof
//! worker. The host relays only opaque handles and canonical bytes.

use core::slice;
use std::{cell::RefCell, mem::size_of, sync::Arc};

use crate::{
    bgv::{
        parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE},
        setup::{
            CanonicalPackageStreamKind, accepted_package_statement_source,
            cancel_collective_public_key_verification_terminal_source_reservation,
            commit_reserved_collective_public_key_verification_terminal_source,
            contribute_generated_canonical_package_proof_and_stream_source,
            reserve_collective_public_key_verification_terminal_source,
            sample_collective_public_key_common_reference_limb,
            with_accepted_setup_verification_sources,
        },
    },
    foundation::{
        AuthenticatedCheckpointContinuationSource, CanonicalDecodeLimits, CanonicalStreamDomain,
        CanonicalStreamVerifier, CanonicalStreamWriter, FOUNDATION_PROFILE, Hash512,
        PreparedPublicOnlyProofAttemptSource, ProofApplicationSlot, ProofApplicationSlotCeilings,
        STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH, StreamDescriptor,
        VerifiedCanonicalStreamSummary, VerifiedStateReservationRuntimeBinding,
        resolve_prepared_public_only_proof_attempt_source,
        retain_action_private_randomness_for_exact_family, verified_state_reservation_binding,
    },
    hashing::hash_framed_parts_512,
};

#[cfg(test)]
use super::relation_plan::CollectivePublicKeySourceProviderMemoryAccounting;
use super::runtime_ffi::{
    CommonProofGenerationFamilyAdapter, CommonProofGenerationFamilyAdapterDescription,
    cancel_common_proof_verification_family_adapter_reservation,
    commit_reserved_common_proof_verification_family_adapter_from_upstream,
    preflight_generated_common_proof_pending_package,
    preflight_reserved_common_proof_verification_family_adapter_from_upstream,
    reserve_common_proof_verification_family_adapter,
    retain_common_proof_generation_family_adapter,
};
use super::{
    AggregateThresholdShareRuntimeError, CollectivePublicKeySetupPolynomialSource,
    CollectivePublicKeySourcePolynomialProvider, CommonProofGenerationAuthorization,
    CommonProofGenerationPreparationError, CommonProofGenerationSources,
    CommonProofPrivateCoinCoordinateCapacity, CommonProofRelationPlanCapability,
    CommonProofRuntimeError, CommonProofRuntimeLimits, CommonProofSelectedSuiteCapabilityHandle,
    CompiledRelationPlan, ExpectedCommonProofPackageBindings, PreparedCommonProofGeneration,
    PrivateRandomnessCommonProofCoinSource, ProofBaseFieldElement, SetupPublicPolynomialContext,
    SetupPublicPolynomialRootBuilder, SetupPublicPolynomialTree, SetupPublicPolynomialTreeInput,
    VerifiedStatementOwnedTree, canonical_selected_collective_public_key_aggregate_statement,
    selected_proof_runtime_limits, selected_relation_plan_check_context, selected_relation_plans,
    verified_application_statement_hash, with_verified_accepted_setup_vss_package_sources,
};

const ATTEMPT_IDENTIFIER_BYTE_LENGTH: usize = 32;
const STREAM_DESCRIPTION_BYTE_LENGTH: usize = 72;
const PARTICIPANT_SOURCE_DESCRIPTION_BYTE_LENGTH: usize = 136;
const TRACE_HALF_COUNT: usize = 2;
const TRACE_HALF_DEGREE: usize = POLYNOMIAL_DEGREE / TRACE_HALF_COUNT;
const PUBLIC_KEY_SHARE_BODY_BYTE_LENGTH: u64 =
    DATA_PRIMES.len() as u64 * POLYNOMIAL_DEGREE as u64 * size_of::<u64>() as u64;
const PUBLIC_KEY_SHARE_TRACE_ROW_COUNT: usize = DATA_PRIMES.len() * TRACE_HALF_COUNT;
const PUBLIC_KEY_SHARE_DESCRIPTOR_MAXIMUM_BYTE_LENGTH: usize = 104
    + 64 * (PUBLIC_KEY_SHARE_BODY_BYTE_LENGTH as usize)
        .div_ceil(FOUNDATION_PROFILE.stream_chunk_byte_length);
const COLLECTIVE_SOURCE_CATALOG_BINDING_DOMAIN: &str =
    "sealed-lattice/collective-public-key/source-catalog-binding/v1";
const COLLECTIVE_ORDERED_ROOT_BINDING_DOMAIN: &str =
    "sealed-lattice/collective-public-key/ordered-root-binding/v1";
const COLLECTIVE_ORDERED_CARRIER_BINDING_DOMAIN: &str =
    "sealed-lattice/collective-public-key/ordered-carrier-binding/v1";
const PUBLIC_KEY_SHARE_CARRIER_BINDING_DOMAIN: &str =
    "sealed-lattice/public-key-share/carrier-binding/v1";

#[derive(Clone)]
struct CollectiveContext {
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    public_setup_seed: [u8; Hash512::BYTE_LENGTH],
    ordered_participant_identities: Box<[[u8; Hash512::BYTE_LENGTH]]>,
}

struct AuthenticatedParticipantPublicKeyShare {
    verified_summary: VerifiedCanonicalStreamSummary,
    public_polynomial_context_hash: [u8; Hash512::BYTE_LENGTH],
    public_key_share_root: [u8; Hash512::BYTE_LENGTH],
    carrier_binding: [u8; Hash512::BYTE_LENGTH],
}

struct ActiveParticipantPublicKeyShare {
    roster_position: usize,
    stream_verifier: CanonicalStreamVerifier,
    root_builder: SetupPublicPolynomialRootBuilder,
    next_coefficient_ordinal: usize,
    pending_trace_row: Vec<u64>,
}

struct FinalizedCollectivePublicKey {
    ordered_public_key_share_roots: Box<[[u8; Hash512::BYTE_LENGTH]]>,
    aggregate_b_polynomials: Box<[Arc<[u64]>]>,
    ordered_stream_polynomials: Box<[Arc<[u64]>]>,
    collective_public_key_root: [u8; Hash512::BYTE_LENGTH],
    stream_descriptor: StreamDescriptor,
    canonical_application_statement_bytes: Box<[u8]>,
}

struct CollectivePublicKeySession {
    context: CollectiveContext,
    evaluation_domain_size: usize,
    active_participant: Option<ActiveParticipantPublicKeyShare>,
    authenticated_participants: Vec<AuthenticatedParticipantPublicKeyShare>,
    aggregate_b_polynomials: Vec<Vec<u64>>,
    finalized: Option<FinalizedCollectivePublicKey>,
    generated_proof_handle: Option<u32>,
    poisoned: bool,
}

impl CollectivePublicKeySession {
    fn begin(vss_recipient_authority_handle: u32) -> Result<Self, CommonProofRuntimeError> {
        let context = with_verified_accepted_setup_vss_package_sources(
            vss_recipient_authority_handle,
            |public_randomness, _| {
                let verified_context = public_randomness.context();
                Ok(CollectiveContext {
                    protocol_version: verified_context.protocol_version(),
                    suite_identifier: verified_context.suite_identifier().into_bytes(),
                    ceremony_context_hash: verified_context.ceremony_context_hash().into_bytes(),
                    action_context_hash: verified_context.action_context_hash().into_bytes(),
                    roster_hash: verified_context.roster_hash().into_bytes(),
                    setup_proof_context_hash: public_randomness
                        .setup_proof_context_hash()
                        .into_bytes(),
                    public_setup_seed: public_randomness.public_setup_seed().into_bytes(),
                    ordered_participant_identities: public_randomness
                        .ordered_participant_identities()
                        .iter()
                        .map(|identity| identity.into_bytes())
                        .collect::<Vec<_>>()
                        .into_boxed_slice(),
                })
            },
        )
        .map_err(aggregate_runtime_error)?;
        if context.protocol_version != FOUNDATION_PROFILE.protocol_version
            || context.ordered_participant_identities.len()
                != usize::from(FOUNDATION_PROFILE.participant_count)
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let relation_plan = selected_collective_relation_plan()?;
        let variant = relation_plan
            .select_variant(None, None)
            .map_err(|_| CommonProofRuntimeError::InvalidPlanCapability)?;
        let evaluation_domain_size = usize::try_from(variant.evaluation_domain_size())
            .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
        let mut aggregate_b_polynomials = Vec::new();
        aggregate_b_polynomials
            .try_reserve_exact(DATA_PRIMES.len())
            .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
        for _ in DATA_PRIMES {
            aggregate_b_polynomials.push(vec![0_u64; POLYNOMIAL_DEGREE]);
        }
        let mut authenticated_participants = Vec::new();
        authenticated_participants
            .try_reserve_exact(usize::from(FOUNDATION_PROFILE.participant_count))
            .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
        Ok(Self {
            context,
            evaluation_domain_size,
            active_participant: None,
            authenticated_participants,
            aggregate_b_polynomials,
            finalized: None,
            generated_proof_handle: None,
            poisoned: false,
        })
    }

    fn begin_participant(
        &mut self,
        roster_position: usize,
        canonical_descriptor_bytes: &[u8],
    ) -> Result<(), CommonProofRuntimeError> {
        if self.poisoned
            || self.finalized.is_some()
            || self.active_participant.is_some()
            || roster_position != self.authenticated_participants.len()
            || roster_position >= usize::from(FOUNDATION_PROFILE.participant_count)
            || canonical_descriptor_bytes.is_empty()
            || canonical_descriptor_bytes.len() > PUBLIC_KEY_SHARE_DESCRIPTOR_MAXIMUM_BYTE_LENGTH
        {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        let descriptor = StreamDescriptor::decode(
            canonical_descriptor_bytes,
            &public_key_share_descriptor_decode_limits(),
        )
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        if descriptor.total_byte_length != PUBLIC_KEY_SHARE_BODY_BYTE_LENGTH {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let participant_identity = *self
            .context
            .ordered_participant_identities
            .get(roster_position)
            .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
        let public_polynomial_context = SetupPublicPolynomialContext::public_key_share(
            self.context.setup_proof_context_hash,
            participant_identity,
            u16::try_from(roster_position)
                .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?,
        )
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        self.active_participant = Some(ActiveParticipantPublicKeyShare {
            roster_position,
            stream_verifier: CanonicalStreamVerifier::new(
                CanonicalStreamDomain::PublicKeyShareMaterial,
                descriptor,
            )
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?,
            root_builder: SetupPublicPolynomialRootBuilder::new(
                &public_polynomial_context,
                self.evaluation_domain_size,
                TRACE_HALF_DEGREE,
                u32::try_from(PUBLIC_KEY_SHARE_TRACE_ROW_COUNT)
                    .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?,
            )
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?,
            next_coefficient_ordinal: 0,
            pending_trace_row: Vec::with_capacity(TRACE_HALF_DEGREE),
        });
        Ok(())
    }

    fn absorb_participant_chunk(
        &mut self,
        roster_position: usize,
        chunk_index: usize,
        chunk_bytes: &[u8],
    ) -> Result<(), CommonProofRuntimeError> {
        if self.poisoned {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        let result = self.absorb_participant_chunk_inner(roster_position, chunk_index, chunk_bytes);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn absorb_participant_chunk_inner(
        &mut self,
        roster_position: usize,
        chunk_index: usize,
        chunk_bytes: &[u8],
    ) -> Result<(), CommonProofRuntimeError> {
        let active = self
            .active_participant
            .as_mut()
            .filter(|active| active.roster_position == roster_position)
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
        if chunk_bytes.is_empty() || !chunk_bytes.len().is_multiple_of(size_of::<u64>()) {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        active
            .stream_verifier
            .absorb_chunk(chunk_index, chunk_bytes)
            .into_result()
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        for coefficient_bytes in chunk_bytes.chunks_exact(size_of::<u64>()) {
            let coefficient = u64::from_le_bytes(
                coefficient_bytes
                    .try_into()
                    .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?,
            );
            let limb_ordinal = active.next_coefficient_ordinal / POLYNOMIAL_DEGREE;
            let coefficient_ordinal = active.next_coefficient_ordinal % POLYNOMIAL_DEGREE;
            let modulus = *DATA_PRIMES
                .get(limb_ordinal)
                .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
            if coefficient >= modulus {
                return Err(CommonProofRuntimeError::WrongVerificationBinding);
            }
            let aggregate_coefficient = self
                .aggregate_b_polynomials
                .get_mut(limb_ordinal)
                .and_then(|polynomial| polynomial.get_mut(coefficient_ordinal))
                .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
            *aggregate_coefficient = u64::try_from(
                (u128::from(*aggregate_coefficient) + u128::from(coefficient))
                    % u128::from(modulus),
            )
            .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
            active.pending_trace_row.push(coefficient);
            if active.pending_trace_row.len() == TRACE_HALF_DEGREE {
                active
                    .root_builder
                    .absorb_canonical_trace_row(&active.pending_trace_row)
                    .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
                active.pending_trace_row.clear();
            }
            active.next_coefficient_ordinal = active
                .next_coefficient_ordinal
                .checked_add(1)
                .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
        }
        Ok(())
    }

    fn finish_participant(
        &mut self,
        roster_position: usize,
    ) -> Result<(), CommonProofRuntimeError> {
        if self.poisoned {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        let result = self.finish_participant_inner(roster_position);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn finish_participant_inner(
        &mut self,
        roster_position: usize,
    ) -> Result<(), CommonProofRuntimeError> {
        let active = self
            .active_participant
            .take()
            .filter(|active| active.roster_position == roster_position)
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
        if active.next_coefficient_ordinal != DATA_PRIMES.len() * POLYNOMIAL_DEGREE
            || !active.pending_trace_row.is_empty()
        {
            self.poisoned = true;
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let verified_summary = active
            .stream_verifier
            .finish_with_summary()
            .into_result()
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        let (public_polynomial_context_hash, public_key_share_root) = active
            .root_builder
            .finish()
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        let participant_identity = self.context.ordered_participant_identities[roster_position];
        let carrier_binding = hash_framed_parts_512(
            PUBLIC_KEY_SHARE_CARRIER_BINDING_DOMAIN,
            &[
                &self.context.protocol_version.to_le_bytes(),
                &self.context.suite_identifier,
                &self.context.ceremony_context_hash,
                &self.context.action_context_hash,
                &self.context.roster_hash,
                &self.context.setup_proof_context_hash,
                &participant_identity,
                &u16::try_from(roster_position)
                    .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?
                    .to_le_bytes(),
                &public_polynomial_context_hash,
                &public_key_share_root,
                &verified_summary.total_byte_length().to_le_bytes(),
                verified_summary.full_object_digest().as_bytes(),
            ],
        );
        self.authenticated_participants
            .push(AuthenticatedParticipantPublicKeyShare {
                verified_summary,
                public_polynomial_context_hash,
                public_key_share_root,
                carrier_binding,
            });
        Ok(())
    }

    fn finish_roster(&mut self) -> Result<(), CommonProofRuntimeError> {
        if self.poisoned {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        let result = self.finish_roster_inner();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn finish_roster_inner(&mut self) -> Result<(), CommonProofRuntimeError> {
        if self.poisoned
            || self.active_participant.is_some()
            || self.finalized.is_some()
            || self.authenticated_participants.len()
                != usize::from(FOUNDATION_PROFILE.participant_count)
        {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        let aggregate_b_polynomials = std::mem::take(&mut self.aggregate_b_polynomials)
            .into_iter()
            .map(Arc::<[u64]>::from)
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let collective_context = SetupPublicPolynomialContext::collective_public_key(
            self.context.setup_proof_context_hash,
        )
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        let (_, collective_public_key_root) = construct_trace_half_root(
            &collective_context,
            self.evaluation_domain_size,
            &aggregate_b_polynomials,
        )?;
        let mut ordered_stream_polynomials = aggregate_b_polynomials.to_vec();
        ordered_stream_polynomials
            .try_reserve_exact(DATA_PRIMES.len())
            .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
        for data_modulus_ordinal in 0..DATA_PRIMES.len() {
            ordered_stream_polynomials.push(Arc::<[u64]>::from(
                sample_collective_public_key_common_reference_limb(
                    &self.context.public_setup_seed,
                    u16::try_from(data_modulus_ordinal)
                        .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?,
                    POLYNOMIAL_DEGREE,
                )
                .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?,
            ));
        }
        let ordered_stream_polynomials = ordered_stream_polynomials.into_boxed_slice();
        let stream_descriptor = derive_stream_descriptor(&ordered_stream_polynomials)?;
        let ordered_public_key_share_roots = self
            .authenticated_participants
            .iter()
            .map(|participant| participant.public_key_share_root)
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let canonical_application_statement_bytes =
            canonical_selected_collective_public_key_aggregate_statement(
                self.context.setup_proof_context_hash,
                &ordered_public_key_share_roots,
                collective_public_key_root,
                stream_descriptor.full_object_digest.into_bytes(),
            )
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?
            .into_boxed_slice();
        self.finalized = Some(FinalizedCollectivePublicKey {
            ordered_public_key_share_roots,
            aggregate_b_polynomials,
            ordered_stream_polynomials,
            collective_public_key_root,
            stream_descriptor,
            canonical_application_statement_bytes,
        });
        Ok(())
    }

    fn copy_participant_source_description(
        &self,
        roster_position: usize,
        output: &mut [u8],
    ) -> Result<(), CommonProofRuntimeError> {
        if self.poisoned || output.len() != PARTICIPANT_SOURCE_DESCRIPTION_BYTE_LENGTH {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let participant = self
            .authenticated_participants
            .get(roster_position)
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
        output[..64].copy_from_slice(&participant.carrier_binding);
        output[64..128]
            .copy_from_slice(participant.verified_summary.full_object_digest().as_bytes());
        output[128..].copy_from_slice(
            &participant
                .verified_summary
                .total_byte_length()
                .to_le_bytes(),
        );
        Ok(())
    }

    fn finalized(&self) -> Result<&FinalizedCollectivePublicKey, CommonProofRuntimeError> {
        self.finalized
            .as_ref()
            .filter(|_| !self.poisoned)
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)
    }

    fn source_provider(
        &self,
        relation_plan: &CompiledRelationPlan,
    ) -> Result<
        (
            Vec<super::RelationProofTreeInput>,
            CollectivePublicKeySourcePolynomialProvider,
        ),
        CommonProofRuntimeError,
    > {
        let finalized = self.finalized()?;
        let mut sources = Vec::new();
        sources
            .try_reserve_exact(self.authenticated_participants.len() + 1)
            .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
        for participant in &self.authenticated_participants {
            sources.push(
                CollectivePublicKeySetupPolynomialSource::from_authenticated_stream(
                    participant.public_polynomial_context_hash,
                    participant.public_key_share_root,
                    participant.carrier_binding,
                    participant.verified_summary.clone(),
                )
                .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?,
            );
        }
        let collective_context = SetupPublicPolynomialContext::collective_public_key(
            self.context.setup_proof_context_hash,
        )
        .and_then(|context| context.context_hash())
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        sources.push(
            CollectivePublicKeySetupPolynomialSource::from_resident_polynomials(
                collective_context,
                finalized.collective_public_key_root,
                finalized.aggregate_b_polynomials.clone(),
            )
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?,
        );
        let application_statement_hash = verified_application_statement_hash(
            self.context.protocol_version,
            self.context.suite_identifier,
            ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            &finalized.canonical_application_statement_bytes,
        );
        let source_catalog_binding = self.source_catalog_binding(relation_plan)?;
        CollectivePublicKeySourcePolynomialProvider::prepare(
            relation_plan,
            self.context.protocol_version,
            self.context.suite_identifier,
            application_statement_hash,
            source_catalog_binding,
            sources,
        )
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)
    }

    fn source_catalog_binding(
        &self,
        relation_plan: &CompiledRelationPlan,
    ) -> Result<[u8; Hash512::BYTE_LENGTH], CommonProofRuntimeError> {
        let ordered_root_parts = self
            .finalized()?
            .ordered_public_key_share_roots
            .iter()
            .map(|root| root.as_slice())
            .collect::<Vec<_>>();
        let ordered_root_binding =
            hash_framed_parts_512(COLLECTIVE_ORDERED_ROOT_BINDING_DOMAIN, &ordered_root_parts);
        let ordered_carrier_parts = self
            .authenticated_participants
            .iter()
            .map(|participant| participant.carrier_binding.as_slice())
            .collect::<Vec<_>>();
        let ordered_carrier_binding = hash_framed_parts_512(
            COLLECTIVE_ORDERED_CARRIER_BINDING_DOMAIN,
            &ordered_carrier_parts,
        );
        let finalized = self.finalized()?;
        let variant = relation_plan
            .select_variant(None, None)
            .map_err(|_| CommonProofRuntimeError::InvalidPlanCapability)?;
        Ok(hash_framed_parts_512(
            COLLECTIVE_SOURCE_CATALOG_BINDING_DOMAIN,
            &[
                &self.context.protocol_version.to_le_bytes(),
                &self.context.suite_identifier,
                &self.context.ceremony_context_hash,
                &self.context.action_context_hash,
                &self.context.roster_hash,
                &self.context.setup_proof_context_hash,
                &ordered_carrier_binding,
                &ordered_root_binding,
                &finalized.collective_public_key_root,
                finalized.stream_descriptor.full_object_digest.as_bytes(),
                &finalized.stream_descriptor.total_byte_length.to_le_bytes(),
                &relation_plan
                    .canonical_hash()
                    .map_err(|_| CommonProofRuntimeError::InvalidPlanCapability)?,
                &variant
                    .canonical_hash()
                    .map_err(|_| CommonProofRuntimeError::InvalidPlanCapability)?,
            ],
        ))
    }

    fn copy_stream_range(
        &self,
        byte_offset: u64,
        output: &mut [u8],
    ) -> Result<(), CommonProofRuntimeError> {
        let finalized = self.finalized()?;
        if output.is_empty()
            || output.len() > FOUNDATION_PROFILE.stream_chunk_byte_length
            || byte_offset
                .checked_add(
                    u64::try_from(output.len())
                        .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?,
                )
                .is_none_or(|end| end > finalized.stream_descriptor.total_byte_length)
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        for (output_ordinal, output_byte) in output.iter_mut().enumerate() {
            let absolute_byte_offset = byte_offset
                .checked_add(
                    u64::try_from(output_ordinal)
                        .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?,
                )
                .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
            let coefficient_ordinal = usize::try_from(absolute_byte_offset / 8)
                .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
            let polynomial_ordinal = coefficient_ordinal / POLYNOMIAL_DEGREE;
            let polynomial_coefficient_ordinal = coefficient_ordinal % POLYNOMIAL_DEGREE;
            let coefficient_byte_ordinal = usize::try_from(absolute_byte_offset % 8)
                .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
            let coefficient = finalized
                .ordered_stream_polynomials
                .get(polynomial_ordinal)
                .and_then(|polynomial| polynomial.get(polynomial_coefficient_ordinal))
                .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
            *output_byte = coefficient.to_le_bytes()[coefficient_byte_ordinal];
        }
        Ok(())
    }
}

struct SingleCollectiveSessionRegistry {
    active: Option<(u32, CollectivePublicKeySession)>,
    next_handle: u32,
}

impl Default for SingleCollectiveSessionRegistry {
    fn default() -> Self {
        Self {
            active: None,
            next_handle: 1,
        }
    }
}

impl SingleCollectiveSessionRegistry {
    fn retain(
        &mut self,
        session: CollectivePublicKeySession,
    ) -> Result<u32, CommonProofRuntimeError> {
        if self.active.is_some() || self.next_handle == 0 {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        let handle = self.next_handle;
        self.next_handle = handle
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
        self.active = Some((handle, session));
        Ok(handle)
    }

    fn with<Output>(
        &self,
        handle: u32,
        inspect: impl FnOnce(&CollectivePublicKeySession) -> Result<Output, CommonProofRuntimeError>,
    ) -> Result<Output, CommonProofRuntimeError> {
        inspect(
            self.active
                .as_ref()
                .filter(|(active_handle, _)| *active_handle == handle)
                .map(|(_, session)| session)
                .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?,
        )
    }

    fn with_mut<Output>(
        &mut self,
        handle: u32,
        inspect: impl FnOnce(&mut CollectivePublicKeySession) -> Result<Output, CommonProofRuntimeError>,
    ) -> Result<Output, CommonProofRuntimeError> {
        inspect(
            self.active
                .as_mut()
                .filter(|(active_handle, _)| *active_handle == handle)
                .map(|(_, session)| session)
                .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?,
        )
    }

    fn take(&mut self, handle: u32) -> Result<CollectivePublicKeySession, CommonProofRuntimeError> {
        self.with(handle, |_| Ok(()))?;
        self.active
            .take()
            .map(|(_, session)| session)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(test)]
pub(crate) struct CollectivePublicKeyApplicationMemoryAccounting {
    session_registry_fixed_byte_length: u64,
    roster_identity_payload_byte_length: u64,
    authenticated_participant_catalog_byte_length: u64,
    ordered_public_key_share_root_payload_byte_length: u64,
    session_polynomial_reference_catalog_byte_length: u64,
    common_reference_polynomial_payload_byte_length: u64,
    common_reference_polynomial_allocation_header_byte_length: u64,
    collective_stream_descriptor_digest_payload_byte_length: u64,
    collective_stream_descriptor_digest_allocation_header_byte_length: u64,
    canonical_application_statement_payload_byte_length: u64,
    shared_source_authority_payload_byte_length: u64,
    loading_persistent_resident_byte_length: u64,
    post_source_polynomial_finish_persistent_resident_byte_length: u64,
    maximum_boundary_overlap_byte_length: u64,
}

#[cfg(test)]
impl CollectivePublicKeyApplicationMemoryAccounting {
    pub(crate) const fn session_registry_fixed_byte_length(self) -> u64 {
        self.session_registry_fixed_byte_length
    }

    pub(crate) const fn roster_identity_payload_byte_length(self) -> u64 {
        self.roster_identity_payload_byte_length
    }

    pub(crate) const fn authenticated_participant_catalog_byte_length(self) -> u64 {
        self.authenticated_participant_catalog_byte_length
    }

    pub(crate) const fn ordered_public_key_share_root_payload_byte_length(self) -> u64 {
        self.ordered_public_key_share_root_payload_byte_length
    }

    pub(crate) const fn session_polynomial_reference_catalog_byte_length(self) -> u64 {
        self.session_polynomial_reference_catalog_byte_length
    }

    pub(crate) const fn common_reference_polynomial_payload_byte_length(self) -> u64 {
        self.common_reference_polynomial_payload_byte_length
    }

    pub(crate) const fn common_reference_polynomial_allocation_header_byte_length(self) -> u64 {
        self.common_reference_polynomial_allocation_header_byte_length
    }

    pub(crate) const fn collective_stream_descriptor_digest_payload_byte_length(self) -> u64 {
        self.collective_stream_descriptor_digest_payload_byte_length
    }

    pub(crate) const fn collective_stream_descriptor_digest_allocation_header_byte_length(
        self,
    ) -> u64 {
        self.collective_stream_descriptor_digest_allocation_header_byte_length
    }

    pub(crate) const fn canonical_application_statement_payload_byte_length(self) -> u64 {
        self.canonical_application_statement_payload_byte_length
    }

    pub(crate) const fn shared_source_authority_payload_byte_length(self) -> u64 {
        self.shared_source_authority_payload_byte_length
    }

    pub(crate) const fn loading_persistent_resident_byte_length(self) -> u64 {
        self.loading_persistent_resident_byte_length
    }

    pub(crate) const fn post_source_polynomial_finish_persistent_resident_byte_length(self) -> u64 {
        self.post_source_polynomial_finish_persistent_resident_byte_length
    }

    pub(crate) const fn maximum_boundary_overlap_byte_length(self) -> u64 {
        self.maximum_boundary_overlap_byte_length
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(test)]
pub(crate) struct CollectivePublicKeyRootPipelineMemoryAccounting {
    session_registry_fixed_byte_length: u64,
    roster_identity_payload_byte_length: u64,
    authenticated_participant_catalog_byte_length: u64,
    participant_descriptor_digest_payload_byte_length: u64,
    participant_descriptor_digest_allocation_header_byte_length: u64,
    aggregate_polynomial_payload_byte_length: u64,
    aggregate_polynomial_catalog_byte_length: u64,
    pending_trace_row_payload_byte_length: u64,
    root_builder_owned_payload_peak_byte_length: u64,
    source_boundary_input_byte_length: u64,
    peak_combined_wasm_resident_byte_length: u64,
}

#[cfg(test)]
impl CollectivePublicKeyRootPipelineMemoryAccounting {
    pub(crate) const fn session_registry_fixed_byte_length(self) -> u64 {
        self.session_registry_fixed_byte_length
    }

    pub(crate) const fn roster_identity_payload_byte_length(self) -> u64 {
        self.roster_identity_payload_byte_length
    }

    pub(crate) const fn authenticated_participant_catalog_byte_length(self) -> u64 {
        self.authenticated_participant_catalog_byte_length
    }

    pub(crate) const fn participant_descriptor_digest_payload_byte_length(self) -> u64 {
        self.participant_descriptor_digest_payload_byte_length
    }

    pub(crate) const fn participant_descriptor_digest_allocation_header_byte_length(self) -> u64 {
        self.participant_descriptor_digest_allocation_header_byte_length
    }

    pub(crate) const fn aggregate_polynomial_payload_byte_length(self) -> u64 {
        self.aggregate_polynomial_payload_byte_length
    }

    pub(crate) const fn aggregate_polynomial_catalog_byte_length(self) -> u64 {
        self.aggregate_polynomial_catalog_byte_length
    }

    pub(crate) const fn pending_trace_row_payload_byte_length(self) -> u64 {
        self.pending_trace_row_payload_byte_length
    }

    pub(crate) const fn root_builder_owned_payload_peak_byte_length(self) -> u64 {
        self.root_builder_owned_payload_peak_byte_length
    }

    pub(crate) const fn source_boundary_input_byte_length(self) -> u64 {
        self.source_boundary_input_byte_length
    }

    pub(crate) const fn peak_combined_wasm_resident_byte_length(self) -> u64 {
        self.peak_combined_wasm_resident_byte_length
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(test)]
pub(crate) struct CollectivePublicKeyStreamAndTrafficAccounting {
    participant_body_byte_length: u64,
    participant_descriptor_byte_length: u64,
    authenticated_share_store_resident_byte_length: u64,
    aggregate_output_body_byte_length: u64,
    aggregate_output_descriptor_byte_length: u64,
    aggregate_output_store_resident_byte_length: u64,
    canonical_input_read_count: u64,
    canonical_input_read_byte_length: u64,
    proof_replay_read_count: u64,
    proof_replay_read_byte_length: u64,
    full_lifecycle_input_read_count: u64,
    full_lifecycle_input_read_byte_length: u64,
    aggregate_output_write_count: u64,
    aggregate_output_write_byte_length: u64,
    authenticated_source_request_byte_length: u64,
    proof_replay_request_byte_length: u64,
    maximum_boundary_copied_buffer_byte_length: u64,
}

#[cfg(test)]
impl CollectivePublicKeyStreamAndTrafficAccounting {
    pub(crate) const fn participant_body_byte_length(self) -> u64 {
        self.participant_body_byte_length
    }

    pub(crate) const fn participant_descriptor_byte_length(self) -> u64 {
        self.participant_descriptor_byte_length
    }

    pub(crate) const fn authenticated_share_store_resident_byte_length(self) -> u64 {
        self.authenticated_share_store_resident_byte_length
    }

    pub(crate) const fn aggregate_output_body_byte_length(self) -> u64 {
        self.aggregate_output_body_byte_length
    }

    pub(crate) const fn aggregate_output_descriptor_byte_length(self) -> u64 {
        self.aggregate_output_descriptor_byte_length
    }

    pub(crate) const fn aggregate_output_store_resident_byte_length(self) -> u64 {
        self.aggregate_output_store_resident_byte_length
    }

    pub(crate) const fn canonical_input_read_count(self) -> u64 {
        self.canonical_input_read_count
    }

    pub(crate) const fn canonical_input_read_byte_length(self) -> u64 {
        self.canonical_input_read_byte_length
    }

    pub(crate) const fn proof_replay_read_count(self) -> u64 {
        self.proof_replay_read_count
    }

    pub(crate) const fn proof_replay_read_byte_length(self) -> u64 {
        self.proof_replay_read_byte_length
    }

    pub(crate) const fn full_lifecycle_input_read_count(self) -> u64 {
        self.full_lifecycle_input_read_count
    }

    pub(crate) const fn full_lifecycle_input_read_byte_length(self) -> u64 {
        self.full_lifecycle_input_read_byte_length
    }

    pub(crate) const fn aggregate_output_write_count(self) -> u64 {
        self.aggregate_output_write_count
    }

    pub(crate) const fn aggregate_output_write_byte_length(self) -> u64 {
        self.aggregate_output_write_byte_length
    }

    pub(crate) const fn authenticated_source_request_byte_length(self) -> u64 {
        self.authenticated_source_request_byte_length
    }

    pub(crate) const fn proof_replay_request_byte_length(self) -> u64 {
        self.proof_replay_request_byte_length
    }

    pub(crate) const fn maximum_boundary_copied_buffer_byte_length(self) -> u64 {
        self.maximum_boundary_copied_buffer_byte_length
    }
}

#[cfg(test)]
fn checked_count_bytes(
    count: usize,
    item_byte_length: usize,
) -> Result<u64, CommonProofRuntimeError> {
    u64::try_from(count)
        .ok()
        .and_then(|count| {
            u64::try_from(item_byte_length)
                .ok()
                .and_then(|item_byte_length| count.checked_mul(item_byte_length))
        })
        .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)
}

#[cfg(test)]
fn arc_allocation_header_byte_length() -> Result<usize, CommonProofRuntimeError> {
    size_of::<std::sync::atomic::AtomicUsize>()
        .checked_mul(2)
        .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)
}

#[cfg(test)]
pub(crate) fn collective_public_key_application_memory_accounting(
    canonical_application_statement_byte_length: u64,
    source_provider_accounting: CollectivePublicKeySourceProviderMemoryAccounting,
) -> Result<CollectivePublicKeyApplicationMemoryAccounting, CommonProofRuntimeError> {
    if canonical_application_statement_byte_length == 0 {
        return Err(CommonProofRuntimeError::AllocationLimitExceeded);
    }
    let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
    let polynomial_count = DATA_PRIMES.len();
    let collective_stream_polynomial_count = polynomial_count
        .checked_mul(2)
        .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
    let collective_stream_chunk_count = usize::try_from(
        PUBLIC_KEY_SHARE_BODY_BYTE_LENGTH
            .checked_mul(2)
            .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?,
    )
    .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?
    .div_ceil(FOUNDATION_PROFILE.stream_chunk_byte_length);
    let session_registry_fixed_byte_length =
        checked_count_bytes(1, size_of::<SingleCollectiveSessionRegistry>())?;
    let roster_identity_payload_byte_length =
        checked_count_bytes(participant_count, Hash512::BYTE_LENGTH)?;
    let authenticated_participant_catalog_byte_length = checked_count_bytes(
        participant_count,
        size_of::<AuthenticatedParticipantPublicKeyShare>(),
    )?;
    let ordered_public_key_share_root_payload_byte_length =
        checked_count_bytes(participant_count, Hash512::BYTE_LENGTH)?;
    let session_polynomial_reference_catalog_byte_length = checked_count_bytes(
        polynomial_count
            .checked_add(collective_stream_polynomial_count)
            .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?,
        size_of::<Arc<[u64]>>(),
    )?;
    let common_reference_polynomial_payload_byte_length = PUBLIC_KEY_SHARE_BODY_BYTE_LENGTH;
    let common_reference_polynomial_allocation_header_byte_length =
        checked_count_bytes(polynomial_count, arc_allocation_header_byte_length()?)?;
    let collective_stream_descriptor_digest_payload_byte_length =
        checked_count_bytes(collective_stream_chunk_count, size_of::<Hash512>())?;
    let collective_stream_descriptor_digest_allocation_header_byte_length =
        checked_count_bytes(1, arc_allocation_header_byte_length()?)?;
    let shared_source_authority_payload_byte_length = [
        source_provider_accounting.authenticated_descriptor_digest_payload_byte_length(),
        source_provider_accounting.authenticated_descriptor_digest_allocation_header_byte_length(),
        source_provider_accounting.resident_polynomial_payload_byte_length(),
        source_provider_accounting.resident_polynomial_allocation_header_byte_length(),
    ]
    .into_iter()
    .try_fold(0_u64, |total, byte_length| {
        total
            .checked_add(byte_length)
            .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)
    })?;
    let loading_persistent_resident_byte_length = [
        session_registry_fixed_byte_length,
        roster_identity_payload_byte_length,
        authenticated_participant_catalog_byte_length,
        ordered_public_key_share_root_payload_byte_length,
        session_polynomial_reference_catalog_byte_length,
        common_reference_polynomial_payload_byte_length,
        common_reference_polynomial_allocation_header_byte_length,
        collective_stream_descriptor_digest_payload_byte_length,
        collective_stream_descriptor_digest_allocation_header_byte_length,
        canonical_application_statement_byte_length,
    ]
    .into_iter()
    .try_fold(0_u64, |total, byte_length| {
        total
            .checked_add(byte_length)
            .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)
    })?;
    let post_source_polynomial_finish_persistent_resident_byte_length =
        loading_persistent_resident_byte_length
            .checked_add(shared_source_authority_payload_byte_length)
            .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
    let maximum_boundary_overlap_byte_length =
        u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
            .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
    Ok(CollectivePublicKeyApplicationMemoryAccounting {
        session_registry_fixed_byte_length,
        roster_identity_payload_byte_length,
        authenticated_participant_catalog_byte_length,
        ordered_public_key_share_root_payload_byte_length,
        session_polynomial_reference_catalog_byte_length,
        common_reference_polynomial_payload_byte_length,
        common_reference_polynomial_allocation_header_byte_length,
        collective_stream_descriptor_digest_payload_byte_length,
        collective_stream_descriptor_digest_allocation_header_byte_length,
        canonical_application_statement_payload_byte_length:
            canonical_application_statement_byte_length,
        shared_source_authority_payload_byte_length,
        loading_persistent_resident_byte_length,
        post_source_polynomial_finish_persistent_resident_byte_length,
        maximum_boundary_overlap_byte_length,
    })
}

#[cfg(test)]
pub(crate) fn collective_public_key_root_pipeline_memory_accounting(
    evaluation_domain_size: usize,
) -> Result<CollectivePublicKeyRootPipelineMemoryAccounting, CommonProofRuntimeError> {
    let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
    let participant_chunk_count = usize::try_from(PUBLIC_KEY_SHARE_BODY_BYTE_LENGTH)
        .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?
        .div_ceil(FOUNDATION_PROFILE.stream_chunk_byte_length);
    let root_plan =
        super::setup_public_polynomial::setup_public_polynomial_wasm_compact_root_memory_plan(
            evaluation_domain_size,
            TRACE_HALF_DEGREE,
            u32::try_from(PUBLIC_KEY_SHARE_TRACE_ROW_COUNT)
                .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?,
        )
        .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
    let session_registry_fixed_byte_length =
        checked_count_bytes(1, size_of::<SingleCollectiveSessionRegistry>())?;
    let roster_identity_payload_byte_length =
        checked_count_bytes(participant_count, Hash512::BYTE_LENGTH)?;
    let authenticated_participant_catalog_byte_length = checked_count_bytes(
        participant_count,
        size_of::<AuthenticatedParticipantPublicKeyShare>(),
    )?;
    let participant_descriptor_digest_payload_byte_length = checked_count_bytes(
        participant_count
            .checked_mul(participant_chunk_count)
            .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?,
        size_of::<Hash512>(),
    )?;
    let participant_descriptor_digest_allocation_header_byte_length =
        checked_count_bytes(participant_count, arc_allocation_header_byte_length()?)?;
    let aggregate_polynomial_payload_byte_length = PUBLIC_KEY_SHARE_BODY_BYTE_LENGTH;
    let aggregate_polynomial_catalog_byte_length =
        checked_count_bytes(DATA_PRIMES.len(), size_of::<Vec<u64>>())?;
    let pending_trace_row_payload_byte_length =
        checked_count_bytes(TRACE_HALF_DEGREE, size_of::<u64>())?;
    let root_builder_owned_payload_peak_byte_length = root_plan.owned_payload_peak_byte_length();
    let source_boundary_input_byte_length =
        u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
            .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
    let peak_combined_wasm_resident_byte_length = [
        session_registry_fixed_byte_length,
        roster_identity_payload_byte_length,
        authenticated_participant_catalog_byte_length,
        participant_descriptor_digest_payload_byte_length,
        participant_descriptor_digest_allocation_header_byte_length,
        aggregate_polynomial_payload_byte_length,
        aggregate_polynomial_catalog_byte_length,
        pending_trace_row_payload_byte_length,
        root_builder_owned_payload_peak_byte_length,
        source_boundary_input_byte_length,
    ]
    .into_iter()
    .try_fold(0_u64, |total, byte_length| {
        total
            .checked_add(byte_length)
            .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)
    })?;
    Ok(CollectivePublicKeyRootPipelineMemoryAccounting {
        session_registry_fixed_byte_length,
        roster_identity_payload_byte_length,
        authenticated_participant_catalog_byte_length,
        participant_descriptor_digest_payload_byte_length,
        participant_descriptor_digest_allocation_header_byte_length,
        aggregate_polynomial_payload_byte_length,
        aggregate_polynomial_catalog_byte_length,
        pending_trace_row_payload_byte_length,
        root_builder_owned_payload_peak_byte_length,
        source_boundary_input_byte_length,
        peak_combined_wasm_resident_byte_length,
    })
}

#[cfg(test)]
pub(crate) fn collective_public_key_stream_and_traffic_accounting()
-> Result<CollectivePublicKeyStreamAndTrafficAccounting, CommonProofRuntimeError> {
    let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
    let chunk_byte_length = FOUNDATION_PROFILE.stream_chunk_byte_length;
    let participant_chunk_count = usize::try_from(PUBLIC_KEY_SHARE_BODY_BYTE_LENGTH)
        .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?
        .div_ceil(chunk_byte_length);
    let participant_descriptor_byte_length = 104_u64
        .checked_add(checked_count_bytes(
            participant_chunk_count,
            Hash512::BYTE_LENGTH,
        )?)
        .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
    let all_participant_body_byte_length = u64::try_from(participant_count)
        .ok()
        .and_then(|count| count.checked_mul(PUBLIC_KEY_SHARE_BODY_BYTE_LENGTH))
        .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
    let authenticated_share_store_resident_byte_length = all_participant_body_byte_length
        .checked_add(
            u64::try_from(participant_count)
                .ok()
                .and_then(|count| count.checked_mul(participant_descriptor_byte_length))
                .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?,
        )
        .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
    let aggregate_output_body_byte_length = PUBLIC_KEY_SHARE_BODY_BYTE_LENGTH
        .checked_mul(2)
        .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
    let aggregate_output_chunk_count = usize::try_from(aggregate_output_body_byte_length)
        .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?
        .div_ceil(chunk_byte_length);
    let aggregate_output_descriptor_byte_length = 104_u64
        .checked_add(checked_count_bytes(
            aggregate_output_chunk_count,
            Hash512::BYTE_LENGTH,
        )?)
        .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
    let aggregate_output_store_resident_byte_length = aggregate_output_body_byte_length
        .checked_add(aggregate_output_descriptor_byte_length)
        .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
    let canonical_input_read_count = participant_count
        .checked_mul(participant_chunk_count)
        .and_then(|count| u64::try_from(count).ok())
        .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
    let proof_replay_read_count = canonical_input_read_count;
    let full_lifecycle_input_read_count = canonical_input_read_count
        .checked_add(proof_replay_read_count)
        .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
    let proof_replay_read_byte_length = all_participant_body_byte_length;
    let full_lifecycle_input_read_byte_length = all_participant_body_byte_length
        .checked_add(proof_replay_read_byte_length)
        .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
    let aggregate_output_write_count = u64::try_from(aggregate_output_chunk_count)
        .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
    let authenticated_source_request_byte_length = u64::from(
        super::runtime_ffi::sealed_lattice_common_proof_generation_authenticated_source_request_byte_length(),
    );
    let proof_replay_request_byte_length = proof_replay_read_count
        .checked_mul(authenticated_source_request_byte_length)
        .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
    Ok(CollectivePublicKeyStreamAndTrafficAccounting {
        participant_body_byte_length: PUBLIC_KEY_SHARE_BODY_BYTE_LENGTH,
        participant_descriptor_byte_length,
        authenticated_share_store_resident_byte_length,
        aggregate_output_body_byte_length,
        aggregate_output_descriptor_byte_length,
        aggregate_output_store_resident_byte_length,
        canonical_input_read_count,
        canonical_input_read_byte_length: all_participant_body_byte_length,
        proof_replay_read_count,
        proof_replay_read_byte_length,
        full_lifecycle_input_read_count,
        full_lifecycle_input_read_byte_length,
        aggregate_output_write_count,
        aggregate_output_write_byte_length: aggregate_output_body_byte_length,
        authenticated_source_request_byte_length,
        proof_replay_request_byte_length,
        maximum_boundary_copied_buffer_byte_length: u64::try_from(chunk_byte_length)
            .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?,
    })
}

thread_local! {
    static COLLECTIVE_PUBLIC_KEY_SESSION_REGISTRY: RefCell<SingleCollectiveSessionRegistry> =
        RefCell::new(SingleCollectiveSessionRegistry::default());
}

struct CollectiveProofRuntimePlan {
    compiled_relation_plan: CompiledRelationPlan,
    relation_plan: CommonProofRelationPlanCapability,
    limits: CommonProofRuntimeLimits,
}

fn selected_collective_relation_plan() -> Result<CompiledRelationPlan, CommonProofRuntimeError> {
    selected_relation_plans()
        .map_err(|_| CommonProofRuntimeError::InvalidPlanCapability)?
        .into_iter()
        .find(|artifact| {
            artifact.application_statement_schema_identifier()
                == ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
        })
        .map(|artifact| artifact.compiled_plan().clone())
        .ok_or(CommonProofRuntimeError::InvalidPlanCapability)
}

fn selected_collective_runtime_plan(
    canonical_statement: &[u8],
) -> Result<CollectiveProofRuntimePlan, CommonProofRuntimeError> {
    let schema_identifier =
        ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER;
    let compiled_relation_plan = selected_collective_relation_plan()?;
    let variant = compiled_relation_plan
        .select_variant(None, None)
        .map_err(|_| CommonProofRuntimeError::InvalidPlanCapability)?;
    let limits = selected_proof_runtime_limits(schema_identifier, canonical_statement, variant)
        .map_err(|_| CommonProofRuntimeError::InvalidLimits)?;
    let relation_context = selected_relation_plan_check_context(schema_identifier)
        .ok_or(CommonProofRuntimeError::InvalidPlanCapability)?;
    let relation_plan = CommonProofRelationPlanCapability::from_compiled_plan(
        &compiled_relation_plan,
        &relation_context,
        None,
        None,
    )
    .map_err(|_| CommonProofRuntimeError::InvalidPlanCapability)?;
    Ok(CollectiveProofRuntimePlan {
        compiled_relation_plan,
        relation_plan,
        limits,
    })
}

fn resolve_collective_public_key_prepared_attempt(
    action_randomness_handle: u32,
    verified_reservation_binding: VerifiedStateReservationRuntimeBinding,
    session_handle: u32,
    checkpoint_continuation: AuthenticatedCheckpointContinuationSource,
) -> Result<PreparedPublicOnlyProofAttemptSource, CommonProofRuntimeError> {
    let (context, statement) = COLLECTIVE_PUBLIC_KEY_SESSION_REGISTRY.with(|registry| {
        registry.borrow().with(session_handle, |session| {
            Ok((
                session.context.clone(),
                session
                    .finalized()?
                    .canonical_application_statement_bytes
                    .to_vec(),
            ))
        })
    })?;
    let application_slot = ProofApplicationSlot::new(
        Hash512::from_bytes(context.suite_identifier),
        Hash512::from_bytes(context.ceremony_context_hash),
        Hash512::from_bytes(context.action_context_hash),
        ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        None,
        None,
        None,
    )
    .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
    let statement_hash = Hash512::from_bytes(verified_application_statement_hash(
        context.protocol_version,
        context.suite_identifier,
        ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        &statement,
    ));
    resolve_prepared_public_only_proof_attempt_source(
        action_randomness_handle,
        verified_reservation_binding,
        Hash512::from_bytes(context.roster_hash),
        application_slot,
        statement_hash,
        checkpoint_continuation,
    )
    .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)
}

fn prepare_common_generation(
    session_handle: u32,
    action_randomness_handle: u32,
    prepared_attempt: PreparedPublicOnlyProofAttemptSource,
    runtime_plan: CollectiveProofRuntimePlan,
) -> Result<PreparedCommonProofGeneration, CommonProofRuntimeError> {
    let (context, canonical_statement, relation_trees, source_provider) =
        COLLECTIVE_PUBLIC_KEY_SESSION_REGISTRY.with(|registry| {
            registry.borrow().with(session_handle, |session| {
                let (relation_trees, source_provider) =
                    session.source_provider(&runtime_plan.compiled_relation_plan)?;
                Ok((
                    session.context.clone(),
                    session
                        .finalized()?
                        .canonical_application_statement_bytes
                        .to_vec(),
                    relation_trees,
                    source_provider,
                ))
            })
        })?;
    let authorization = CommonProofGenerationAuthorization::from_public_only_authenticated_attempt(
        prepared_attempt,
        &runtime_plan.relation_plan,
        context.protocol_version,
        &canonical_statement,
    )
    .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
    let relation_variant = runtime_plan
        .compiled_relation_plan
        .select_variant(None, None)
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
    let coordinate_capacity =
        CommonProofPrivateCoinCoordinateCapacity::from_relation_plan_variant(relation_variant)
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
    let private_coins = PrivateRandomnessCommonProofCoinSource::new(
        retain_action_private_randomness_for_exact_family(action_randomness_handle)
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?,
        prepared_attempt.application_statement_schema_identifier(),
        Hash512::from_bytes(authorization.binding_hash()),
        prepared_attempt.private_randomness_attempt_identifier(),
        coordinate_capacity,
    )
    .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
    let sources = CommonProofGenerationSources::new(private_coins, source_provider);
    PreparedCommonProofGeneration::from_row_code_whir_sources(
        authorization,
        runtime_plan.relation_plan,
        canonical_statement,
        relation_trees,
        runtime_plan.limits,
        sources,
    )
    .map_err(|error| match error {
        CommonProofGenerationPreparationError::Runtime(error) => error,
        CommonProofGenerationPreparationError::Generation(_) => {
            CommonProofRuntimeError::WrongVerificationBinding
        }
    })
}

#[derive(Clone, Copy)]
enum GenerationMode {
    Fresh,
    Resume,
}

#[allow(clippy::too_many_arguments)]
fn prepare_generation(
    session_handle: u32,
    action_randomness_handle: u32,
    state_verifier_session_handle: u32,
    state_verifier_session_capability: &[u8],
    verified_reservation_handle: u32,
    checkpoint_lineage_identifier: [u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
    generation_mode: GenerationMode,
) -> Result<u32, CommonProofRuntimeError> {
    if checkpoint_lineage_identifier == [0_u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH]
        || state_verifier_session_capability.len() != STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH
    {
        return Err(CommonProofRuntimeError::WrongVerificationBinding);
    }
    let canonical_statement = COLLECTIVE_PUBLIC_KEY_SESSION_REGISTRY.with(|registry| {
        registry.borrow().with(session_handle, |session| {
            if session.generated_proof_handle.is_some() {
                return Err(CommonProofRuntimeError::WrongOperationPhase);
            }
            Ok(session
                .finalized()?
                .canonical_application_statement_bytes
                .to_vec())
        })
    })?;
    let verified_reservation_binding = verified_state_reservation_binding(
        state_verifier_session_handle,
        state_verifier_session_capability,
        verified_reservation_handle,
    )
    .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
    let runtime_plan = selected_collective_runtime_plan(&canonical_statement)?;
    let checkpoint_schedule_digest = runtime_plan
        .relation_plan
        .checkpoint_schedule_digest()
        .map_err(|_| CommonProofRuntimeError::InvalidLimits)?;
    let fresh_continuation =
        AuthenticatedCheckpointContinuationSource::for_fresh_common_proof_attempt(
            checkpoint_lineage_identifier,
            checkpoint_schedule_digest,
        );
    let fresh_attempt = resolve_collective_public_key_prepared_attempt(
        action_randomness_handle,
        verified_reservation_binding,
        session_handle,
        fresh_continuation,
    )?;
    let adapter = match generation_mode {
        GenerationMode::Fresh => {
            CommonProofGenerationFamilyAdapter::fresh(prepare_common_generation(
                session_handle,
                action_randomness_handle,
                fresh_attempt,
                runtime_plan,
            )?)
        }
        GenerationMode::Resume => {
            let fresh_preparation = prepare_common_generation(
                session_handle,
                action_randomness_handle,
                fresh_attempt,
                runtime_plan,
            )?;
            let description = CommonProofGenerationFamilyAdapterDescription::new(
                fresh_preparation.application_statement_schema_identifier(),
                fresh_preparation.runtime_binding_hash(),
                fresh_preparation.generation_authorization_hash(),
                fresh_preparation.proof_attempt_lineage_identifier(),
            );
            drop(fresh_preparation);
            CommonProofGenerationFamilyAdapter::resume(
                description,
                checkpoint_lineage_identifier,
                checkpoint_schedule_digest,
                Box::new(move |continuation| {
                    let statement = COLLECTIVE_PUBLIC_KEY_SESSION_REGISTRY.with(|registry| {
                        registry.borrow().with(session_handle, |session| {
                            Ok(session
                                .finalized()?
                                .canonical_application_statement_bytes
                                .to_vec())
                        })
                    })?;
                    let runtime_plan = selected_collective_runtime_plan(&statement)?;
                    let attempt = resolve_collective_public_key_prepared_attempt(
                        action_randomness_handle,
                        verified_reservation_binding,
                        session_handle,
                        continuation,
                    )?;
                    prepare_common_generation(
                        session_handle,
                        action_randomness_handle,
                        attempt,
                        runtime_plan,
                    )
                    .map_err(CommonProofGenerationPreparationError::from)
                }),
            )
        }
    };
    retain_common_proof_generation_family_adapter(adapter)
}

fn commit_generated_proof(
    session_handle: u32,
    generated_common_proof_handle: u32,
) -> Result<(), CommonProofRuntimeError> {
    COLLECTIVE_PUBLIC_KEY_SESSION_REGISTRY.with(|registry| {
        registry.borrow_mut().with_mut(session_handle, |session| {
            if session.generated_proof_handle.is_some() {
                return Err(CommonProofRuntimeError::WrongOperationPhase);
            }
            let canonical_application_statement_bytes = session
                .finalized()?
                .canonical_application_statement_bytes
                .to_vec();
            preflight_generated_common_proof_pending_package(
                generated_common_proof_handle,
                ExpectedCommonProofPackageBindings {
                    suite_identifier: session.context.suite_identifier,
                    ceremony_context_hash: session.context.ceremony_context_hash,
                    action_context_hash: session.context.action_context_hash,
                    application_statement_schema_identifier:
                        ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                    roster_position: None,
                    schedule_position: None,
                    canonical_application_statement_bytes: &canonical_application_statement_bytes,
                },
            )?;
            session.generated_proof_handle = Some(generated_common_proof_handle);
            Ok(())
        })
    })
}

fn package_stream_descriptor(
    session_handle: u32,
) -> Result<StreamDescriptor, CommonProofRuntimeError> {
    COLLECTIVE_PUBLIC_KEY_SESSION_REGISTRY.with(|registry| {
        registry.borrow().with(session_handle, |session| {
            if session.generated_proof_handle.is_none() {
                return Err(CommonProofRuntimeError::WrongOperationPhase);
            }
            Ok(session.finalized()?.stream_descriptor.clone())
        })
    })
}

fn contribute_package(
    session_handle: u32,
    package_builder_handle: u32,
    generated_common_proof_handle: u32,
    canonical_application_statement_bytes: &[u8],
) -> Result<(), CommonProofRuntimeError> {
    COLLECTIVE_PUBLIC_KEY_SESSION_REGISTRY.with(|registry| {
        registry.borrow().with(session_handle, |session| {
            if session.generated_proof_handle != Some(generated_common_proof_handle)
                || session
                    .finalized()?
                    .canonical_application_statement_bytes
                    .as_ref()
                    != canonical_application_statement_bytes
            {
                return Err(CommonProofRuntimeError::WrongVerificationBinding);
            }
            Ok(())
        })
    })?;
    contribute_generated_canonical_package_proof_and_stream_source(
        package_builder_handle,
        CanonicalPackageStreamKind::CollectivePublicKey,
        session_handle,
        package_stream_descriptor,
        generated_common_proof_handle,
        canonical_application_statement_bytes,
    )
}

fn prepare_verification(
    selected_suite_handle: u32,
    session_handle: u32,
    accepted_setup_assembly_handle: u32,
) -> Result<(u32, u32), CommonProofRuntimeError> {
    let adapter_reservation_handle = reserve_common_proof_verification_family_adapter()?;
    let terminal_reservation_handle =
        match reserve_collective_public_key_verification_terminal_source() {
            Ok(handle) => handle,
            Err(error) => {
                cancel_common_proof_verification_family_adapter_reservation(
                    adapter_reservation_handle,
                )?;
                return Err(error);
            }
        };
    let preparation = (|| {
        let (context, statement, aggregate_polynomials, expected_root, generated_proof_handle) =
            COLLECTIVE_PUBLIC_KEY_SESSION_REGISTRY.with(|registry| {
                registry.borrow().with(session_handle, |session| {
                    let finalized = session.finalized()?;
                    Ok((
                        session.context.clone(),
                        finalized.canonical_application_statement_bytes.to_vec(),
                        finalized.aggregate_b_polynomials.clone(),
                        finalized.collective_public_key_root,
                        session
                            .generated_proof_handle
                            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?,
                    ))
                })
            })?;
        preflight_generated_common_proof_pending_package(
            generated_proof_handle,
            ExpectedCommonProofPackageBindings {
                suite_identifier: context.suite_identifier,
                ceremony_context_hash: context.ceremony_context_hash,
                action_context_hash: context.action_context_hash,
                application_statement_schema_identifier:
                    ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                roster_position: None,
                schedule_position: None,
                canonical_application_statement_bytes: &statement,
            },
        )?;
        let relation_plan = selected_collective_relation_plan()?;
        let evaluation_domain_size = usize::try_from(
            relation_plan
                .select_variant(None, None)
                .map_err(|_| CommonProofRuntimeError::InvalidPlanCapability)?
                .evaluation_domain_size(),
        )
        .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
        let collective_context =
            SetupPublicPolynomialContext::collective_public_key(context.setup_proof_context_hash)
                .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        let collective_tree = construct_trace_half_tree(
            &collective_context,
            evaluation_domain_size,
            &aggregate_polynomials,
        )?;
        if collective_tree.root() != expected_root {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let (statement_source, statement_trees, roster_hash) =
            with_accepted_setup_verification_sources(
                accepted_setup_assembly_handle,
                |package, verified_public_randomness| {
                    let verified_context = verified_public_randomness.context();
                    if verified_context.protocol_version() != context.protocol_version
                        || verified_context.suite_identifier().into_bytes()
                            != context.suite_identifier
                        || verified_context.ceremony_context_hash().into_bytes()
                            != context.ceremony_context_hash
                        || verified_context.action_context_hash().into_bytes()
                            != context.action_context_hash
                        || verified_context.roster_hash().into_bytes() != context.roster_hash
                        || verified_public_randomness
                            .setup_proof_context_hash()
                            .into_bytes()
                            != context.setup_proof_context_hash
                    {
                        return Err(CommonProofRuntimeError::WrongVerificationBinding);
                    }
                    let source = accepted_package_statement_source(
                        package,
                        verified_public_randomness,
                        ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                        None,
                        None,
                        None,
                        &statement,
                    )?;
                    let trees =
                        VerifiedStatementOwnedTree::from_verified_accepted_setup_statement_source(
                            &source,
                            verified_public_randomness,
                        )
                        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
                    Ok((source, trees, verified_context.roster_hash().into_bytes()))
                },
            )?;
        let selected_suite_handle =
            CommonProofSelectedSuiteCapabilityHandle::from_identifier(selected_suite_handle);
        preflight_reserved_common_proof_verification_family_adapter_from_upstream(
            adapter_reservation_handle,
            |upstream_inputs| {
                upstream_inputs.preflight_statement_tree_and_auxiliary_root_family_verification_without_evaluator(
                    &selected_suite_handle,
                    &statement_source,
                    &statement_trees,
                    &[],
                )
            },
        )?;
        Ok((
            context,
            statement,
            collective_tree,
            statement_source,
            statement_trees,
            roster_hash,
        ))
    })();
    let (_context, statement, collective_tree, statement_source, statement_trees, roster_hash) =
        match preparation {
            Ok(prepared) => prepared,
            Err(error) => {
                cancel_common_proof_verification_family_adapter_reservation(
                    adapter_reservation_handle,
                )?;
                cancel_collective_public_key_verification_terminal_source_reservation(
                    terminal_reservation_handle,
                )?;
                return Err(error);
            }
        };
    let terminal_statement_trees = statement_trees.clone();
    commit_reserved_collective_public_key_verification_terminal_source(
        terminal_reservation_handle,
        accepted_setup_assembly_handle,
        statement,
        roster_hash,
        terminal_statement_trees,
        collective_tree,
    );
    let adapter_handle = commit_reserved_common_proof_verification_family_adapter_from_upstream(
        adapter_reservation_handle,
        move |upstream_inputs| {
            let selected_suite_handle =
                CommonProofSelectedSuiteCapabilityHandle::from_identifier(selected_suite_handle);
            upstream_inputs
                .prepare_preflighted_statement_tree_and_auxiliary_root_family_verification_without_evaluator(
                    &selected_suite_handle,
                    statement_source,
                    statement_trees,
                    Vec::new(),
                )
        },
    );
    Ok((adapter_handle, terminal_reservation_handle))
}

fn construct_trace_half_tree(
    context: &SetupPublicPolynomialContext,
    evaluation_domain_size: usize,
    polynomials: &[Arc<[u64]>],
) -> Result<SetupPublicPolynomialTree, CommonProofRuntimeError> {
    if polynomials.len() != DATA_PRIMES.len() || !POLYNOMIAL_DEGREE.is_multiple_of(TRACE_HALF_COUNT)
    {
        return Err(CommonProofRuntimeError::WrongVerificationBinding);
    }
    let mut columns = Vec::new();
    columns
        .try_reserve_exact(DATA_PRIMES.len() * TRACE_HALF_COUNT)
        .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
    for (polynomial, modulus) in polynomials.iter().zip(DATA_PRIMES) {
        if polynomial.len() != POLYNOMIAL_DEGREE
            || polynomial.iter().any(|coefficient| *coefficient >= modulus)
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        for half_ordinal in 0..TRACE_HALF_COUNT {
            let start = half_ordinal
                .checked_mul(TRACE_HALF_DEGREE)
                .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
            let end = start
                .checked_add(TRACE_HALF_DEGREE)
                .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
            columns.push(
                polynomial[start..end]
                    .iter()
                    .copied()
                    .map(ProofBaseFieldElement::from_canonical)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?,
            );
        }
    }
    SetupPublicPolynomialTree::construct(SetupPublicPolynomialTreeInput {
        context,
        evaluation_domain_size,
        source_polynomial_degree_bound_exclusive: TRACE_HALF_DEGREE,
        ordered_trace_rows: &columns,
    })
    .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)
}

fn construct_trace_half_root(
    context: &SetupPublicPolynomialContext,
    evaluation_domain_size: usize,
    polynomials: &[Arc<[u64]>],
) -> Result<([u8; Hash512::BYTE_LENGTH], [u8; Hash512::BYTE_LENGTH]), CommonProofRuntimeError> {
    if polynomials.len() != DATA_PRIMES.len()
        || !POLYNOMIAL_DEGREE.is_multiple_of(TRACE_HALF_COUNT)
        || polynomials
            .iter()
            .zip(DATA_PRIMES)
            .any(|(polynomial, modulus)| {
                polynomial.len() != POLYNOMIAL_DEGREE
                    || polynomial.iter().any(|coefficient| *coefficient >= modulus)
            })
    {
        return Err(CommonProofRuntimeError::WrongVerificationBinding);
    }
    SetupPublicPolynomialTree::construct_root_from_canonical_trace_rows(
        context,
        evaluation_domain_size,
        TRACE_HALF_DEGREE,
        PUBLIC_KEY_SHARE_TRACE_ROW_COUNT,
        polynomials.iter().flat_map(|polynomial| {
            let (low, high) = polynomial.split_at(TRACE_HALF_DEGREE);
            [low, high]
        }),
    )
    .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)
}

fn public_key_share_descriptor_decode_limits() -> CanonicalDecodeLimits {
    CanonicalDecodeLimits {
        maximum_tuple_byte_length: PUBLIC_KEY_SHARE_DESCRIPTOR_MAXIMUM_BYTE_LENGTH,
        maximum_item_byte_length: PUBLIC_KEY_SHARE_DESCRIPTOR_MAXIMUM_BYTE_LENGTH,
        maximum_cumulative_work_byte_length: PUBLIC_KEY_SHARE_DESCRIPTOR_MAXIMUM_BYTE_LENGTH * 2,
        maximum_cumulative_allocation_byte_length: PUBLIC_KEY_SHARE_DESCRIPTOR_MAXIMUM_BYTE_LENGTH
            * 2,
        ..CanonicalDecodeLimits::default()
    }
}

fn derive_stream_descriptor(
    ordered_polynomials: &[Arc<[u64]>],
) -> Result<StreamDescriptor, CommonProofRuntimeError> {
    if ordered_polynomials.len() != DATA_PRIMES.len() * 2
        || ordered_polynomials
            .iter()
            .any(|polynomial| polynomial.len() != POLYNOMIAL_DEGREE)
    {
        return Err(CommonProofRuntimeError::WrongVerificationBinding);
    }
    let total_byte_length = u64::try_from(ordered_polynomials.len())
        .ok()
        .and_then(|count| count.checked_mul(u64::try_from(POLYNOMIAL_DEGREE).ok()?))
        .and_then(|count| count.checked_mul(8))
        .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
    let mut writer = CanonicalStreamWriter::new(
        CanonicalStreamDomain::CollectivePublicKey,
        total_byte_length,
    )
    .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
    let mut pending_chunk = Vec::with_capacity(FOUNDATION_PROFILE.stream_chunk_byte_length);
    let mut chunk_index = 0_usize;
    for polynomial in ordered_polynomials {
        for coefficient in polynomial.iter() {
            for byte in coefficient.to_le_bytes() {
                pending_chunk.push(byte);
                if pending_chunk.len() == FOUNDATION_PROFILE.stream_chunk_byte_length {
                    writer
                        .absorb_chunk(chunk_index, &pending_chunk)
                        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
                    chunk_index = chunk_index
                        .checked_add(1)
                        .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
                    pending_chunk.clear();
                }
            }
        }
    }
    if !pending_chunk.is_empty() {
        writer
            .absorb_chunk(chunk_index, &pending_chunk)
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
    }
    writer
        .finish()
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)
}

fn aggregate_runtime_error(error: AggregateThresholdShareRuntimeError) -> CommonProofRuntimeError {
    match error {
        AggregateThresholdShareRuntimeError::Runtime(error) => error,
        _ => CommonProofRuntimeError::WrongVerificationBinding,
    }
}

unsafe fn exact_input<'input>(
    pointer: *const u8,
    byte_length: usize,
) -> Result<&'input [u8], CommonProofRuntimeError> {
    if pointer.is_null() || byte_length == 0 {
        return Err(CommonProofRuntimeError::WrongVerificationBinding);
    }
    Ok(unsafe { slice::from_raw_parts(pointer, byte_length) })
}

unsafe fn exact_output<'output>(
    pointer: *mut u8,
    byte_length: usize,
) -> Result<&'output mut [u8], CommonProofRuntimeError> {
    if pointer.is_null() || byte_length == 0 {
        return Err(CommonProofRuntimeError::WrongVerificationBinding);
    }
    Ok(unsafe { slice::from_raw_parts_mut(pointer, byte_length) })
}

unsafe fn write_status(status_pointer: *mut u32, status: u32) {
    if !status_pointer.is_null() {
        unsafe { status_pointer.write(status) };
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_collective_public_key_aggregate_begin(
    vss_recipient_authority_handle: u32,
    status_pointer: *mut u32,
) -> u32 {
    let result =
        CollectivePublicKeySession::begin(vss_recipient_authority_handle).and_then(|session| {
            COLLECTIVE_PUBLIC_KEY_SESSION_REGISTRY
                .with(|registry| registry.borrow_mut().retain(session))
        });
    match result {
        Ok(handle) => {
            unsafe { write_status(status_pointer, 0) };
            handle
        }
        Err(error) => {
            unsafe {
                write_status(
                    status_pointer,
                    super::runtime_ffi::runtime_error_status(error),
                )
            };
            0
        }
    }
}

#[unsafe(no_mangle)]
pub const extern "C" fn sealed_lattice_collective_public_key_aggregate_participant_body_byte_length()
-> u64 {
    PUBLIC_KEY_SHARE_BODY_BYTE_LENGTH
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_collective_public_key_aggregate_begin_participant(
    session_handle: u32,
    roster_position: u32,
    canonical_descriptor_pointer: *const u8,
    canonical_descriptor_byte_length: usize,
) -> u32 {
    let result = (|| {
        let canonical_descriptor = unsafe {
            exact_input(
                canonical_descriptor_pointer,
                canonical_descriptor_byte_length,
            )
        }?;
        COLLECTIVE_PUBLIC_KEY_SESSION_REGISTRY.with(|registry| {
            registry.borrow_mut().with_mut(session_handle, |session| {
                session.begin_participant(
                    usize::try_from(roster_position)
                        .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?,
                    canonical_descriptor,
                )
            })
        })
    })();
    result.map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_collective_public_key_aggregate_absorb_participant_chunk(
    session_handle: u32,
    roster_position: u32,
    chunk_index: u32,
    chunk_pointer: *const u8,
    chunk_byte_length: usize,
) -> u32 {
    let result = (|| {
        let chunk = unsafe { exact_input(chunk_pointer, chunk_byte_length) }?;
        COLLECTIVE_PUBLIC_KEY_SESSION_REGISTRY.with(|registry| {
            registry.borrow_mut().with_mut(session_handle, |session| {
                session.absorb_participant_chunk(
                    usize::try_from(roster_position)
                        .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?,
                    usize::try_from(chunk_index)
                        .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?,
                    chunk,
                )
            })
        })
    })();
    result.map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_collective_public_key_aggregate_finish_participant(
    session_handle: u32,
    roster_position: u32,
) -> u32 {
    COLLECTIVE_PUBLIC_KEY_SESSION_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .with_mut(session_handle, |session| {
                session.finish_participant(
                    usize::try_from(roster_position)
                        .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?,
                )
            })
            .map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_collective_public_key_aggregate_copy_participant_source_description(
    session_handle: u32,
    roster_position: u32,
    output_pointer: *mut u8,
    output_byte_length: usize,
) -> u32 {
    let result = (|| {
        let output = unsafe { exact_output(output_pointer, output_byte_length) }?;
        COLLECTIVE_PUBLIC_KEY_SESSION_REGISTRY.with(|registry| {
            registry.borrow().with(session_handle, |session| {
                session.copy_participant_source_description(
                    usize::try_from(roster_position)
                        .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?,
                    output,
                )
            })
        })
    })();
    result.map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_collective_public_key_aggregate_finish_roster(
    session_handle: u32,
) -> u32 {
    COLLECTIVE_PUBLIC_KEY_SESSION_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .with_mut(session_handle, CollectivePublicKeySession::finish_roster)
            .map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_collective_public_key_aggregate_statement_byte_length(
    session_handle: u32,
    status_pointer: *mut u32,
) -> u64 {
    let result = COLLECTIVE_PUBLIC_KEY_SESSION_REGISTRY.with(|registry| {
        registry.borrow().with(session_handle, |session| {
            u64::try_from(
                session
                    .finalized()?
                    .canonical_application_statement_bytes
                    .len(),
            )
            .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)
        })
    });
    match result {
        Ok(length) => {
            unsafe { write_status(status_pointer, 0) };
            length
        }
        Err(error) => {
            unsafe {
                write_status(
                    status_pointer,
                    super::runtime_ffi::runtime_error_status(error),
                )
            };
            0
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_collective_public_key_aggregate_copy_statement(
    session_handle: u32,
    output_pointer: *mut u8,
    output_byte_length: usize,
) -> u32 {
    let result = (|| {
        let output = unsafe { exact_output(output_pointer, output_byte_length) }?;
        COLLECTIVE_PUBLIC_KEY_SESSION_REGISTRY.with(|registry| {
            registry.borrow().with(session_handle, |session| {
                let canonical_application_statement_bytes =
                    &session.finalized()?.canonical_application_statement_bytes;
                if output.len() != canonical_application_statement_bytes.len() {
                    return Err(CommonProofRuntimeError::WrongVerificationBinding);
                }
                output.copy_from_slice(canonical_application_statement_bytes);
                Ok(())
            })
        })
    })();
    result.map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_collective_public_key_aggregate_describe_stream(
    session_handle: u32,
    output_pointer: *mut u8,
    output_byte_length: usize,
) -> u32 {
    let result = (|| {
        let output = unsafe { exact_output(output_pointer, output_byte_length) }?;
        if output.len() != STREAM_DESCRIPTION_BYTE_LENGTH {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        COLLECTIVE_PUBLIC_KEY_SESSION_REGISTRY.with(|registry| {
            registry.borrow().with(session_handle, |session| {
                let stream_descriptor = &session.finalized()?.stream_descriptor;
                output[..8].copy_from_slice(&stream_descriptor.total_byte_length.to_le_bytes());
                output[8..].copy_from_slice(stream_descriptor.full_object_digest.as_bytes());
                Ok(())
            })
        })
    })();
    result.map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_collective_public_key_aggregate_copy_stream_range(
    session_handle: u32,
    byte_offset: u64,
    output_pointer: *mut u8,
    output_byte_length: usize,
) -> u32 {
    let result = (|| {
        let output = unsafe { exact_output(output_pointer, output_byte_length) }?;
        COLLECTIVE_PUBLIC_KEY_SESSION_REGISTRY.with(|registry| {
            registry.borrow().with(session_handle, |session| {
                session.copy_stream_range(byte_offset, output)
            })
        })
    })();
    result.map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
}

#[allow(clippy::too_many_arguments)]
unsafe fn prepare_generation_ffi(
    session_handle: u32,
    action_randomness_handle: u32,
    state_verifier_session_handle: u32,
    state_verifier_session_capability_pointer: *const u8,
    state_verifier_session_capability_byte_length: usize,
    verified_reservation_handle: u32,
    checkpoint_lineage_identifier_pointer: *const u8,
    checkpoint_lineage_identifier_byte_length: usize,
    status_pointer: *mut u32,
    mode: GenerationMode,
) -> u32 {
    let result = (|| {
        let state_capability = unsafe {
            exact_input(
                state_verifier_session_capability_pointer,
                state_verifier_session_capability_byte_length,
            )
        }?;
        let checkpoint_lineage = unsafe {
            exact_input(
                checkpoint_lineage_identifier_pointer,
                checkpoint_lineage_identifier_byte_length,
            )
        }?;
        let checkpoint_lineage: [u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH] = checkpoint_lineage
            .try_into()
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        prepare_generation(
            session_handle,
            action_randomness_handle,
            state_verifier_session_handle,
            state_capability,
            verified_reservation_handle,
            checkpoint_lineage,
            mode,
        )
    })();
    match result {
        Ok(handle) => {
            unsafe { write_status(status_pointer, 0) };
            handle
        }
        Err(error) => {
            unsafe {
                write_status(
                    status_pointer,
                    super::runtime_ffi::runtime_error_status(error),
                )
            };
            0
        }
    }
}

#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_collective_public_key_aggregate_prepare_generation(
    session_handle: u32,
    action_randomness_handle: u32,
    state_verifier_session_handle: u32,
    state_verifier_session_capability_pointer: *const u8,
    state_verifier_session_capability_byte_length: usize,
    verified_reservation_handle: u32,
    checkpoint_lineage_identifier_pointer: *const u8,
    checkpoint_lineage_identifier_byte_length: usize,
    status_pointer: *mut u32,
) -> u32 {
    unsafe {
        prepare_generation_ffi(
            session_handle,
            action_randomness_handle,
            state_verifier_session_handle,
            state_verifier_session_capability_pointer,
            state_verifier_session_capability_byte_length,
            verified_reservation_handle,
            checkpoint_lineage_identifier_pointer,
            checkpoint_lineage_identifier_byte_length,
            status_pointer,
            GenerationMode::Fresh,
        )
    }
}

#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_collective_public_key_aggregate_prepare_resumed_generation(
    session_handle: u32,
    action_randomness_handle: u32,
    state_verifier_session_handle: u32,
    state_verifier_session_capability_pointer: *const u8,
    state_verifier_session_capability_byte_length: usize,
    verified_reservation_handle: u32,
    checkpoint_lineage_identifier_pointer: *const u8,
    checkpoint_lineage_identifier_byte_length: usize,
    status_pointer: *mut u32,
) -> u32 {
    unsafe {
        prepare_generation_ffi(
            session_handle,
            action_randomness_handle,
            state_verifier_session_handle,
            state_verifier_session_capability_pointer,
            state_verifier_session_capability_byte_length,
            verified_reservation_handle,
            checkpoint_lineage_identifier_pointer,
            checkpoint_lineage_identifier_byte_length,
            status_pointer,
            GenerationMode::Resume,
        )
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_collective_public_key_aggregate_commit_generated_proof(
    session_handle: u32,
    generated_common_proof_handle: u32,
) -> u32 {
    commit_generated_proof(session_handle, generated_common_proof_handle)
        .map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_collective_public_key_aggregate_contribute_package(
    session_handle: u32,
    package_builder_handle: u32,
    generated_common_proof_handle: u32,
    canonical_application_statement_pointer: *const u8,
    canonical_application_statement_byte_length: usize,
) -> u32 {
    let result = if canonical_application_statement_byte_length
        > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length
    {
        Err(CommonProofRuntimeError::WrongVerificationBinding)
    } else {
        unsafe {
            exact_input(
                canonical_application_statement_pointer,
                canonical_application_statement_byte_length,
            )
        }
        .and_then(|statement| {
            contribute_package(
                session_handle,
                package_builder_handle,
                generated_common_proof_handle,
                statement,
            )
        })
    };
    result.map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_collective_public_key_aggregate_prepare_verification(
    selected_suite_handle: u32,
    session_handle: u32,
    accepted_setup_assembly_handle: u32,
    terminal_source_handle_output_pointer: *mut u32,
    status_pointer: *mut u32,
) -> u32 {
    if terminal_source_handle_output_pointer.is_null() {
        unsafe {
            write_status(
                status_pointer,
                super::runtime_ffi::runtime_error_status(
                    CommonProofRuntimeError::WrongVerificationBinding,
                ),
            )
        };
        return 0;
    }
    match prepare_verification(
        selected_suite_handle,
        session_handle,
        accepted_setup_assembly_handle,
    ) {
        Ok((adapter_handle, terminal_source_handle)) => {
            unsafe {
                terminal_source_handle_output_pointer.write(terminal_source_handle);
                write_status(status_pointer, 0);
            }
            adapter_handle
        }
        Err(error) => {
            unsafe {
                write_status(
                    status_pointer,
                    super::runtime_ffi::runtime_error_status(error),
                )
            };
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_collective_public_key_aggregate_discard_session(
    session_handle: u32,
) -> u32 {
    COLLECTIVE_PUBLIC_KEY_SESSION_REGISTRY
        .with(|registry| registry.borrow_mut().take(session_handle).map(|_| ()))
        .map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::{
        MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH,
        relation_plan::collective_public_key_source_provider_memory_accounting,
        setup_public_polynomial_wasm_compact_root_memory_plan,
    };

    #[test]
    fn selected_collective_public_key_accounting_separates_live_memory_storage_and_traffic() {
        let relation_plan =
            selected_collective_relation_plan().expect("the selected collective plan exists");
        let variant = relation_plan
            .select_variant(None, None)
            .expect("the selected collective variant exists");
        let source_provider = collective_public_key_source_provider_memory_accounting(variant)
            .expect("source-provider accounting derives");
        let canonical_statement = canonical_selected_collective_public_key_aggregate_statement(
            [0x31; Hash512::BYTE_LENGTH],
            &vec![[0x41; Hash512::BYTE_LENGTH]; usize::from(FOUNDATION_PROFILE.participant_count)],
            [0x51; Hash512::BYTE_LENGTH],
            [0x61; Hash512::BYTE_LENGTH],
        )
        .expect("the selected collective statement encodes");
        let application = collective_public_key_application_memory_accounting(
            u64::try_from(canonical_statement.len()).expect("statement length fits u64"),
            source_provider,
        )
        .expect("application accounting derives");
        let evaluation_domain_size = usize::try_from(variant.evaluation_domain_size())
            .expect("the evaluation domain fits usize");
        let root_pipeline =
            collective_public_key_root_pipeline_memory_accounting(evaluation_domain_size)
                .expect("root-pipeline accounting derives");
        let expected_wasm_root_plan = setup_public_polynomial_wasm_compact_root_memory_plan(
            evaluation_domain_size,
            TRACE_HALF_DEGREE,
            u32::try_from(PUBLIC_KEY_SHARE_TRACE_ROW_COUNT)
                .expect("the selected root row count fits u32"),
        )
        .expect("the selected Wasm root plan derives");
        let traffic = collective_public_key_stream_and_traffic_accounting()
            .expect("stream and traffic accounting derives");

        assert_eq!(
            source_provider.loading_persistent_resident_byte_length(),
            [
                source_provider.provider_fixed_byte_length(),
                source_provider.prepared_source_catalog_byte_length(),
                source_provider.prepared_authenticated_material_payload_byte_length(),
                source_provider.ordered_column_catalog_byte_length(),
                source_provider.authenticated_descriptor_digest_payload_byte_length(),
                source_provider.authenticated_descriptor_digest_allocation_header_byte_length(),
                source_provider.authenticated_chunk_flag_payload_byte_length(),
                source_provider.resident_polynomial_payload_byte_length(),
                source_provider.resident_polynomial_allocation_header_byte_length(),
                source_provider.resident_polynomial_reference_catalog_byte_length(),
            ]
            .into_iter()
            .sum::<u64>(),
        );
        assert_eq!(
            source_provider.preparation_peak_resident_byte_length(),
            source_provider.loading_persistent_resident_byte_length()
                - source_provider.provider_fixed_byte_length()
                + source_provider.relation_tree_input_catalog_byte_length()
                + source_provider.provider_fixed_byte_length().max(
                    source_provider.input_source_catalog_byte_length()
                        + source_provider.input_authenticated_summary_payload_byte_length(),
                ),
        );
        assert_eq!(
            source_provider.post_source_polynomial_finish_persistent_resident_byte_length(),
            source_provider.loading_persistent_resident_byte_length()
                - source_provider.authenticated_chunk_flag_payload_byte_length(),
        );
        assert_eq!(
            source_provider.additional_loading_source_polynomials_transient_byte_length(),
            checked_count_bytes(TRACE_HALF_DEGREE, size_of::<u64>())
                .expect("the trace-half byte length is representable")
                .checked_add(
                    u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
                        .expect("the stream chunk byte length fits u64"),
                )
                .expect("the loading overlap is representable"),
        );
        assert_eq!(
            source_provider.maximum_returned_source_polynomial_byte_length(),
            checked_count_bytes(TRACE_HALF_DEGREE, size_of::<ProofBaseFieldElement>())
                .expect("the returned source polynomial byte length is representable"),
        );
        assert_eq!(source_provider.authenticated_source_read_count(), 60);
        assert_eq!(
            source_provider.authenticated_source_read_byte_length(),
            60_293_120,
        );

        assert_eq!(
            application.loading_persistent_resident_byte_length(),
            [
                application.session_registry_fixed_byte_length(),
                application.roster_identity_payload_byte_length(),
                application.authenticated_participant_catalog_byte_length(),
                application.ordered_public_key_share_root_payload_byte_length(),
                application.session_polynomial_reference_catalog_byte_length(),
                application.common_reference_polynomial_payload_byte_length(),
                application.common_reference_polynomial_allocation_header_byte_length(),
                application.collective_stream_descriptor_digest_payload_byte_length(),
                application.collective_stream_descriptor_digest_allocation_header_byte_length(),
                application.canonical_application_statement_payload_byte_length(),
            ]
            .into_iter()
            .sum::<u64>(),
        );
        assert_eq!(
            application.post_source_polynomial_finish_persistent_resident_byte_length(),
            application.loading_persistent_resident_byte_length()
                + application.shared_source_authority_payload_byte_length(),
        );
        assert_eq!(
            application.maximum_boundary_overlap_byte_length(),
            1_048_576,
        );

        assert_eq!(
            root_pipeline.peak_combined_wasm_resident_byte_length(),
            [
                root_pipeline.session_registry_fixed_byte_length(),
                root_pipeline.roster_identity_payload_byte_length(),
                root_pipeline.authenticated_participant_catalog_byte_length(),
                root_pipeline.participant_descriptor_digest_payload_byte_length(),
                root_pipeline.participant_descriptor_digest_allocation_header_byte_length(),
                root_pipeline.aggregate_polynomial_payload_byte_length(),
                root_pipeline.aggregate_polynomial_catalog_byte_length(),
                root_pipeline.pending_trace_row_payload_byte_length(),
                root_pipeline.root_builder_owned_payload_peak_byte_length(),
                root_pipeline.source_boundary_input_byte_length(),
            ]
            .into_iter()
            .sum::<u64>(),
        );
        assert_eq!(
            root_pipeline.root_builder_owned_payload_peak_byte_length(),
            expected_wasm_root_plan.owned_payload_peak_byte_length(),
        );
        assert!(
            root_pipeline.peak_combined_wasm_resident_byte_length()
                <= MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH,
        );

        assert_eq!(traffic.participant_body_byte_length(), 6_029_312);
        assert_eq!(traffic.participant_descriptor_byte_length(), 488);
        assert_eq!(
            traffic.authenticated_share_store_resident_byte_length(),
            60_298_000,
        );
        assert_eq!(traffic.aggregate_output_body_byte_length(), 12_058_624);
        assert_eq!(traffic.aggregate_output_descriptor_byte_length(), 872);
        assert_eq!(
            traffic.aggregate_output_store_resident_byte_length(),
            12_059_496,
        );
        assert_eq!(traffic.canonical_input_read_count(), 60);
        assert_eq!(traffic.canonical_input_read_byte_length(), 60_293_120);
        assert_eq!(traffic.proof_replay_read_count(), 60);
        assert_eq!(traffic.proof_replay_read_byte_length(), 60_293_120);
        assert_eq!(traffic.full_lifecycle_input_read_count(), 120);
        assert_eq!(traffic.full_lifecycle_input_read_byte_length(), 120_586_240,);
        assert_eq!(traffic.aggregate_output_write_count(), 12);
        assert_eq!(traffic.aggregate_output_write_byte_length(), 12_058_624);
        assert_eq!(traffic.authenticated_source_request_byte_length(), 160);
        assert_eq!(traffic.proof_replay_request_byte_length(), 9_600);
        assert_eq!(
            traffic.maximum_boundary_copied_buffer_byte_length(),
            1_048_576,
        );
    }
}
