use std::sync::Arc;

use crate::{
    bgv::{
        parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE},
        proof_suite::{
            BorrowedVerifiedCommonProofCapability, BoundTreeConstructionKind, BoundTreeRootUse,
            CommonProofVerifierError, ConsumedVerifiedCommonProofCapability,
            RelationTreeDescriptor, SelectedApplicationStatementContext,
            SetupPublicPolynomialContext, SetupPublicPolynomialTree, SuiteModulusReference,
            VerifiedStatementOwnedTree, VerifiedStreamedProofTreeTerminal,
            VerifiedStreamedProofTreeTerminalPreflight,
            decode_selected_aggregate_threshold_share_statement,
            decode_selected_collective_public_key_aggregate_statement,
            decode_selected_public_key_share_statement, decode_selected_same_secret_statement,
            decode_selected_vss_share_linkage_statement, selected_relation_plans,
            verified_application_statement_hash,
        },
    },
    foundation::{
        CanonicalCodecError, CanonicalCodecErrorKind, CanonicalItem, CanonicalItemType,
        CanonicalStreamDomain, FOUNDATION_PROFILE, Hash512, ParticipantIdentity,
        ProofApplicationSlot, ProofApplicationSlotCeilings, RefusalReason, StreamDescriptor,
        VerifiedBoardApplicationSource, hash_foundation_tuple_512,
        selected_sharing_data_prime_coordinates,
    },
};

use super::verified_public_randomness::{
    VerifiedPublicRandomness, VerifiedSetupVerificationContext,
};

const COLLECTIVE_PUBLIC_KEY_AGGREGATE_TREE_ORDINAL: u32 =
    FOUNDATION_PROFILE.participant_count as u32;
const COLLECTIVE_PUBLIC_KEY_AGGREGATE_ROOT_SOURCE_ORDINAL: u32 =
    FOUNDATION_PROFILE.participant_count as u32;
const COLLECTIVE_PUBLIC_KEY_TRACE_COLUMN_COUNT: usize = DATA_PRIMES.len() * 2;
const COLLECTIVE_PUBLIC_KEY_TRACE_HALF_DEGREE: usize = POLYNOMIAL_DEGREE / 2;
const RECIPIENT_INPUT_ROOT_DOMAIN: &str = "sealed-lattice/setup/recipient-input/v1";

/// Compact terminal for one participant's complete selected same-secret proof.
/// The common verifier has already checked the relation; this terminal keeps
/// only the roots needed to join VSS, public-key, and evaluator-key families.
pub(in crate::bgv) struct VerifiedSameSecretTerminal {
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    manifest_hash: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    ordered_degree_zero_commitment_roots: Box<[[u8; Hash512::BYTE_LENGTH]]>,
    anchor_commitment_roots: [[u8; Hash512::BYTE_LENGTH]; 3],
    proof_stream_descriptor: StreamDescriptor,
}

pub(in crate::bgv) struct VerifiedSameSecretTerminalPreflight {
    terminal: VerifiedSameSecretTerminal,
}

impl VerifiedSameSecretTerminalPreflight {
    pub(in crate::bgv) const fn roster_position(&self) -> u16 {
        self.terminal.roster_position()
    }

    pub(in crate::bgv) fn complete(
        self,
        _verified_proof: ConsumedVerifiedCommonProofCapability,
    ) -> VerifiedSameSecretTerminal {
        self.terminal
    }
}

impl VerifiedSameSecretTerminal {
    pub(in crate::bgv) fn preflight_from_borrowed_common_proof(
        verified_proof: BorrowedVerifiedCommonProofCapability<'_>,
        canonical_application_statement_bytes: &[u8],
        verified_public_randomness: &VerifiedPublicRandomness,
    ) -> Result<VerifiedSameSecretTerminalPreflight, CommonProofVerifierError> {
        let context = verified_public_randomness.context();
        let statement = decode_selected_same_secret_statement(
            canonical_application_statement_bytes,
            SelectedApplicationStatementContext::new(
                verified_proof.protocol_version(),
                verified_proof.suite_identifier(),
                None,
                None,
            ),
        )
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let expected_application_statement_hash = verified_application_statement_hash(
            verified_proof.protocol_version(),
            verified_proof.suite_identifier(),
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
            canonical_application_statement_bytes,
        );
        let expected_application_slot_hash = ProofApplicationSlot::new(
            Hash512::from_bytes(verified_proof.suite_identifier()),
            Hash512::from_bytes(verified_proof.ceremony_context_hash()),
            Hash512::from_bytes(verified_proof.action_context_hash()),
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
            Some(statement.roster_position()),
            None,
            None,
        )
        .and_then(ProofApplicationSlot::hash)
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let expected_participant_identity = verified_public_randomness
            .ordered_participant_identities()
            .get(usize::from(statement.roster_position()))
            .copied()
            .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
        if verified_proof.protocol_version() != FOUNDATION_PROFILE.protocol_version
            || verified_proof.protocol_version() != context.protocol_version()
            || verified_proof.suite_identifier() != context.suite_identifier().into_bytes()
            || verified_proof.ceremony_context_hash()
                != context.ceremony_context_hash().into_bytes()
            || verified_proof.action_context_hash() != context.action_context_hash().into_bytes()
            || verified_proof.application_statement_schema_identifier()
                != ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER
            || verified_proof.proof_stream_domain() != CanonicalStreamDomain::SameSecretProof
            || verified_proof.application_statement_hash() != expected_application_statement_hash
            || verified_proof.proof_application_slot_hash()
                != expected_application_slot_hash.into_bytes()
            || verified_proof.schedule_position().is_some()
            || verified_proof.top_count().is_some()
            || statement.setup_proof_context_hash()
                != verified_public_randomness
                    .setup_proof_context_hash()
                    .into_bytes()
            || statement.participant_identity() != expected_participant_identity.into_bytes()
        {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }
        require_selected_unscheduled_relation_plan(&verified_proof)?;
        Ok(VerifiedSameSecretTerminalPreflight {
            terminal: Self {
                protocol_version: verified_proof.protocol_version(),
                suite_identifier: verified_proof.suite_identifier(),
                manifest_hash: context.manifest_hash().into_bytes(),
                ceremony_context_hash: verified_proof.ceremony_context_hash(),
                action_context_hash: verified_proof.action_context_hash(),
                roster_hash: context.roster_hash().into_bytes(),
                setup_proof_context_hash: statement.setup_proof_context_hash(),
                participant_identity: statement.participant_identity(),
                roster_position: statement.roster_position(),
                ordered_degree_zero_commitment_roots: statement
                    .ordered_degree_zero_commitment_roots()
                    .into(),
                anchor_commitment_roots: statement.anchor_commitment_roots(),
                proof_stream_descriptor: verified_proof.proof_stream_descriptor().clone(),
            },
        })
    }

    pub(super) const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub(super) const fn suite_identifier(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.suite_identifier
    }

    pub(super) const fn manifest_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.manifest_hash
    }

    pub(super) const fn ceremony_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.ceremony_context_hash
    }

    pub(super) const fn action_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.action_context_hash
    }

    pub(super) const fn roster_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.roster_hash
    }

    pub(super) const fn setup_proof_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.setup_proof_context_hash
    }

    pub(super) const fn participant_identity(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.participant_identity
    }

    pub(super) const fn roster_position(&self) -> u16 {
        self.roster_position
    }

    pub(super) fn ordered_degree_zero_commitment_roots(&self) -> &[[u8; Hash512::BYTE_LENGTH]] {
        &self.ordered_degree_zero_commitment_roots
    }

    pub(super) const fn anchor_commitment_roots(&self) -> [[u8; Hash512::BYTE_LENGTH]; 3] {
        self.anchor_commitment_roots
    }

    pub(super) const fn proof_stream_descriptor(&self) -> &StreamDescriptor {
        &self.proof_stream_descriptor
    }
}

/// Compact terminal for one participant's complete selected public-key share
/// proof. The verifier-owned statement roots survive while the proof frontier
/// and queries are released.
pub(in crate::bgv) struct VerifiedPublicKeyShareTerminal {
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    manifest_hash: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    anchor_commitment_roots: [[u8; Hash512::BYTE_LENGTH]; 3],
    public_key_share_root: [u8; Hash512::BYTE_LENGTH],
    proof_stream_descriptor: StreamDescriptor,
}

pub(in crate::bgv) struct VerifiedPublicKeyShareTerminalPreflight {
    terminal: VerifiedPublicKeyShareTerminal,
}

impl VerifiedPublicKeyShareTerminalPreflight {
    pub(in crate::bgv) const fn roster_position(&self) -> u16 {
        self.terminal.roster_position()
    }

    pub(in crate::bgv) fn complete(
        self,
        _verified_proof: ConsumedVerifiedCommonProofCapability,
    ) -> VerifiedPublicKeyShareTerminal {
        self.terminal
    }
}

impl VerifiedPublicKeyShareTerminal {
    pub(in crate::bgv) fn preflight_from_borrowed_common_proof(
        verified_proof: BorrowedVerifiedCommonProofCapability<'_>,
        canonical_application_statement_bytes: &[u8],
        verified_public_randomness: &VerifiedPublicRandomness,
    ) -> Result<VerifiedPublicKeyShareTerminalPreflight, CommonProofVerifierError> {
        let context = verified_public_randomness.context();
        let statement = decode_selected_public_key_share_statement(
            canonical_application_statement_bytes,
            SelectedApplicationStatementContext::new(
                verified_proof.protocol_version(),
                verified_proof.suite_identifier(),
                None,
                None,
            ),
        )
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let expected_application_statement_hash = verified_application_statement_hash(
            verified_proof.protocol_version(),
            verified_proof.suite_identifier(),
            ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
            canonical_application_statement_bytes,
        );
        let expected_application_slot_hash = ProofApplicationSlot::new(
            Hash512::from_bytes(verified_proof.suite_identifier()),
            Hash512::from_bytes(verified_proof.ceremony_context_hash()),
            Hash512::from_bytes(verified_proof.action_context_hash()),
            ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
            Some(statement.roster_position()),
            None,
            None,
        )
        .and_then(ProofApplicationSlot::hash)
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let expected_participant_identity = verified_public_randomness
            .ordered_participant_identities()
            .get(usize::from(statement.roster_position()))
            .copied()
            .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
        if verified_proof.protocol_version() != FOUNDATION_PROFILE.protocol_version
            || verified_proof.protocol_version() != context.protocol_version()
            || verified_proof.suite_identifier() != context.suite_identifier().into_bytes()
            || verified_proof.ceremony_context_hash()
                != context.ceremony_context_hash().into_bytes()
            || verified_proof.action_context_hash() != context.action_context_hash().into_bytes()
            || verified_proof.application_statement_schema_identifier()
                != ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
            || verified_proof.proof_stream_domain() != CanonicalStreamDomain::PublicKeyShareProof
            || verified_proof.application_statement_hash() != expected_application_statement_hash
            || verified_proof.proof_application_slot_hash()
                != expected_application_slot_hash.into_bytes()
            || verified_proof.schedule_position().is_some()
            || verified_proof.top_count().is_some()
            || statement.setup_proof_context_hash()
                != verified_public_randomness
                    .setup_proof_context_hash()
                    .into_bytes()
            || statement.participant_identity() != expected_participant_identity.into_bytes()
        {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }
        require_selected_unscheduled_relation_plan(&verified_proof)?;
        Ok(VerifiedPublicKeyShareTerminalPreflight {
            terminal: Self {
                protocol_version: verified_proof.protocol_version(),
                suite_identifier: verified_proof.suite_identifier(),
                manifest_hash: context.manifest_hash().into_bytes(),
                ceremony_context_hash: verified_proof.ceremony_context_hash(),
                action_context_hash: verified_proof.action_context_hash(),
                roster_hash: context.roster_hash().into_bytes(),
                setup_proof_context_hash: statement.setup_proof_context_hash(),
                participant_identity: statement.participant_identity(),
                roster_position: statement.roster_position(),
                anchor_commitment_roots: statement.anchor_commitment_roots(),
                public_key_share_root: statement.public_key_share_root(),
                proof_stream_descriptor: verified_proof.proof_stream_descriptor().clone(),
            },
        })
    }

    pub(super) const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub(super) const fn suite_identifier(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.suite_identifier
    }

    pub(super) const fn manifest_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.manifest_hash
    }

    pub(super) const fn ceremony_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.ceremony_context_hash
    }

    pub(super) const fn action_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.action_context_hash
    }

    pub(super) const fn roster_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.roster_hash
    }

    pub(super) const fn setup_proof_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.setup_proof_context_hash
    }

    pub(super) const fn participant_identity(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.participant_identity
    }

    pub(super) const fn roster_position(&self) -> u16 {
        self.roster_position
    }

    pub(super) const fn anchor_commitment_roots(&self) -> [[u8; Hash512::BYTE_LENGTH]; 3] {
        self.anchor_commitment_roots
    }

    pub(super) const fn public_key_share_root(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.public_key_share_root
    }

    pub(super) const fn proof_stream_descriptor(&self) -> &StreamDescriptor {
        &self.proof_stream_descriptor
    }
}

/// Compact authority minted only by consuming the complete collective-key
/// aggregate proof together with its verifier-recomputed role-three tree.
/// The large low-degree extension and Merkle layers are discarded after the
/// exact aggregate B polynomials have been recovered from their opened source
/// coefficients.
pub(in crate::bgv) struct VerifiedCollectivePublicKeyTerminal {
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    proof_stream_descriptor: StreamDescriptor,
    ordered_public_key_share_roots: Box<[[u8; Hash512::BYTE_LENGTH]]>,
    collective_public_key_root: [u8; Hash512::BYTE_LENGTH],
    collective_public_key_full_object_digest: [u8; Hash512::BYTE_LENGTH],
    collective_public_key_b_polynomials: Box<[Arc<[u64]>]>,
}

pub(in crate::bgv) struct VerifiedCollectivePublicKeyTerminalPreflight {
    terminal: VerifiedCollectivePublicKeyTerminal,
    tree_preflight: VerifiedStreamedProofTreeTerminalPreflight,
}

impl VerifiedCollectivePublicKeyTerminalPreflight {
    pub(in crate::bgv) const fn protocol_version(&self) -> u16 {
        self.terminal.protocol_version()
    }

    pub(in crate::bgv) const fn suite_identifier(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.terminal.suite_identifier()
    }

    pub(in crate::bgv) const fn ceremony_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.terminal.ceremony_context_hash()
    }

    pub(in crate::bgv) const fn action_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.terminal.action_context_hash()
    }

    pub(in crate::bgv) const fn roster_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.terminal.roster_hash()
    }

    pub(in crate::bgv) const fn setup_proof_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.terminal.setup_proof_context_hash()
    }

    pub(in crate::bgv) fn ordered_public_key_share_roots(&self) -> &[[u8; Hash512::BYTE_LENGTH]] {
        self.terminal.ordered_public_key_share_roots()
    }

    pub(in crate::bgv) fn complete(
        self,
        _verified_proof: ConsumedVerifiedCommonProofCapability,
        collective_public_key_tree: SetupPublicPolynomialTree,
    ) -> VerifiedCollectivePublicKeyTerminal {
        let _collective_public_key_tree = self.tree_preflight.complete(collective_public_key_tree);
        self.terminal
    }
}

impl VerifiedCollectivePublicKeyTerminal {
    pub(in crate::bgv) fn preflight_from_borrowed_common_proof_and_tree(
        verified_proof: BorrowedVerifiedCommonProofCapability<'_>,
        canonical_application_statement_bytes: &[u8],
        roster_hash: [u8; Hash512::BYTE_LENGTH],
        statement_trees: &[VerifiedStatementOwnedTree],
        collective_public_key_tree: &SetupPublicPolynomialTree,
    ) -> Result<VerifiedCollectivePublicKeyTerminalPreflight, CommonProofVerifierError> {
        let protocol_version = verified_proof.protocol_version();
        let suite_identifier = verified_proof.suite_identifier();
        let proof_stream_descriptor = verified_proof.proof_stream_descriptor().clone();
        let statement = decode_selected_collective_public_key_aggregate_statement(
            canonical_application_statement_bytes,
            SelectedApplicationStatementContext::new(
                protocol_version,
                suite_identifier,
                None,
                None,
            ),
        )
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let expected_application_statement_hash = verified_application_statement_hash(
            protocol_version,
            suite_identifier,
            ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            canonical_application_statement_bytes,
        );
        let expected_application_slot_hash = ProofApplicationSlot::new(
            Hash512::from_bytes(suite_identifier),
            Hash512::from_bytes(verified_proof.ceremony_context_hash()),
            Hash512::from_bytes(verified_proof.action_context_hash()),
            ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            None,
            None,
            None,
        )
        .and_then(ProofApplicationSlot::hash)
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let public_polynomial_context = SetupPublicPolynomialContext::collective_public_key(
            statement.setup_proof_context_hash(),
        )
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let expected_column_moduli = expected_collective_public_key_column_moduli()?;
        let selected_plan_artifact = selected_relation_plans()
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?
            .into_iter()
            .find(|artifact| {
                artifact.application_statement_schema_identifier()
                    == ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
            })
            .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
        let selected_plan = selected_plan_artifact.compiled_plan();
        let selected_variant = selected_plan
            .select_variant(None, None)
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let expected_tree = selected_variant
            .ordered_trees()
            .get(
                usize::try_from(COLLECTIVE_PUBLIC_KEY_AGGREGATE_TREE_ORDINAL)
                    .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?,
            )
            .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
        let expected_relation_column_count = match expected_tree {
            RelationTreeDescriptor::BoundPublic {
                construction_kind: BoundTreeConstructionKind::SetupPolynomial,
                expected_root_source_ordinal,
                root_use: BoundTreeRootUse::Output,
                ordered_column_ordinals,
            } if *expected_root_source_ordinal
                == COLLECTIVE_PUBLIC_KEY_AGGREGATE_ROOT_SOURCE_ORDINAL =>
            {
                ordered_column_ordinals.len()
            }
            _ => return Err(CommonProofVerifierError::InvalidApplicationStatement),
        };
        let mut matching_statement_trees = statement_trees.iter().filter(|tree| {
            tree.ordered_tree_ordinal() == COLLECTIVE_PUBLIC_KEY_AGGREGATE_TREE_ORDINAL
                && tree.expected_root_source_ordinal()
                    == COLLECTIVE_PUBLIC_KEY_AGGREGATE_ROOT_SOURCE_ORDINAL
                && tree.expected_root() == statement.collective_public_key_root()
        });
        let statement_tree = matching_statement_trees
            .next()
            .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
        if matching_statement_trees.next().is_some() {
            return Err(CommonProofVerifierError::InvalidBoundTree);
        }

        if protocol_version != FOUNDATION_PROFILE.protocol_version
            || verified_proof.application_statement_schema_identifier()
                != ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
            || verified_proof.proof_stream_domain()
                != CanonicalStreamDomain::CollectivePublicKeyAggregateProof
            || verified_proof.application_statement_hash()
                != expected_application_statement_hash
            || verified_proof.proof_application_slot_hash()
                != expected_application_slot_hash.into_bytes()
            || verified_proof.schedule_position().is_some()
            || verified_proof.top_count().is_some()
            || selected_plan
                .canonical_hash()
                .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?
                != verified_proof.relation_plan_hash()
            || selected_variant
                .canonical_hash()
                .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?
                != verified_proof.relation_plan_variant_hash()
            || collective_public_key_tree.root() != statement.collective_public_key_root()
            || collective_public_key_tree.source_polynomial_degree_bound_exclusive()
                != COLLECTIVE_PUBLIC_KEY_TRACE_HALF_DEGREE
            || usize::try_from(collective_public_key_tree.row_width()).ok()
                != Some(COLLECTIVE_PUBLIC_KEY_TRACE_COLUMN_COUNT)
            || expected_relation_column_count != COLLECTIVE_PUBLIC_KEY_TRACE_COLUMN_COUNT
            || statement_tree.ordered_canonical_residue_moduli()
                != expected_column_moduli.as_slice()
        {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }

        let collective_public_key_b_polynomials = compact_collective_public_key_b_polynomials(
            collective_public_key_tree.ordered_trace_rows(),
        )?;
        let tree_preflight =
            VerifiedStreamedProofTreeTerminal::preflight_from_recomputed_public_polynomial_tree(
                verified_proof.verified_proof(),
                canonical_application_statement_bytes,
                verified_proof.ceremony_context_hash(),
                verified_proof.action_context_hash(),
                roster_hash,
                COLLECTIVE_PUBLIC_KEY_AGGREGATE_TREE_ORDINAL,
                COLLECTIVE_PUBLIC_KEY_AGGREGATE_ROOT_SOURCE_ORDINAL,
                statement.collective_public_key_root(),
                public_polynomial_context,
                expected_column_moduli,
                collective_public_key_tree,
            )?;
        Ok(VerifiedCollectivePublicKeyTerminalPreflight {
            terminal: Self {
                protocol_version,
                suite_identifier,
                ceremony_context_hash: verified_proof.ceremony_context_hash(),
                action_context_hash: verified_proof.action_context_hash(),
                roster_hash,
                setup_proof_context_hash: statement.setup_proof_context_hash(),
                proof_stream_descriptor,
                ordered_public_key_share_roots: statement.ordered_public_key_share_roots().into(),
                collective_public_key_root: statement.collective_public_key_root(),
                collective_public_key_full_object_digest: statement
                    .collective_public_key_full_object_digest(),
                collective_public_key_b_polynomials,
            },
            tree_preflight,
        })
    }

    pub(super) const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub(super) const fn suite_identifier(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.suite_identifier
    }

    pub(super) const fn ceremony_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.ceremony_context_hash
    }

    pub(super) const fn action_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.action_context_hash
    }

    pub(super) const fn roster_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.roster_hash
    }

    pub(super) const fn setup_proof_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.setup_proof_context_hash
    }

    pub(super) const fn proof_stream_descriptor(&self) -> &StreamDescriptor {
        &self.proof_stream_descriptor
    }

    pub(super) fn ordered_public_key_share_roots(&self) -> &[[u8; Hash512::BYTE_LENGTH]] {
        &self.ordered_public_key_share_roots
    }

    pub(super) const fn collective_public_key_root(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.collective_public_key_root
    }

    pub(super) const fn collective_public_key_full_object_digest(
        &self,
    ) -> [u8; Hash512::BYTE_LENGTH] {
        self.collective_public_key_full_object_digest
    }

    pub(super) fn collective_public_key_b_polynomials(&self) -> &[Arc<[u64]>] {
        &self.collective_public_key_b_polynomials
    }
}

/// Compact authority for one dealer's complete selected VSS linkage proof.
/// It retains the exact root inventory needed to join every recipient's
/// aggregate proof to the same dealer witnesses, plus the verified proof
/// descriptor used by the terminal package inventory.
pub(in crate::bgv) struct VerifiedVssShareLinkageTerminal {
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    manifest_hash: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    public_setup_seed: [u8; Hash512::BYTE_LENGTH],
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    board_object_hash: [u8; Hash512::BYTE_LENGTH],
    board_object_canonical_byte_length: u64,
    proof_stream_descriptor: StreamDescriptor,
    ordered_coefficient_material_roots: Box<[[u8; Hash512::BYTE_LENGTH]]>,
    ordered_recipient_share_material_roots: Box<[[u8; Hash512::BYTE_LENGTH]]>,
    ordered_recipient_envelope_hashes: Box<[[u8; Hash512::BYTE_LENGTH]]>,
}

pub(in crate::bgv) struct VerifiedVssShareLinkageTerminalPreflight {
    terminal: VerifiedVssShareLinkageTerminal,
}

impl VerifiedVssShareLinkageTerminalPreflight {
    pub(in crate::bgv) fn complete(
        self,
        _verified_proof: ConsumedVerifiedCommonProofCapability,
    ) -> VerifiedVssShareLinkageTerminal {
        self.terminal
    }
}

impl VerifiedVssShareLinkageTerminal {
    pub(in crate::bgv) fn preflight_from_borrowed_common_proof(
        verified_proof: BorrowedVerifiedCommonProofCapability<'_>,
        canonical_application_statement_bytes: &[u8],
        board_source: &VerifiedBoardApplicationSource,
        verified_public_randomness: &VerifiedPublicRandomness,
    ) -> Result<VerifiedVssShareLinkageTerminalPreflight, CommonProofVerifierError> {
        let protocol_version = verified_proof.protocol_version();
        let suite_identifier = verified_proof.suite_identifier();
        let board_object_hash = verified_proof.board_object_hash();
        let board_object_canonical_byte_length =
            u64::try_from(board_source.canonical_carrier_bytes().len())
                .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let proof_stream_descriptor = verified_proof.proof_stream_descriptor().clone();
        let board_payload = board_source
            .dealer_public_record_payload()
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let verified_setup_context = verified_public_randomness.context();
        let statement = decode_selected_vss_share_linkage_statement(
            canonical_application_statement_bytes,
            SelectedApplicationStatementContext::new(
                protocol_version,
                suite_identifier,
                None,
                None,
            ),
        )
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let expected_application_statement_hash = verified_application_statement_hash(
            protocol_version,
            suite_identifier,
            ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
            canonical_application_statement_bytes,
        );
        let expected_application_slot_hash = ProofApplicationSlot::new(
            Hash512::from_bytes(suite_identifier),
            Hash512::from_bytes(verified_proof.ceremony_context_hash()),
            Hash512::from_bytes(verified_proof.action_context_hash()),
            ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
            Some(statement.roster_position()),
            None,
            None,
        )
        .and_then(ProofApplicationSlot::hash)
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        if protocol_version != FOUNDATION_PROFILE.protocol_version
            || verified_proof.application_statement_schema_identifier()
                != ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
            || verified_proof.proof_stream_domain()
                != CanonicalStreamDomain::DealerVssShareLinkageProof
            || verified_proof.application_statement_hash() != expected_application_statement_hash
            || verified_proof.proof_application_slot_hash()
                != expected_application_slot_hash.into_bytes()
            || verified_proof.schedule_position().is_some()
            || verified_proof.top_count().is_some()
            || statement.protocol_version() != protocol_version
            || statement.suite_identifier() != suite_identifier
            || statement.ceremony_context_hash() != verified_proof.ceremony_context_hash()
            || statement.action_context_hash() != verified_proof.action_context_hash()
            || !board_source_matches_setup_context(board_source, verified_setup_context)
            || board_source.object_hash().into_bytes() != board_object_hash
            || board_source.producer_sequence() != 0
            || board_source.producer_roster_position() != Some(statement.roster_position())
            || board_source
                .producer_participant_identity()
                .map(ParticipantIdentity::into_bytes)
                != Some(statement.participant_identity())
            || board_payload.dealer_roster_position() != statement.roster_position()
            || board_payload.public_setup_seed_prerequisite()
                != verified_public_randomness.public_setup_seed()
            || statement.public_setup_seed()
                != verified_public_randomness.public_setup_seed().into_bytes()
            || board_payload.share_linkage_proof() != &proof_stream_descriptor
            || !hash_roots_match_statement_roots(
                board_payload.coefficient_material_roots(),
                statement.ordered_coefficient_material_roots(),
            )
            || !hash_roots_match_statement_roots(
                board_payload.recipient_share_material_roots(),
                statement.ordered_recipient_share_material_roots(),
            )
            || board_payload.ordered_recipient_envelope_hashes().len()
                != verified_public_randomness
                    .ordered_participant_identities()
                    .len()
            || verified_public_randomness
                .ordered_participant_identities()
                .get(usize::from(statement.roster_position()))
                .map(|participant_identity| participant_identity.into_bytes())
                != Some(statement.participant_identity())
        {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }
        Ok(VerifiedVssShareLinkageTerminalPreflight {
            terminal: Self {
                protocol_version,
                suite_identifier,
                manifest_hash: verified_setup_context.manifest_hash().into_bytes(),
                ceremony_context_hash: statement.ceremony_context_hash(),
                action_context_hash: statement.action_context_hash(),
                roster_hash: statement.roster_hash(),
                public_setup_seed: statement.public_setup_seed(),
                setup_proof_context_hash: verified_public_randomness
                    .setup_proof_context_hash()
                    .into_bytes(),
                participant_identity: statement.participant_identity(),
                roster_position: statement.roster_position(),
                board_object_hash,
                board_object_canonical_byte_length,
                proof_stream_descriptor,
                ordered_coefficient_material_roots: statement
                    .ordered_coefficient_material_roots()
                    .to_vec()
                    .into_boxed_slice(),
                ordered_recipient_share_material_roots: statement
                    .ordered_recipient_share_material_roots()
                    .to_vec()
                    .into_boxed_slice(),
                ordered_recipient_envelope_hashes: board_payload
                    .ordered_recipient_envelope_hashes()
                    .iter()
                    .map(|envelope_hash| envelope_hash.into_bytes())
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
            },
        })
    }

    pub(in crate::bgv) const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub(in crate::bgv) const fn suite_identifier(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.suite_identifier
    }

    pub(in crate::bgv) const fn manifest_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.manifest_hash
    }

    pub(in crate::bgv) const fn ceremony_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.ceremony_context_hash
    }

    pub(in crate::bgv) const fn action_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.action_context_hash
    }

    pub(in crate::bgv) const fn roster_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.roster_hash
    }

    pub(in crate::bgv) const fn public_setup_seed(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.public_setup_seed
    }

    pub(in crate::bgv) const fn setup_proof_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.setup_proof_context_hash
    }

    pub(in crate::bgv) const fn participant_identity(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.participant_identity
    }

    pub(in crate::bgv) const fn roster_position(&self) -> u16 {
        self.roster_position
    }

    pub(in crate::bgv) const fn board_object_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.board_object_hash
    }

    pub(in crate::bgv) const fn board_object_canonical_byte_length(&self) -> u64 {
        self.board_object_canonical_byte_length
    }

    pub(in crate::bgv) const fn proof_stream_descriptor(&self) -> &StreamDescriptor {
        &self.proof_stream_descriptor
    }

    pub(in crate::bgv) fn ordered_coefficient_material_roots(
        &self,
    ) -> &[[u8; Hash512::BYTE_LENGTH]] {
        &self.ordered_coefficient_material_roots
    }

    pub(in crate::bgv) fn ordered_recipient_share_material_roots(
        &self,
    ) -> &[[u8; Hash512::BYTE_LENGTH]] {
        &self.ordered_recipient_share_material_roots
    }

    pub(in crate::bgv) fn ordered_recipient_envelope_hashes(
        &self,
    ) -> &[[u8; Hash512::BYTE_LENGTH]] {
        &self.ordered_recipient_envelope_hashes
    }
}

/// Compact authority for one participant's aggregate threshold-share proof.
/// Its source roots remain compact so the final join can prove that every
/// recipient aggregate consumed the same dealer roots accepted by 0x2110.
pub(in crate::bgv) struct VerifiedAggregateThresholdShareTerminal {
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    manifest_hash: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    public_setup_seed: [u8; Hash512::BYTE_LENGTH],
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    board_object_hash: [u8; Hash512::BYTE_LENGTH],
    board_object_canonical_byte_length: u64,
    proof_stream_descriptor: StreamDescriptor,
    recipient_input_root: [u8; Hash512::BYTE_LENGTH],
    ordered_source_share_roots: Box<[[u8; Hash512::BYTE_LENGTH]]>,
    ordered_aggregate_threshold_roots: Box<[[u8; Hash512::BYTE_LENGTH]]>,
}

impl VerifiedAggregateThresholdShareTerminal {
    pub(in crate::bgv) fn from_consumed_common_proof(
        verified_proof: ConsumedVerifiedCommonProofCapability,
        canonical_application_statement_bytes: &[u8],
        board_source: VerifiedBoardApplicationSource,
        verified_public_randomness: &VerifiedPublicRandomness,
    ) -> Result<Self, CommonProofVerifierError> {
        let protocol_version = verified_proof.protocol_version();
        let suite_identifier = verified_proof.suite_identifier();
        let board_object_hash = verified_proof.board_object_hash();
        let board_object_canonical_byte_length =
            u64::try_from(board_source.canonical_carrier_bytes().len())
                .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let proof_stream_descriptor = verified_proof.proof_stream_descriptor().clone();
        let board_payload = board_source
            .private_share_acceptance_payload()
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let verified_setup_context = verified_public_randomness.context();
        let statement = decode_selected_aggregate_threshold_share_statement(
            canonical_application_statement_bytes,
            SelectedApplicationStatementContext::new(
                protocol_version,
                suite_identifier,
                None,
                None,
            ),
        )
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let expected_application_statement_hash = verified_application_statement_hash(
            protocol_version,
            suite_identifier,
            ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
            canonical_application_statement_bytes,
        );
        let expected_application_slot_hash = ProofApplicationSlot::new(
            Hash512::from_bytes(suite_identifier),
            Hash512::from_bytes(verified_proof.ceremony_context_hash()),
            Hash512::from_bytes(verified_proof.action_context_hash()),
            ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
            Some(statement.roster_position()),
            None,
            None,
        )
        .and_then(ProofApplicationSlot::hash)
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;

        if protocol_version != FOUNDATION_PROFILE.protocol_version
            || verified_proof.application_statement_schema_identifier()
                != ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER
            || verified_proof.proof_stream_domain()
                != CanonicalStreamDomain::RecipientAggregateThresholdShareProof
            || verified_proof.application_statement_hash()
                != expected_application_statement_hash
            || verified_proof.proof_application_slot_hash()
                != expected_application_slot_hash.into_bytes()
            || verified_proof.schedule_position().is_some()
            || verified_proof.top_count().is_some()
            || statement.protocol_version() != protocol_version
            || statement.suite_identifier() != suite_identifier
            || statement.ceremony_context_hash() != verified_proof.ceremony_context_hash()
            || statement.action_context_hash() != verified_proof.action_context_hash()
            || !board_source_matches_setup_context(&board_source, verified_setup_context)
            || board_source.object_hash().into_bytes() != board_object_hash
            || board_source.producer_sequence() != 0
            || board_source.producer_roster_position() != Some(statement.roster_position())
            || board_source
                .producer_participant_identity()
                .map(ParticipantIdentity::into_bytes)
                != Some(statement.participant_identity())
            || board_payload.recipient_input_root().into_bytes()
                != statement.recipient_input_root()
            || board_payload.aggregate_threshold_share_proof() != &proof_stream_descriptor
            || !hash_roots_match_statement_roots(
                board_payload.aggregate_threshold_share_material_roots(),
                statement.ordered_aggregate_threshold_roots(),
            )
            || verified_public_randomness
                .ordered_participant_identities()
                .get(usize::from(statement.roster_position()))
                .map(|participant_identity| participant_identity.into_bytes())
                != Some(statement.participant_identity())
        {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }

        Ok(Self {
            protocol_version,
            suite_identifier,
            manifest_hash: verified_setup_context.manifest_hash().into_bytes(),
            ceremony_context_hash: statement.ceremony_context_hash(),
            action_context_hash: statement.action_context_hash(),
            roster_hash: statement.roster_hash(),
            public_setup_seed: verified_public_randomness.public_setup_seed().into_bytes(),
            setup_proof_context_hash: verified_public_randomness
                .setup_proof_context_hash()
                .into_bytes(),
            participant_identity: statement.participant_identity(),
            roster_position: statement.roster_position(),
            board_object_hash,
            board_object_canonical_byte_length,
            proof_stream_descriptor,
            recipient_input_root: statement.recipient_input_root(),
            ordered_source_share_roots: statement
                .ordered_source_share_roots()
                .to_vec()
                .into_boxed_slice(),
            ordered_aggregate_threshold_roots: statement
                .ordered_aggregate_threshold_roots()
                .to_vec()
                .into_boxed_slice(),
        })
    }

    pub(super) const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub(super) const fn suite_identifier(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.suite_identifier
    }

    pub(super) const fn manifest_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.manifest_hash
    }

    pub(super) const fn ceremony_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.ceremony_context_hash
    }

    pub(super) const fn action_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.action_context_hash
    }

    pub(super) const fn roster_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.roster_hash
    }

    pub(super) const fn public_setup_seed(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.public_setup_seed
    }

    pub(super) const fn setup_proof_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.setup_proof_context_hash
    }

    pub(super) const fn participant_identity(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.participant_identity
    }

    pub(in crate::bgv) const fn roster_position(&self) -> u16 {
        self.roster_position
    }

    pub(super) const fn board_object_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.board_object_hash
    }

    pub(super) const fn board_object_canonical_byte_length(&self) -> u64 {
        self.board_object_canonical_byte_length
    }

    pub(super) const fn proof_stream_descriptor(&self) -> &StreamDescriptor {
        &self.proof_stream_descriptor
    }

    pub(super) const fn recipient_input_root(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.recipient_input_root
    }

    pub(super) fn ordered_source_share_roots(&self) -> &[[u8; Hash512::BYTE_LENGTH]] {
        &self.ordered_source_share_roots
    }

    pub(super) fn ordered_aggregate_threshold_roots(&self) -> &[[u8; Hash512::BYTE_LENGTH]] {
        &self.ordered_aggregate_threshold_roots
    }
}

/// Closed, compact VSS qualification authority for the exact selected roster.
/// Each constituent proof terminal has already consumed and joined its signed
/// board carrier. Construction additionally recomputes every recipient input
/// root and checks the dealer/recipient transpose before discarding the large
/// cross-product root catalogs that no later verifier consumes.
pub(in crate::bgv) struct VerifiedVssQualificationTerminals {
    context: VerifiedSetupVerificationContext,
    public_setup_seed: Hash512,
    setup_proof_context_hash: Hash512,
    ordered_participant_identities: Box<[ParticipantIdentity]>,
    ordered_dealer_public_record_object_hashes: Box<[Hash512]>,
    ordered_dealer_public_record_canonical_byte_lengths: Box<[u64]>,
    ordered_private_share_acceptance_object_hashes: Box<[Hash512]>,
    ordered_private_share_acceptance_canonical_byte_lengths: Box<[u64]>,
    ordered_share_linkage_proof_descriptors: Box<[StreamDescriptor]>,
    ordered_aggregate_threshold_share_proof_descriptors: Box<[StreamDescriptor]>,
    ordered_degree_zero_vss_material_roots: Box<[[u8; Hash512::BYTE_LENGTH]]>,
    ordered_aggregate_threshold_share_material_roots: Box<[[u8; Hash512::BYTE_LENGTH]]>,
}

impl VerifiedVssQualificationTerminals {
    pub(in crate::bgv) fn from_verified_terminals(
        verified_public_randomness: &VerifiedPublicRandomness,
        ordered_dealer_terminals: Vec<VerifiedVssShareLinkageTerminal>,
        ordered_recipient_terminals: Vec<VerifiedAggregateThresholdShareTerminal>,
    ) -> Result<Self, RefusalReason> {
        let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
        let sharing_limb_count = selected_sharing_data_prime_coordinates()
            .map_err(|error| error.refusal_reason)?
            .len();
        let reconstruction_threshold = usize::from(FOUNDATION_PROFILE.reconstruction_threshold);
        let expected_coefficient_root_count = sharing_limb_count
            .checked_mul(reconstruction_threshold)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        let expected_recipient_root_count = sharing_limb_count
            .checked_mul(participant_count)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        if ordered_dealer_terminals.len() != participant_count
            || ordered_recipient_terminals.len() != participant_count
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }

        let context = verified_public_randomness.context();
        let public_setup_seed = verified_public_randomness.public_setup_seed();
        let setup_proof_context_hash = verified_public_randomness.setup_proof_context_hash();
        let ordered_participant_identities =
            verified_public_randomness.ordered_participant_identities();
        let mut ordered_dealer_public_record_object_hashes = Vec::with_capacity(participant_count);
        let mut ordered_dealer_public_record_canonical_byte_lengths =
            Vec::with_capacity(participant_count);
        let mut ordered_share_linkage_proof_descriptors = Vec::with_capacity(participant_count);
        let mut ordered_degree_zero_vss_material_roots = Vec::with_capacity(
            participant_count
                .checked_mul(sharing_limb_count)
                .ok_or(RefusalReason::OutsideSupportedProfile)?,
        );

        for (dealer_roster_position, terminal) in ordered_dealer_terminals.iter().enumerate() {
            let expected_roster_position = u16::try_from(dealer_roster_position)
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
            let expected_participant_identity = ordered_participant_identities
                .get(dealer_roster_position)
                .ok_or(RefusalReason::WrongTypeOrLength)?;
            if !vss_terminal_matches_setup_context(
                terminal,
                context,
                public_setup_seed,
                setup_proof_context_hash,
            ) || terminal.roster_position() != expected_roster_position
                || terminal.participant_identity() != expected_participant_identity.into_bytes()
            {
                return Err(RefusalReason::WrongContext);
            }
            if terminal.ordered_coefficient_material_roots().len()
                != expected_coefficient_root_count
                || terminal.ordered_recipient_share_material_roots().len()
                    != expected_recipient_root_count
                || terminal.ordered_recipient_envelope_hashes().len() != participant_count
            {
                return Err(RefusalReason::WrongTypeOrLength);
            }
            ordered_dealer_public_record_object_hashes
                .push(Hash512::from_bytes(terminal.board_object_hash()));
            ordered_dealer_public_record_canonical_byte_lengths
                .push(terminal.board_object_canonical_byte_length());
            ordered_share_linkage_proof_descriptors
                .push(terminal.proof_stream_descriptor().clone());
            for sharing_limb_ordinal in 0..sharing_limb_count {
                let coefficient_zero_ordinal = sharing_limb_ordinal
                    .checked_mul(reconstruction_threshold)
                    .ok_or(RefusalReason::OutsideSupportedProfile)?;
                ordered_degree_zero_vss_material_roots.push(
                    *terminal
                        .ordered_coefficient_material_roots()
                        .get(coefficient_zero_ordinal)
                        .ok_or(RefusalReason::WrongTypeOrLength)?,
                );
            }
        }

        let mut ordered_private_share_acceptance_object_hashes =
            Vec::with_capacity(participant_count);
        let mut ordered_private_share_acceptance_canonical_byte_lengths =
            Vec::with_capacity(participant_count);
        let mut ordered_aggregate_threshold_share_proof_descriptors =
            Vec::with_capacity(participant_count);
        let mut ordered_aggregate_threshold_share_material_roots =
            Vec::with_capacity(expected_recipient_root_count);
        for (recipient_roster_position, terminal) in ordered_recipient_terminals.iter().enumerate()
        {
            let expected_roster_position = u16::try_from(recipient_roster_position)
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
            let expected_participant_identity = ordered_participant_identities
                .get(recipient_roster_position)
                .ok_or(RefusalReason::WrongTypeOrLength)?;
            if !aggregate_terminal_matches_setup_context(
                terminal,
                context,
                public_setup_seed,
                setup_proof_context_hash,
            ) || terminal.roster_position() != expected_roster_position
                || terminal.participant_identity() != expected_participant_identity.into_bytes()
            {
                return Err(RefusalReason::WrongContext);
            }
            if terminal.ordered_source_share_roots().len() != expected_recipient_root_count
                || terminal.ordered_aggregate_threshold_roots().len() != sharing_limb_count
            {
                return Err(RefusalReason::WrongTypeOrLength);
            }

            let ordered_recipient_envelope_hashes = ordered_dealer_terminals
                .iter()
                .map(|dealer_terminal| {
                    dealer_terminal
                        .ordered_recipient_envelope_hashes()
                        .get(recipient_roster_position)
                        .copied()
                        .map(Hash512::from_bytes)
                        .ok_or(RefusalReason::WrongTypeOrLength)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let expected_recipient_input_root = derive_recipient_input_root(
                context.action_context_hash(),
                *expected_participant_identity,
                &ordered_dealer_public_record_object_hashes,
                &ordered_recipient_envelope_hashes,
            )?;
            if terminal.recipient_input_root() != expected_recipient_input_root.into_bytes() {
                return Err(RefusalReason::WrongHashOrRoot);
            }

            for (dealer_roster_position, dealer_terminal) in
                ordered_dealer_terminals.iter().enumerate()
            {
                for sharing_limb_ordinal in 0..sharing_limb_count {
                    let aggregate_source_ordinal = dealer_roster_position
                        .checked_mul(sharing_limb_count)
                        .and_then(|offset| offset.checked_add(sharing_limb_ordinal))
                        .ok_or(RefusalReason::OutsideSupportedProfile)?;
                    let dealer_recipient_ordinal = sharing_limb_ordinal
                        .checked_mul(participant_count)
                        .and_then(|offset| offset.checked_add(recipient_roster_position))
                        .ok_or(RefusalReason::OutsideSupportedProfile)?;
                    if terminal.ordered_source_share_roots()[aggregate_source_ordinal]
                        != dealer_terminal.ordered_recipient_share_material_roots()
                            [dealer_recipient_ordinal]
                    {
                        return Err(RefusalReason::WrongHashOrRoot);
                    }
                }
            }

            ordered_private_share_acceptance_object_hashes
                .push(Hash512::from_bytes(terminal.board_object_hash()));
            ordered_private_share_acceptance_canonical_byte_lengths
                .push(terminal.board_object_canonical_byte_length());
            ordered_aggregate_threshold_share_proof_descriptors
                .push(terminal.proof_stream_descriptor().clone());
            ordered_aggregate_threshold_share_material_roots
                .extend_from_slice(terminal.ordered_aggregate_threshold_roots());
        }

        Ok(Self {
            context,
            public_setup_seed,
            setup_proof_context_hash,
            ordered_participant_identities: ordered_participant_identities
                .to_vec()
                .into_boxed_slice(),
            ordered_dealer_public_record_object_hashes: ordered_dealer_public_record_object_hashes
                .into_boxed_slice(),
            ordered_dealer_public_record_canonical_byte_lengths:
                ordered_dealer_public_record_canonical_byte_lengths.into_boxed_slice(),
            ordered_private_share_acceptance_object_hashes:
                ordered_private_share_acceptance_object_hashes.into_boxed_slice(),
            ordered_private_share_acceptance_canonical_byte_lengths:
                ordered_private_share_acceptance_canonical_byte_lengths.into_boxed_slice(),
            ordered_share_linkage_proof_descriptors: ordered_share_linkage_proof_descriptors
                .into_boxed_slice(),
            ordered_aggregate_threshold_share_proof_descriptors:
                ordered_aggregate_threshold_share_proof_descriptors.into_boxed_slice(),
            ordered_degree_zero_vss_material_roots: ordered_degree_zero_vss_material_roots
                .into_boxed_slice(),
            ordered_aggregate_threshold_share_material_roots:
                ordered_aggregate_threshold_share_material_roots.into_boxed_slice(),
        })
    }

    pub(super) const fn context(&self) -> VerifiedSetupVerificationContext {
        self.context
    }

    pub(super) const fn public_setup_seed(&self) -> Hash512 {
        self.public_setup_seed
    }

    pub(super) const fn setup_proof_context_hash(&self) -> Hash512 {
        self.setup_proof_context_hash
    }

    pub(super) fn ordered_participant_identities(&self) -> &[ParticipantIdentity] {
        &self.ordered_participant_identities
    }

    pub(super) fn ordered_dealer_public_record_object_hashes(&self) -> &[Hash512] {
        &self.ordered_dealer_public_record_object_hashes
    }

    pub(super) fn ordered_dealer_public_record_canonical_byte_lengths(&self) -> &[u64] {
        &self.ordered_dealer_public_record_canonical_byte_lengths
    }

    pub(super) fn ordered_private_share_acceptance_object_hashes(&self) -> &[Hash512] {
        &self.ordered_private_share_acceptance_object_hashes
    }

    pub(super) fn ordered_private_share_acceptance_canonical_byte_lengths(&self) -> &[u64] {
        &self.ordered_private_share_acceptance_canonical_byte_lengths
    }

    pub(super) fn ordered_share_linkage_proof_descriptors(&self) -> &[StreamDescriptor] {
        &self.ordered_share_linkage_proof_descriptors
    }

    pub(super) fn ordered_aggregate_threshold_share_proof_descriptors(
        &self,
    ) -> &[StreamDescriptor] {
        &self.ordered_aggregate_threshold_share_proof_descriptors
    }

    pub(super) fn degree_zero_vss_material_roots_for_dealer(
        &self,
        dealer_roster_position: usize,
    ) -> Option<&[[u8; Hash512::BYTE_LENGTH]]> {
        let sharing_limb_count = selected_sharing_data_prime_coordinates().ok()?.len();
        let start = dealer_roster_position.checked_mul(sharing_limb_count)?;
        let end = start.checked_add(sharing_limb_count)?;
        self.ordered_degree_zero_vss_material_roots.get(start..end)
    }

    pub(super) fn aggregate_threshold_share_material_roots_for_recipient(
        &self,
        recipient_roster_position: usize,
    ) -> Option<&[[u8; Hash512::BYTE_LENGTH]]> {
        let sharing_limb_count = selected_sharing_data_prime_coordinates().ok()?.len();
        let start = recipient_roster_position.checked_mul(sharing_limb_count)?;
        let end = start.checked_add(sharing_limb_count)?;
        self.ordered_aggregate_threshold_share_material_roots
            .get(start..end)
    }
}

fn board_source_matches_setup_context(
    board_source: &VerifiedBoardApplicationSource,
    context: VerifiedSetupVerificationContext,
) -> bool {
    board_source.suite_identifier() == context.suite_identifier()
        && board_source.manifest_hash() == context.manifest_hash()
        && board_source.ceremony_context_hash() == context.ceremony_context_hash()
        && board_source.action_context_hash() == context.action_context_hash()
        && board_source.roster_hash() == context.roster_hash()
}

fn hash_roots_match_statement_roots(
    board_roots: &[Hash512],
    statement_roots: &[[u8; Hash512::BYTE_LENGTH]],
) -> bool {
    board_roots.len() == statement_roots.len()
        && board_roots
            .iter()
            .zip(statement_roots)
            .all(|(board_root, statement_root)| board_root.as_bytes() == statement_root)
}

fn vss_terminal_matches_setup_context(
    terminal: &VerifiedVssShareLinkageTerminal,
    context: VerifiedSetupVerificationContext,
    public_setup_seed: Hash512,
    setup_proof_context_hash: Hash512,
) -> bool {
    terminal.protocol_version() == context.protocol_version()
        && terminal.suite_identifier() == context.suite_identifier().into_bytes()
        && terminal.manifest_hash() == context.manifest_hash().into_bytes()
        && terminal.ceremony_context_hash() == context.ceremony_context_hash().into_bytes()
        && terminal.action_context_hash() == context.action_context_hash().into_bytes()
        && terminal.roster_hash() == context.roster_hash().into_bytes()
        && terminal.public_setup_seed() == public_setup_seed.into_bytes()
        && terminal.setup_proof_context_hash() == setup_proof_context_hash.into_bytes()
}

fn aggregate_terminal_matches_setup_context(
    terminal: &VerifiedAggregateThresholdShareTerminal,
    context: VerifiedSetupVerificationContext,
    public_setup_seed: Hash512,
    setup_proof_context_hash: Hash512,
) -> bool {
    terminal.protocol_version() == context.protocol_version()
        && terminal.suite_identifier() == context.suite_identifier().into_bytes()
        && terminal.manifest_hash() == context.manifest_hash().into_bytes()
        && terminal.ceremony_context_hash() == context.ceremony_context_hash().into_bytes()
        && terminal.action_context_hash() == context.action_context_hash().into_bytes()
        && terminal.roster_hash() == context.roster_hash().into_bytes()
        && terminal.public_setup_seed() == public_setup_seed.into_bytes()
        && terminal.setup_proof_context_hash() == setup_proof_context_hash.into_bytes()
}

pub(in crate::bgv) fn derive_recipient_input_root(
    action_context_hash: Hash512,
    recipient_participant_identity: ParticipantIdentity,
    ordered_dealer_public_record_object_hashes: &[Hash512],
    ordered_recipient_envelope_hashes: &[Hash512],
) -> Result<Hash512, RefusalReason> {
    let dealer_record_items = ordered_dealer_public_record_object_hashes
        .iter()
        .map(|object_hash| CanonicalItem::hash512(object_hash.into_bytes()))
        .collect::<Vec<_>>();
    let recipient_envelope_items = ordered_recipient_envelope_hashes
        .iter()
        .map(|envelope_hash| CanonicalItem::hash512(envelope_hash.into_bytes()))
        .collect::<Vec<_>>();
    hash_foundation_tuple_512(
        RECIPIENT_INPUT_ROOT_DOMAIN,
        &[
            CanonicalItem::hash512(action_context_hash.into_bytes()),
            CanonicalItem::participant_identity(recipient_participant_identity.into_bytes()),
            CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &dealer_record_items)
                .map_err(terminal_canonical_codec_refusal)?,
            CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &recipient_envelope_items)
                .map_err(terminal_canonical_codec_refusal)?,
        ],
    )
    .map_err(terminal_canonical_codec_refusal)
}

fn terminal_canonical_codec_refusal(error: CanonicalCodecError) -> RefusalReason {
    if error.kind == CanonicalCodecErrorKind::LimitExceeded {
        RefusalReason::OutsideSupportedProfile
    } else {
        RefusalReason::MalformedEncoding
    }
}

fn require_selected_unscheduled_relation_plan(
    verified_proof: &BorrowedVerifiedCommonProofCapability<'_>,
) -> Result<(), CommonProofVerifierError> {
    let selected_plan_artifact = selected_relation_plans()
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?
        .into_iter()
        .find(|artifact| {
            artifact.application_statement_schema_identifier()
                == verified_proof.application_statement_schema_identifier()
        })
        .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
    let selected_plan = selected_plan_artifact.compiled_plan();
    let selected_variant = selected_plan
        .select_variant(None, None)
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
    if selected_plan
        .canonical_hash()
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?
        != verified_proof.relation_plan_hash()
        || selected_variant
            .canonical_hash()
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?
            != verified_proof.relation_plan_variant_hash()
    {
        return Err(CommonProofVerifierError::InvalidApplicationStatement);
    }
    Ok(())
}

fn expected_collective_public_key_column_moduli()
-> Result<Vec<Option<SuiteModulusReference>>, CommonProofVerifierError> {
    let mut ordered_moduli = Vec::with_capacity(COLLECTIVE_PUBLIC_KEY_TRACE_COLUMN_COUNT);
    for data_modulus_index in 0..DATA_PRIMES.len() {
        let reference = SuiteModulusReference::data(
            u16::try_from(data_modulus_index)
                .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?,
        );
        ordered_moduli.extend([Some(reference); 2]);
    }
    Ok(ordered_moduli)
}

fn compact_collective_public_key_b_polynomials(
    columns: &[Vec<crate::bgv::proof_suite::ProofBaseFieldElement>],
) -> Result<Box<[Arc<[u64]>]>, CommonProofVerifierError> {
    if columns.len() != COLLECTIVE_PUBLIC_KEY_TRACE_COLUMN_COUNT {
        return Err(CommonProofVerifierError::InvalidBoundTree);
    }
    columns
        .chunks_exact(2)
        .zip(DATA_PRIMES)
        .map(|(split_columns, modulus)| {
            if split_columns
                .iter()
                .any(|half| half.len() != COLLECTIVE_PUBLIC_KEY_TRACE_HALF_DEGREE)
            {
                return Err(CommonProofVerifierError::InvalidBoundTree);
            }
            let coefficients = split_columns
                .iter()
                .flat_map(|half| half.iter())
                .map(|coefficient| coefficient.canonical())
                .collect::<Vec<_>>();
            if coefficients.len() != POLYNOMIAL_DEGREE
                || coefficients
                    .iter()
                    .any(|coefficient| *coefficient >= modulus)
            {
                return Err(CommonProofVerifierError::InvalidBoundTree);
            }
            Ok(Arc::<[u64]>::from(coefficients))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Vec::into_boxed_slice)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bgv::{
            proof_suite::{
                ProofBaseFieldElement, canonical_selected_vss_share_linkage_statement,
                selected_recipient_private_vss_payload_byte_length,
                verified_application_statement_hash,
            },
            setup::{
                GeneratedPrivateVssMailboxCorpusInput,
                VerifiedGeneratedPrivateVssMailboxCorpusByteLengthCatalog,
            },
        },
        foundation::{
            CanonicalDecodeLimits, MAILBOX_ENVELOPE_ATTEMPT_IDENTIFIER_BYTE_LENGTH,
            MAILBOX_GCM_TAG_BYTE_LENGTH, MAILBOX_KEM_CIPHERTEXT_BYTE_LENGTH,
            MAILBOX_SOURCE_SIGNATURE_BYTE_LENGTH, MailboxAssociatedData, MailboxKeyScheduleInput,
            SignedMailboxEnvelope,
        },
    };

    fn test_hash(
        family: u8,
        first_ordinal: usize,
        second_ordinal: usize,
        third_ordinal: usize,
    ) -> [u8; Hash512::BYTE_LENGTH] {
        let mut bytes = [family; Hash512::BYTE_LENGTH];
        bytes[1..3].copy_from_slice(&u16::try_from(first_ordinal).unwrap().to_le_bytes());
        bytes[3..5].copy_from_slice(&u16::try_from(second_ordinal).unwrap().to_le_bytes());
        bytes[5..7].copy_from_slice(&u16::try_from(third_ordinal).unwrap().to_le_bytes());
        bytes
    }

    fn test_stream_descriptor(family: u8, roster_position: usize) -> StreamDescriptor {
        StreamDescriptor::new(
            1,
            vec![Hash512::from_bytes(test_hash(
                family,
                roster_position,
                0,
                0,
            ))],
            Hash512::from_bytes(test_hash(family.wrapping_add(1), roster_position, 0, 0)),
        )
        .unwrap()
    }

    fn selected_sharing_limb_count() -> usize {
        selected_sharing_data_prime_coordinates()
            .expect("selected sharing coordinates")
            .len()
    }

    fn vss_qualification_fixture() -> (
        VerifiedPublicRandomness,
        Vec<VerifiedVssShareLinkageTerminal>,
        Vec<VerifiedAggregateThresholdShareTerminal>,
    ) {
        let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
        let reconstruction_threshold = usize::from(FOUNDATION_PROFILE.reconstruction_threshold);
        let participant_identities = (0..participant_count)
            .map(|roster_position| {
                ParticipantIdentity::from_bytes(test_hash(0x71, roster_position, 0, 0))
            })
            .collect::<Vec<_>>();
        let verified_public_randomness = VerifiedPublicRandomness::from_test_values(
            Hash512::from_bytes([0x11; 64]),
            Hash512::from_bytes([0x18; 64]),
            Hash512::from_bytes([0x22; 64]),
            Hash512::from_bytes([0x33; 64]),
            Hash512::from_bytes([0x44; 64]),
            participant_identities.clone(),
            Hash512::from_bytes([0x55; 64]),
        );
        let context = verified_public_randomness.context();
        let setup_proof_context_hash = verified_public_randomness.setup_proof_context_hash();

        let dealer_terminals = (0..participant_count)
            .map(|dealer_roster_position| {
                let ordered_coefficient_material_roots = (0..selected_sharing_limb_count())
                    .flat_map(|sharing_limb_ordinal| {
                        (0..reconstruction_threshold).map(move |coefficient_ordinal| {
                            test_hash(
                                0x81,
                                dealer_roster_position,
                                sharing_limb_ordinal,
                                coefficient_ordinal,
                            )
                        })
                    })
                    .collect::<Vec<_>>();
                let ordered_recipient_share_material_roots = (0..selected_sharing_limb_count())
                    .flat_map(|sharing_limb_ordinal| {
                        (0..participant_count).map(move |recipient_roster_position| {
                            test_hash(
                                0x82,
                                dealer_roster_position,
                                sharing_limb_ordinal,
                                recipient_roster_position,
                            )
                        })
                    })
                    .collect::<Vec<_>>();
                let ordered_recipient_envelope_hashes = (0..participant_count)
                    .map(|recipient_roster_position| {
                        test_hash(0x83, dealer_roster_position, recipient_roster_position, 0)
                    })
                    .collect::<Vec<_>>();
                VerifiedVssShareLinkageTerminal {
                    protocol_version: FOUNDATION_PROFILE.protocol_version,
                    suite_identifier: context.suite_identifier().into_bytes(),
                    manifest_hash: context.manifest_hash().into_bytes(),
                    ceremony_context_hash: context.ceremony_context_hash().into_bytes(),
                    action_context_hash: context.action_context_hash().into_bytes(),
                    roster_hash: context.roster_hash().into_bytes(),
                    public_setup_seed: verified_public_randomness.public_setup_seed().into_bytes(),
                    setup_proof_context_hash: setup_proof_context_hash.into_bytes(),
                    participant_identity: participant_identities[dealer_roster_position]
                        .into_bytes(),
                    roster_position: u16::try_from(dealer_roster_position).unwrap(),
                    board_object_hash: test_hash(0x84, dealer_roster_position, 0, 0),
                    board_object_canonical_byte_length: u64::try_from(201 + dealer_roster_position)
                        .unwrap(),
                    proof_stream_descriptor: test_stream_descriptor(0x85, dealer_roster_position),
                    ordered_coefficient_material_roots: ordered_coefficient_material_roots
                        .into_boxed_slice(),
                    ordered_recipient_share_material_roots: ordered_recipient_share_material_roots
                        .into_boxed_slice(),
                    ordered_recipient_envelope_hashes: ordered_recipient_envelope_hashes
                        .into_boxed_slice(),
                }
            })
            .collect::<Vec<_>>();

        let ordered_dealer_object_hashes = dealer_terminals
            .iter()
            .map(|terminal| Hash512::from_bytes(terminal.board_object_hash()))
            .collect::<Vec<_>>();
        let recipient_terminals = (0..participant_count)
            .map(|recipient_roster_position| {
                let ordered_recipient_envelope_hashes = dealer_terminals
                    .iter()
                    .map(|dealer_terminal| {
                        Hash512::from_bytes(
                            dealer_terminal.ordered_recipient_envelope_hashes()
                                [recipient_roster_position],
                        )
                    })
                    .collect::<Vec<_>>();
                let recipient_input_root = derive_recipient_input_root(
                    context.action_context_hash(),
                    participant_identities[recipient_roster_position],
                    &ordered_dealer_object_hashes,
                    &ordered_recipient_envelope_hashes,
                )
                .unwrap();
                let ordered_source_share_roots = dealer_terminals
                    .iter()
                    .flat_map(|dealer_terminal| {
                        (0..selected_sharing_limb_count()).map(move |sharing_limb_ordinal| {
                            dealer_terminal.ordered_recipient_share_material_roots()
                                [sharing_limb_ordinal * participant_count
                                    + recipient_roster_position]
                        })
                    })
                    .collect::<Vec<_>>();
                let ordered_aggregate_threshold_roots = (0..selected_sharing_limb_count())
                    .map(|sharing_limb_ordinal| {
                        test_hash(0x91, recipient_roster_position, sharing_limb_ordinal, 0)
                    })
                    .collect::<Vec<_>>();
                VerifiedAggregateThresholdShareTerminal {
                    protocol_version: FOUNDATION_PROFILE.protocol_version,
                    suite_identifier: context.suite_identifier().into_bytes(),
                    manifest_hash: context.manifest_hash().into_bytes(),
                    ceremony_context_hash: context.ceremony_context_hash().into_bytes(),
                    action_context_hash: context.action_context_hash().into_bytes(),
                    roster_hash: context.roster_hash().into_bytes(),
                    public_setup_seed: verified_public_randomness.public_setup_seed().into_bytes(),
                    setup_proof_context_hash: setup_proof_context_hash.into_bytes(),
                    participant_identity: participant_identities[recipient_roster_position]
                        .into_bytes(),
                    roster_position: u16::try_from(recipient_roster_position).unwrap(),
                    board_object_hash: test_hash(0x92, recipient_roster_position, 0, 0),
                    board_object_canonical_byte_length: u64::try_from(
                        301 + recipient_roster_position,
                    )
                    .unwrap(),
                    proof_stream_descriptor: test_stream_descriptor(
                        0x93,
                        recipient_roster_position,
                    ),
                    recipient_input_root: recipient_input_root.into_bytes(),
                    ordered_source_share_roots: ordered_source_share_roots.into_boxed_slice(),
                    ordered_aggregate_threshold_roots: ordered_aggregate_threshold_roots
                        .into_boxed_slice(),
                }
            })
            .collect::<Vec<_>>();
        (
            verified_public_randomness,
            dealer_terminals,
            recipient_terminals,
        )
    }

    fn selected_mailbox_material_roots(
        dealer_terminal: &VerifiedVssShareLinkageTerminal,
        recipient_roster_position: usize,
    ) -> Vec<Hash512> {
        let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
        let mut ordered_roots = dealer_terminal
            .ordered_coefficient_material_roots()
            .iter()
            .copied()
            .map(Hash512::from_bytes)
            .collect::<Vec<_>>();
        ordered_roots.extend(
            (0..selected_sharing_limb_count()).map(|sharing_limb_ordinal| {
                Hash512::from_bytes(
                    dealer_terminal.ordered_recipient_share_material_roots()
                        [sharing_limb_ordinal * participant_count + recipient_roster_position],
                )
            }),
        );
        ordered_roots
    }

    fn generated_mailbox_catalog_fixture() -> (
        VerifiedPublicRandomness,
        Vec<VerifiedVssShareLinkageTerminal>,
        Vec<VerifiedAggregateThresholdShareTerminal>,
        Vec<Vec<u8>>,
    ) {
        let (verified_public_randomness, mut dealer_terminals, mut recipient_terminals) =
            vss_qualification_fixture();
        let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
        let context = verified_public_randomness.context();
        let payload_byte_length = selected_recipient_private_vss_payload_byte_length()
            .expect("selected recipient-private payload length");
        let stream_chunk_byte_length =
            u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length).unwrap();
        let chunk_count =
            usize::try_from(payload_byte_length.div_ceil(stream_chunk_byte_length)).unwrap();
        let mut canonical_envelope_corpus = Vec::with_capacity(
            participant_count
                .checked_mul(participant_count)
                .expect("selected mailbox count"),
        );

        for (dealer_roster_position, dealer_terminal) in dealer_terminals.iter_mut().enumerate() {
            let canonical_statement = canonical_selected_vss_share_linkage_statement(
                context.protocol_version(),
                context.suite_identifier().into_bytes(),
                context.ceremony_context_hash().into_bytes(),
                context.action_context_hash().into_bytes(),
                context.roster_hash().into_bytes(),
                verified_public_randomness.public_setup_seed().into_bytes(),
                dealer_terminal.participant_identity(),
                dealer_terminal.roster_position(),
                dealer_terminal.ordered_coefficient_material_roots(),
                dealer_terminal.ordered_recipient_share_material_roots(),
            )
            .expect("selected VSS statement");
            let statement_hash = Hash512::from_bytes(verified_application_statement_hash(
                context.protocol_version(),
                context.suite_identifier().into_bytes(),
                ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
                &canonical_statement,
            ));
            for recipient_roster_position in 0..participant_count {
                let mut attempt_identifier =
                    [0_u8; MAILBOX_ENVELOPE_ATTEMPT_IDENTIFIER_BYTE_LENGTH];
                attempt_identifier[..2]
                    .copy_from_slice(&u16::try_from(dealer_roster_position).unwrap().to_le_bytes());
                attempt_identifier[2..4].copy_from_slice(
                    &u16::try_from(recipient_roster_position)
                        .unwrap()
                        .to_le_bytes(),
                );
                let key_schedule_input = MailboxKeyScheduleInput {
                    suite_id: context.suite_identifier(),
                    ceremony_context_hash: context.ceremony_context_hash(),
                    action_context_hash: context.action_context_hash(),
                    roster_hash: context.roster_hash(),
                    source_participant_id: ParticipantIdentity::from_bytes(
                        dealer_terminal.participant_identity(),
                    ),
                    recipient_participant_id: verified_public_randomness
                        .ordered_participant_identities()[recipient_roster_position],
                    producer_sequence: 0,
                    envelope_attempt_identifier: attempt_identifier,
                    statement_hash,
                    ordered_material_roots: selected_mailbox_material_roots(
                        dealer_terminal,
                        recipient_roster_position,
                    ),
                };
                let descriptor = StreamDescriptor::new(
                    payload_byte_length,
                    (0..chunk_count)
                        .map(|chunk_ordinal| {
                            Hash512::from_bytes(test_hash(
                                0xa1,
                                dealer_roster_position,
                                recipient_roster_position,
                                chunk_ordinal,
                            ))
                        })
                        .collect(),
                    Hash512::from_bytes(test_hash(
                        0xa2,
                        dealer_roster_position,
                        recipient_roster_position,
                        0,
                    )),
                )
                .expect("selected mailbox descriptor");
                let envelope = SignedMailboxEnvelope::new(
                    MailboxAssociatedData::new(key_schedule_input)
                        .expect("selected mailbox associated data"),
                    [0x5a; MAILBOX_KEM_CIPHERTEXT_BYTE_LENGTH],
                    descriptor,
                    [0xb1; MAILBOX_GCM_TAG_BYTE_LENGTH],
                    [0xc1; MAILBOX_SOURCE_SIGNATURE_BYTE_LENGTH],
                )
                .expect("selected mailbox envelope");
                dealer_terminal.ordered_recipient_envelope_hashes[recipient_roster_position] =
                    envelope
                        .envelope_hash()
                        .expect("selected mailbox envelope hash")
                        .into_bytes();
                canonical_envelope_corpus.push(
                    envelope
                        .encode()
                        .expect("canonical selected mailbox envelope"),
                );
            }
        }

        let ordered_dealer_object_hashes = dealer_terminals
            .iter()
            .map(|terminal| Hash512::from_bytes(terminal.board_object_hash()))
            .collect::<Vec<_>>();
        for (recipient_roster_position, recipient_terminal) in
            recipient_terminals.iter_mut().enumerate()
        {
            let ordered_recipient_envelope_hashes = dealer_terminals
                .iter()
                .map(|dealer_terminal| {
                    Hash512::from_bytes(
                        dealer_terminal.ordered_recipient_envelope_hashes()
                            [recipient_roster_position],
                    )
                })
                .collect::<Vec<_>>();
            recipient_terminal.recipient_input_root = derive_recipient_input_root(
                context.action_context_hash(),
                verified_public_randomness.ordered_participant_identities()
                    [recipient_roster_position],
                &ordered_dealer_object_hashes,
                &ordered_recipient_envelope_hashes,
            )
            .expect("selected recipient input root")
            .into_bytes();
        }

        (
            verified_public_randomness,
            dealer_terminals,
            recipient_terminals,
            canonical_envelope_corpus,
        )
    }

    fn qualification_refusal(
        result: Result<VerifiedVssQualificationTerminals, RefusalReason>,
    ) -> RefusalReason {
        match result {
            Ok(_) => panic!("the invalid VSS qualification unexpectedly succeeded"),
            Err(refusal_reason) => refusal_reason,
        }
    }

    fn trace_half_columns_with_distinct_values() -> Vec<Vec<ProofBaseFieldElement>> {
        DATA_PRIMES
            .iter()
            .copied()
            .enumerate()
            .flat_map(|(modulus_ordinal, modulus)| {
                (0..2).map(move |half_ordinal| {
                    (0..COLLECTIVE_PUBLIC_KEY_TRACE_HALF_DEGREE)
                        .map(|coefficient_ordinal| {
                            let value = (u64::try_from(modulus_ordinal).unwrap() * 101
                                + u64::try_from(half_ordinal).unwrap() * 17
                                + u64::try_from(coefficient_ordinal).unwrap())
                                % modulus;
                            ProofBaseFieldElement::from_canonical(value).unwrap()
                        })
                        .collect()
                })
            })
            .collect()
    }

    #[test]
    fn collective_key_terminal_compacts_adjacent_trace_halves_in_ring_order() {
        let columns = trace_half_columns_with_distinct_values();
        let expected_first_half_end =
            columns[0][COLLECTIVE_PUBLIC_KEY_TRACE_HALF_DEGREE - 1].canonical();
        let expected_second_half_start = columns[1][0].canonical();
        let polynomials = compact_collective_public_key_b_polynomials(&columns)
            .expect("the exact selected split layout compacts");
        assert_eq!(polynomials.len(), DATA_PRIMES.len());
        assert!(
            polynomials
                .iter()
                .all(|polynomial| polynomial.len() == POLYNOMIAL_DEGREE)
        );
        assert_eq!(
            polynomials[0][COLLECTIVE_PUBLIC_KEY_TRACE_HALF_DEGREE - 1],
            expected_first_half_end
        );
        assert_eq!(
            polynomials[0][COLLECTIVE_PUBLIC_KEY_TRACE_HALF_DEGREE],
            expected_second_half_start
        );
        assert!(
            polynomials
                .iter()
                .zip(DATA_PRIMES)
                .all(|(polynomial, modulus)| {
                    polynomial.iter().all(|coefficient| *coefficient < modulus)
                })
        );
    }

    #[test]
    fn collective_key_terminal_rejects_missing_short_and_noncanonical_columns() {
        let mut missing = trace_half_columns_with_distinct_values();
        missing.pop();
        assert!(compact_collective_public_key_b_polynomials(&missing).is_err());

        let mut short = trace_half_columns_with_distinct_values();
        short[4].pop();
        assert!(compact_collective_public_key_b_polynomials(&short).is_err());

        let mut noncanonical = trace_half_columns_with_distinct_values();
        noncanonical[2][19] = ProofBaseFieldElement::from_canonical(DATA_PRIMES[1]).unwrap();
        assert!(compact_collective_public_key_b_polynomials(&noncanonical).is_err());
    }

    #[test]
    fn generated_private_vss_mailbox_catalog_joins_exact_corpus_before_terminal_compaction() {
        let (
            verified_public_randomness,
            dealer_terminals,
            recipient_terminals,
            canonical_envelope_corpus,
        ) = generated_mailbox_catalog_fixture();
        let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
        let expected_mailbox_count = participant_count
            .checked_mul(participant_count)
            .expect("selected mailbox count");
        let canonical_envelope_references = canonical_envelope_corpus
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        let catalog =
            VerifiedGeneratedPrivateVssMailboxCorpusByteLengthCatalog::from_verified_dealer_terminals(
                &verified_public_randomness,
                &dealer_terminals,
                GeneratedPrivateVssMailboxCorpusInput::new(&canonical_envelope_references),
            )
            .expect("verified generated mailbox byte-length catalog");
        let expected_envelope_hashes = dealer_terminals
            .iter()
            .flat_map(|terminal| {
                terminal
                    .ordered_recipient_envelope_hashes()
                    .iter()
                    .copied()
                    .map(Hash512::from_bytes)
            })
            .collect::<Vec<_>>();
        assert_eq!(catalog.ordered_envelope_hashes(), expected_envelope_hashes);
        assert_eq!(
            catalog.ordered_mailbox_byte_lengths().len(),
            expected_mailbox_count
        );
        let selected_payload_byte_length =
            selected_recipient_private_vss_payload_byte_length().unwrap();
        assert!(
            catalog
                .ordered_mailbox_byte_lengths()
                .iter()
                .all(|mailbox| mailbox.ciphertext_stream_byte_length()
                    == selected_payload_byte_length)
        );
        let exact_ciphertext_sum = catalog
            .ordered_mailbox_byte_lengths()
            .iter()
            .try_fold(0_u64, |total, mailbox| {
                total.checked_add(mailbox.ciphertext_stream_byte_length())
            })
            .expect("selected ciphertext corpus sum");
        let exact_envelope_sum = catalog
            .ordered_mailbox_byte_lengths()
            .iter()
            .try_fold(0_u64, |total, mailbox| {
                total.checked_add(mailbox.canonical_signed_envelope_byte_length())
            })
            .expect("selected envelope corpus sum");
        let exact_complete_sum = catalog
            .ordered_mailbox_byte_lengths()
            .iter()
            .try_fold(0_u64, |total, mailbox| {
                total.checked_add(mailbox.complete_recipient_private_wire_byte_length())
            })
            .expect("selected recipient-private corpus sum");
        assert_eq!(
            catalog.ciphertext_stream_byte_length(),
            exact_ciphertext_sum
        );
        assert_eq!(
            catalog.canonical_signed_envelope_byte_length(),
            exact_envelope_sum
        );
        assert_eq!(
            catalog.complete_recipient_private_wire_byte_length(),
            exact_complete_sum
        );
        assert_eq!(
            catalog
                .ordered_dealer_upload_byte_lengths()
                .iter()
                .sum::<u64>(),
            exact_complete_sum
        );
        assert_eq!(
            catalog
                .ordered_recipient_download_byte_lengths()
                .iter()
                .sum::<u64>(),
            exact_complete_sum
        );
        assert_eq!(
            catalog.maximum_ciphertext_descriptor_byte_length(),
            catalog
                .ordered_mailbox_byte_lengths()
                .iter()
                .map(|mailbox| mailbox.ciphertext_descriptor_byte_length())
                .max()
                .unwrap()
        );
        assert_eq!(
            catalog.maximum_canonical_signed_envelope_byte_length(),
            canonical_envelope_corpus
                .iter()
                .map(|envelope| u64::try_from(envelope.len()).unwrap())
                .max()
                .unwrap()
        );

        let mut qualification = VerifiedVssQualificationTerminals::from_verified_terminals(
            &verified_public_randomness,
            dealer_terminals,
            recipient_terminals,
        )
        .expect("selected VSS qualification");
        catalog
            .require_matches_verified_qualification(&qualification)
            .expect("mailbox catalog remains bound after terminal compaction");
        qualification.ordered_dealer_public_record_object_hashes[0] =
            Hash512::from_bytes([0xff; Hash512::BYTE_LENGTH]);
        assert_eq!(
            catalog
                .require_matches_verified_qualification(&qualification)
                .err()
                .expect("a different compact dealer authority refuses"),
            RefusalReason::WrongContext
        );
    }

    #[test]
    fn generated_private_vss_mailbox_catalog_refuses_an_envelope_outside_the_verified_matrix() {
        let (
            verified_public_randomness,
            dealer_terminals,
            _recipient_terminals,
            mut canonical_envelope_corpus,
        ) = generated_mailbox_catalog_fixture();
        let mut first_envelope = SignedMailboxEnvelope::decode(
            &canonical_envelope_corpus[0],
            &CanonicalDecodeLimits::default(),
        )
        .expect("first generated mailbox envelope");
        first_envelope.kem_ciphertext[0] ^= 1;
        canonical_envelope_corpus[0] = first_envelope
            .encode()
            .expect("canonical wrong-hash mailbox envelope");
        let canonical_envelope_references = canonical_envelope_corpus
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        assert_eq!(
            VerifiedGeneratedPrivateVssMailboxCorpusByteLengthCatalog::from_verified_dealer_terminals(
                &verified_public_randomness,
                &dealer_terminals,
                GeneratedPrivateVssMailboxCorpusInput::new(&canonical_envelope_references),
            )
            .err()
            .expect("an envelope outside the verified matrix refuses"),
            RefusalReason::WrongHashOrRoot
        );
    }

    #[test]
    fn generated_private_vss_mailbox_catalog_refuses_missing_input_without_consuming_terminals() {
        let (
            verified_public_randomness,
            dealer_terminals,
            _recipient_terminals,
            canonical_envelope_corpus,
        ) = generated_mailbox_catalog_fixture();
        let canonical_envelope_references = canonical_envelope_corpus
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        let mut incomplete_envelope_references = canonical_envelope_references.clone();
        incomplete_envelope_references.pop();
        assert_eq!(
            VerifiedGeneratedPrivateVssMailboxCorpusByteLengthCatalog::from_verified_dealer_terminals(
                &verified_public_randomness,
                &dealer_terminals,
                GeneratedPrivateVssMailboxCorpusInput::new(&incomplete_envelope_references),
            )
            .err()
            .expect("an incomplete selected-roster mailbox corpus refuses"),
            RefusalReason::WrongTypeOrLength,
        );

        let restored_catalog =
            VerifiedGeneratedPrivateVssMailboxCorpusByteLengthCatalog::from_verified_dealer_terminals(
                &verified_public_randomness,
                &dealer_terminals,
                GeneratedPrivateVssMailboxCorpusInput::new(&canonical_envelope_references),
            )
            .expect("failed preflight leaves all exact dealer terminals available");
        let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
        assert_eq!(participant_count, 10);
        assert_eq!(
            restored_catalog.ordered_mailbox_byte_lengths().len(),
            participant_count * participant_count,
        );
    }

    #[test]
    fn vss_qualification_compacts_exact_roster_order_after_recipient_transpose_joins() {
        let (verified_public_randomness, dealer_terminals, recipient_terminals) =
            vss_qualification_fixture();
        let expected_dealer_hashes = dealer_terminals
            .iter()
            .map(|terminal| Hash512::from_bytes(terminal.board_object_hash()))
            .collect::<Vec<_>>();
        let expected_acceptance_hashes = recipient_terminals
            .iter()
            .map(|terminal| Hash512::from_bytes(terminal.board_object_hash()))
            .collect::<Vec<_>>();
        let expected_dealer_canonical_byte_lengths = dealer_terminals
            .iter()
            .map(VerifiedVssShareLinkageTerminal::board_object_canonical_byte_length)
            .collect::<Vec<_>>();
        let expected_acceptance_canonical_byte_lengths = recipient_terminals
            .iter()
            .map(VerifiedAggregateThresholdShareTerminal::board_object_canonical_byte_length)
            .collect::<Vec<_>>();
        let expected_first_degree_zero_roots = (0..selected_sharing_limb_count())
            .map(|sharing_limb_ordinal| {
                dealer_terminals[0].ordered_coefficient_material_roots()[sharing_limb_ordinal
                    * usize::from(FOUNDATION_PROFILE.reconstruction_threshold)]
            })
            .collect::<Vec<_>>();
        let expected_last_aggregate_roots = recipient_terminals
            [usize::from(FOUNDATION_PROFILE.participant_count) - 1]
            .ordered_aggregate_threshold_roots()
            .to_vec();

        let qualification = VerifiedVssQualificationTerminals::from_verified_terminals(
            &verified_public_randomness,
            dealer_terminals,
            recipient_terminals,
        )
        .expect("the complete positively joined VSS roster qualifies");
        assert_eq!(
            qualification.context(),
            verified_public_randomness.context()
        );
        assert_eq!(
            qualification.public_setup_seed(),
            verified_public_randomness.public_setup_seed()
        );
        assert_eq!(
            qualification.setup_proof_context_hash(),
            verified_public_randomness.setup_proof_context_hash()
        );
        assert_eq!(
            qualification.ordered_dealer_public_record_object_hashes(),
            expected_dealer_hashes
        );
        assert_eq!(
            qualification.ordered_private_share_acceptance_object_hashes(),
            expected_acceptance_hashes
        );
        assert_eq!(
            qualification.ordered_dealer_public_record_canonical_byte_lengths(),
            expected_dealer_canonical_byte_lengths
        );
        assert_eq!(
            qualification.ordered_private_share_acceptance_canonical_byte_lengths(),
            expected_acceptance_canonical_byte_lengths
        );
        assert_eq!(
            qualification
                .degree_zero_vss_material_roots_for_dealer(0)
                .unwrap(),
            expected_first_degree_zero_roots
        );
        assert_eq!(
            qualification
                .aggregate_threshold_share_material_roots_for_recipient(
                    usize::from(FOUNDATION_PROFILE.participant_count) - 1,
                )
                .unwrap(),
            expected_last_aggregate_roots
        );
        assert_eq!(
            qualification
                .ordered_share_linkage_proof_descriptors()
                .len(),
            usize::from(FOUNDATION_PROFILE.participant_count)
        );
        assert_eq!(
            qualification
                .ordered_aggregate_threshold_share_proof_descriptors()
                .len(),
            usize::from(FOUNDATION_PROFILE.participant_count)
        );
        assert_eq!(
            qualification.ordered_participant_identities(),
            verified_public_randomness.ordered_participant_identities()
        );
    }

    #[test]
    fn vss_qualification_rejects_reordering_wrong_recipient_root_and_transpose_mismatch() {
        let (verified_public_randomness, mut dealer_terminals, recipient_terminals) =
            vss_qualification_fixture();
        dealer_terminals.swap(2, 7);
        assert_eq!(
            qualification_refusal(VerifiedVssQualificationTerminals::from_verified_terminals(
                &verified_public_randomness,
                dealer_terminals,
                recipient_terminals,
            )),
            RefusalReason::WrongContext
        );

        let (verified_public_randomness, dealer_terminals, mut recipient_terminals) =
            vss_qualification_fixture();
        recipient_terminals[4].recipient_input_root[17] ^= 0x80;
        assert_eq!(
            qualification_refusal(VerifiedVssQualificationTerminals::from_verified_terminals(
                &verified_public_randomness,
                dealer_terminals,
                recipient_terminals,
            )),
            RefusalReason::WrongHashOrRoot
        );

        let (verified_public_randomness, dealer_terminals, mut recipient_terminals) =
            vss_qualification_fixture();
        recipient_terminals[8]
            .ordered_source_share_roots
            .swap(1, 27);
        assert_eq!(
            qualification_refusal(VerifiedVssQualificationTerminals::from_verified_terminals(
                &verified_public_randomness,
                dealer_terminals,
                recipient_terminals,
            )),
            RefusalReason::WrongHashOrRoot
        );
    }

    #[test]
    fn vss_qualification_rejects_wrong_manifest_and_incomplete_rosters() {
        let (verified_public_randomness, dealer_terminals, mut recipient_terminals) =
            vss_qualification_fixture();
        recipient_terminals[3].manifest_hash[0] ^= 1;
        assert_eq!(
            qualification_refusal(VerifiedVssQualificationTerminals::from_verified_terminals(
                &verified_public_randomness,
                dealer_terminals,
                recipient_terminals,
            )),
            RefusalReason::WrongContext
        );

        let (verified_public_randomness, mut dealer_terminals, recipient_terminals) =
            vss_qualification_fixture();
        dealer_terminals.pop();
        assert_eq!(
            qualification_refusal(VerifiedVssQualificationTerminals::from_verified_terminals(
                &verified_public_randomness,
                dealer_terminals,
                recipient_terminals,
            )),
            RefusalReason::WrongTypeOrLength
        );
    }
}
