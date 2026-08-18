//! Canonical statement-owned public-polynomial LDE trees.
//!
//! Setup statements bind these Merkle roots directly. The canonical source
//! trace values are interpolated and evaluated by this module, so an object
//! hash or a claimed Merkle root can never stand in for the tree opened by the
//! common proof verifier.

use core::mem::size_of;

use crate::{
    bgv::setup::{
        SETUP_COMMITMENT_MODULUS_LIMB_INDICES, parse_lattice_anchor_commitment_canonical_bytes,
    },
    foundation::{CanonicalItem, CanonicalItemType, CanonicalTuple, hash_foundation_tuple_512},
};
use tiny_keccak::{Hasher, Shake};

use super::{
    MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH, PROOF_EVALUATION_COSET_OFFSET,
    ProofBaseFieldElement, ProofEvaluationDomain, ProofFieldError, ProofPolynomialError,
};

const SETUP_PUBLIC_POLYNOMIAL_CONTEXT_SCHEMA_IDENTIFIER: u16 = 0x121b;
pub(super) const SETUP_PUBLIC_POLYNOMIAL_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER: u16 = 0x121c;
const SETUP_PUBLIC_POLYNOMIAL_CONTEXT_SCHEMA_VERSION: u16 = 2;
pub(super) const SETUP_PUBLIC_POLYNOMIAL_LEAF_SCHEMA_VERSION: u16 = 3;

const CONTEXT_HASH_DOMAIN: &str = "sealed-lattice/setup/public-polynomial/context/v2";
pub(super) const SETUP_PUBLIC_POLYNOMIAL_LEAF_HASH_DOMAIN: &str =
    "sealed-lattice/setup/public-polynomial/phase-pair-leaf/v3";
pub(super) const SETUP_PUBLIC_POLYNOMIAL_NODE_HASH_DOMAIN: &str =
    "sealed-lattice/setup/public-polynomial/merkle-node/v3";

#[cfg(all(test, feature = "theorem-evidence"))]
pub(crate) const fn setup_public_polynomial_hash_domains()
-> (&'static str, &'static str, &'static str) {
    (
        CONTEXT_HASH_DOMAIN,
        SETUP_PUBLIC_POLYNOMIAL_LEAF_HASH_DOMAIN,
        SETUP_PUBLIC_POLYNOMIAL_NODE_HASH_DOMAIN,
    )
}

const FOUNDATION_TUPLE_SCHEMA_IDENTIFIER: u16 = 0x0001;
const FOUNDATION_TUPLE_SCHEMA_VERSION: u16 = 1;
const SETUP_PUBLIC_POLYNOMIAL_FIXED_LEAF_BYTE_LENGTH: usize = 104;
const SETUP_PUBLIC_POLYNOMIAL_FIELD_ELEMENT_BYTE_LENGTH: usize = 8;
const SETUP_PUBLIC_POLYNOMIAL_INTERLEAVED_VALUE_BYTE_LENGTH_PER_COLUMN: usize =
    SETUP_PUBLIC_POLYNOMIAL_FIELD_ELEMENT_BYTE_LENGTH * 2;
const AUTHENTICATION_DIGEST_BYTE_LENGTH: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SetupPublicPolynomialError {
    InvalidContext,
    InvalidInput,
    InvalidLatticeAnchor,
    CountOverflow,
    AllocationLimitExceeded,
    CanonicalEncoding,
    Field(ProofFieldError),
    Polynomial(ProofPolynomialError),
}

impl From<ProofFieldError> for SetupPublicPolynomialError {
    fn from(error: ProofFieldError) -> Self {
        Self::Field(error)
    }
}

impl From<ProofPolynomialError> for SetupPublicPolynomialError {
    fn from(error: ProofPolynomialError) -> Self {
        Self::Polynomial(error)
    }
}

fn canonical_encoding_error<T>(_: T) -> SetupPublicPolynomialError {
    SetupPublicPolynomialError::CanonicalEncoding
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum SetupPublicPolynomialRootRole {
    LatticeAnchor = 1,
    PublicKeyShare = 2,
    CollectivePublicKey = 3,
    RelinearizationRoundOneLeft = 4,
    RelinearizationRoundOneRight = 5,
    RelinearizationAggregateRoundOneLeft = 6,
    RelinearizationAggregateRoundOneRight = 7,
    RelinearizationRoundTwo = 8,
    GaloisKeyShare = 9,
    RelinearizationRuntime = 10,
    GaloisCommon = 11,
    GaloisRuntime = 12,
}

impl SetupPublicPolynomialRootRole {
    const fn requires_owner(self) -> bool {
        matches!(
            self,
            Self::LatticeAnchor
                | Self::PublicKeyShare
                | Self::RelinearizationRoundOneLeft
                | Self::RelinearizationRoundOneRight
                | Self::RelinearizationRoundTwo
                | Self::GaloisKeyShare
        )
    }

    const fn requires_schedule_position(self) -> bool {
        matches!(
            self,
            Self::RelinearizationRoundOneLeft
                | Self::RelinearizationRoundOneRight
                | Self::RelinearizationAggregateRoundOneLeft
                | Self::RelinearizationAggregateRoundOneRight
                | Self::RelinearizationRoundTwo
                | Self::GaloisKeyShare
                | Self::RelinearizationRuntime
                | Self::GaloisCommon
                | Self::GaloisRuntime
        )
    }

    const fn requires_commitment_data_prime(self) -> bool {
        matches!(self, Self::LatticeAnchor)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SetupPublicPolynomialContext {
    setup_proof_context_hash: [u8; 64],
    root_role: SetupPublicPolynomialRootRole,
    owner_participant_identity: Option<[u8; 64]>,
    owner_roster_position: Option<u16>,
    schedule_position: Option<u32>,
    commitment_data_prime_index: Option<u16>,
}

impl SetupPublicPolynomialContext {
    pub(crate) fn new(
        setup_proof_context_hash: [u8; 64],
        root_role: SetupPublicPolynomialRootRole,
        owner_participant_identity: Option<[u8; 64]>,
        owner_roster_position: Option<u16>,
        schedule_position: Option<u32>,
        commitment_data_prime_index: Option<u16>,
    ) -> Result<Self, SetupPublicPolynomialError> {
        let context = Self {
            setup_proof_context_hash,
            root_role,
            owner_participant_identity,
            owner_roster_position,
            schedule_position,
            commitment_data_prime_index,
        };
        context.validate()?;
        Ok(context)
    }

    pub(crate) fn lattice_anchor(
        setup_proof_context_hash: [u8; 64],
        owner_participant_identity: [u8; 64],
        owner_roster_position: u16,
        commitment_data_prime_index: u16,
    ) -> Result<Self, SetupPublicPolynomialError> {
        Self::new(
            setup_proof_context_hash,
            SetupPublicPolynomialRootRole::LatticeAnchor,
            Some(owner_participant_identity),
            Some(owner_roster_position),
            None,
            Some(commitment_data_prime_index),
        )
    }

    pub(crate) fn public_key_share(
        setup_proof_context_hash: [u8; 64],
        owner_participant_identity: [u8; 64],
        owner_roster_position: u16,
    ) -> Result<Self, SetupPublicPolynomialError> {
        Self::new(
            setup_proof_context_hash,
            SetupPublicPolynomialRootRole::PublicKeyShare,
            Some(owner_participant_identity),
            Some(owner_roster_position),
            None,
            None,
        )
    }

    pub(crate) fn collective_public_key(
        setup_proof_context_hash: [u8; 64],
    ) -> Result<Self, SetupPublicPolynomialError> {
        Self::new(
            setup_proof_context_hash,
            SetupPublicPolynomialRootRole::CollectivePublicKey,
            None,
            None,
            None,
            None,
        )
    }

    pub(crate) fn galois_common(
        setup_proof_context_hash: [u8; 64],
        schedule_position: u32,
    ) -> Result<Self, SetupPublicPolynomialError> {
        Self::new(
            setup_proof_context_hash,
            SetupPublicPolynomialRootRole::GaloisCommon,
            None,
            None,
            Some(schedule_position),
            None,
        )
    }

    fn validate(&self) -> Result<(), SetupPublicPolynomialError> {
        let owns_root =
            self.owner_participant_identity.is_some() && self.owner_roster_position.is_some();
        if owns_root != self.root_role.requires_owner()
            || self.owner_participant_identity.is_some() != self.owner_roster_position.is_some()
            || self.schedule_position.is_some() != self.root_role.requires_schedule_position()
            || self.commitment_data_prime_index.is_some()
                != self.root_role.requires_commitment_data_prime()
            || self.commitment_data_prime_index.is_some_and(|index| {
                !SETUP_COMMITMENT_MODULUS_LIMB_INDICES
                    .iter()
                    .any(|selected| u16::try_from(*selected).ok() == Some(index))
            })
        {
            return Err(SetupPublicPolynomialError::InvalidContext);
        }
        Ok(())
    }

    pub(crate) const fn root_role(&self) -> SetupPublicPolynomialRootRole {
        self.root_role
    }

    pub(crate) const fn setup_proof_context_hash(&self) -> [u8; 64] {
        self.setup_proof_context_hash
    }

    pub(crate) const fn owner_participant_identity(&self) -> Option<[u8; 64]> {
        self.owner_participant_identity
    }

    pub(crate) const fn owner_roster_position(&self) -> Option<u16> {
        self.owner_roster_position
    }

    pub(crate) const fn schedule_position(&self) -> Option<u32> {
        self.schedule_position
    }

    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>, SetupPublicPolynomialError> {
        let owner_participant_identity = self
            .owner_participant_identity
            .map(CanonicalItem::participant_identity);
        let owner_roster_position = self.owner_roster_position.map(CanonicalItem::unsigned16);
        let schedule_position = self.schedule_position.map(CanonicalItem::unsigned32);
        let commitment_data_prime_index = self
            .commitment_data_prime_index
            .map(CanonicalItem::unsigned16);
        CanonicalTuple::new(
            SETUP_PUBLIC_POLYNOMIAL_CONTEXT_SCHEMA_IDENTIFIER,
            SETUP_PUBLIC_POLYNOMIAL_CONTEXT_SCHEMA_VERSION,
            vec![
                CanonicalItem::hash512(self.setup_proof_context_hash),
                CanonicalItem::unsigned16(self.root_role as u16),
                CanonicalItem::optional(
                    CanonicalItemType::ParticipantIdentity,
                    owner_participant_identity.as_ref(),
                )
                .map_err(canonical_encoding_error)?,
                CanonicalItem::optional(
                    CanonicalItemType::Unsigned16,
                    owner_roster_position.as_ref(),
                )
                .map_err(canonical_encoding_error)?,
                CanonicalItem::optional(CanonicalItemType::Unsigned32, schedule_position.as_ref())
                    .map_err(canonical_encoding_error)?,
                CanonicalItem::optional(
                    CanonicalItemType::Unsigned16,
                    commitment_data_prime_index.as_ref(),
                )
                .map_err(canonical_encoding_error)?,
            ],
        )
        .encode()
        .map_err(canonical_encoding_error)
    }

    pub(crate) fn context_hash(&self) -> Result<[u8; 64], SetupPublicPolynomialError> {
        Ok(hash_foundation_tuple_512(
            CONTEXT_HASH_DOMAIN,
            &[CanonicalItem::variable_bytes(self.canonical_bytes()?)
                .map_err(canonical_encoding_error)?],
        )
        .map_err(canonical_encoding_error)?
        .into_bytes())
    }
}

pub(crate) struct SetupPublicPolynomialTreeInput<'input> {
    pub(crate) context: &'input SetupPublicPolynomialContext,
    pub(crate) evaluation_domain_size: usize,
    pub(crate) source_polynomial_degree_bound_exclusive: usize,
    pub(crate) ordered_trace_rows: &'input [Vec<ProofBaseFieldElement>],
}

pub(crate) struct SetupPublicPolynomialTree {
    public_polynomial_context_hash: [u8; 64],
    root_role: SetupPublicPolynomialRootRole,
    schedule_position: Option<u32>,
    #[cfg(test)]
    evaluation_domain_size: usize,
    source_polynomial_degree_bound_exclusive: usize,
    row_width: u32,
    root: [u8; 64],
    ordered_trace_rows: Vec<Vec<ProofBaseFieldElement>>,
}

pub(crate) struct SetupPublicPolynomialRootBuilder {
    public_polynomial_context_hash: [u8; 64],
    trace_domain: ProofEvaluationDomain,
    evaluation_domain: ProofEvaluationDomain,
    source_polynomial_degree_bound_exclusive: usize,
    expected_column_count: usize,
    source_polynomial_coefficients: Vec<Vec<ProofBaseFieldElement>>,
}

impl SetupPublicPolynomialRootBuilder {
    pub(crate) fn new(
        context: &SetupPublicPolynomialContext,
        evaluation_domain_size: usize,
        source_polynomial_degree_bound_exclusive: usize,
        row_width: u32,
    ) -> Result<Self, SetupPublicPolynomialError> {
        Self::from_verifier_owned_context_hash(
            context.context_hash()?,
            evaluation_domain_size,
            source_polynomial_degree_bound_exclusive,
            row_width,
        )
    }

    /// Rebuilds a setup-polynomial root from a context hash that was already
    /// derived by a verifier-owned statement-tree capability. This does not
    /// accept a producer claim: callers must first obtain the hash from the
    /// positively checked statement source.
    pub(in crate::bgv::proof_suite) fn from_verifier_owned_context_hash(
        public_polynomial_context_hash: [u8; 64],
        evaluation_domain_size: usize,
        source_polynomial_degree_bound_exclusive: usize,
        row_width: u32,
    ) -> Result<Self, SetupPublicPolynomialError> {
        if evaluation_domain_size < 2
            || !evaluation_domain_size.is_power_of_two()
            || source_polynomial_degree_bound_exclusive == 0
            || source_polynomial_degree_bound_exclusive > evaluation_domain_size
            || !source_polynomial_degree_bound_exclusive.is_power_of_two()
            || row_width == 0
        {
            return Err(SetupPublicPolynomialError::InvalidInput);
        }
        let wasm_memory_plan = setup_public_polynomial_wasm_compact_root_memory_plan(
            evaluation_domain_size,
            source_polynomial_degree_bound_exclusive,
            row_width,
        )?;
        if wasm_memory_plan.owned_payload_peak_byte_length()
            > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
        {
            return Err(SetupPublicPolynomialError::AllocationLimitExceeded);
        }
        let trace_domain =
            ProofEvaluationDomain::new_subgroup(source_polynomial_degree_bound_exclusive)?;
        let evaluation_domain =
            ProofEvaluationDomain::new(evaluation_domain_size, PROOF_EVALUATION_COSET_OFFSET)?;
        let expected_column_count =
            usize::try_from(row_width).map_err(|_| SetupPublicPolynomialError::CountOverflow)?;
        let mut source_polynomial_coefficients = Vec::new();
        source_polynomial_coefficients
            .try_reserve_exact(expected_column_count)
            .map_err(|_| SetupPublicPolynomialError::AllocationLimitExceeded)?;
        Ok(Self {
            public_polynomial_context_hash,
            trace_domain,
            evaluation_domain,
            source_polynomial_degree_bound_exclusive,
            expected_column_count,
            source_polynomial_coefficients,
        })
    }

    fn absorb_source_polynomial_coefficients(
        &mut self,
        mut coefficients: Vec<ProofBaseFieldElement>,
    ) -> Result<(), SetupPublicPolynomialError> {
        if self.source_polynomial_coefficients.len() >= self.expected_column_count
            || coefficients.len() != self.source_polynomial_degree_bound_exclusive
        {
            return Err(SetupPublicPolynomialError::InvalidInput);
        }
        self.trace_domain
            .interpolate_base_polynomial_in_place(&mut coefficients)?;
        self.source_polynomial_coefficients.push(coefficients);
        Ok(())
    }

    /// Absorbs one already-canonical setup trace row. The caller retains no
    /// authority by supplying this borrowed row: its values are copied and
    /// interpolated into the builder's bounded source-coefficient catalog.
    pub(crate) fn absorb_trace_row(
        &mut self,
        trace_row: &[ProofBaseFieldElement],
    ) -> Result<(), SetupPublicPolynomialError> {
        if trace_row.len() != self.source_polynomial_degree_bound_exclusive {
            return Err(SetupPublicPolynomialError::InvalidInput);
        }
        let mut coefficients = Vec::new();
        coefficients
            .try_reserve_exact(trace_row.len())
            .map_err(|_| SetupPublicPolynomialError::AllocationLimitExceeded)?;
        coefficients.extend_from_slice(trace_row);
        self.absorb_source_polynomial_coefficients(coefficients)
    }

    /// Decodes one canonical fixed-width residue row directly into one
    /// low-degree coefficient row. The caller never owns a decoded row, and
    /// the builder never retains its full-domain extension.
    pub(crate) fn absorb_canonical_residue_trace_row(
        &mut self,
        encoded_residues: &[u8],
        residue_byte_length: usize,
        canonical_modulus: u64,
    ) -> Result<(), SetupPublicPolynomialError> {
        if residue_byte_length == 0
            || residue_byte_length > size_of::<u64>()
            || canonical_modulus < 2
            || !encoded_residues.len().is_multiple_of(residue_byte_length)
            || encoded_residues.len() / residue_byte_length
                != self.source_polynomial_degree_bound_exclusive
        {
            return Err(SetupPublicPolynomialError::InvalidInput);
        }
        let mut coefficients = Vec::new();
        coefficients
            .try_reserve_exact(self.source_polynomial_degree_bound_exclusive)
            .map_err(|_| SetupPublicPolynomialError::AllocationLimitExceeded)?;
        for encoded_residue in encoded_residues.chunks_exact(residue_byte_length) {
            let mut residue_bytes = [0_u8; size_of::<u64>()];
            residue_bytes[..residue_byte_length].copy_from_slice(encoded_residue);
            let residue = u64::from_le_bytes(residue_bytes);
            if residue >= canonical_modulus {
                return Err(SetupPublicPolynomialError::InvalidInput);
            }
            coefficients.push(ProofBaseFieldElement::from_canonical(residue)?);
        }
        self.absorb_source_polynomial_coefficients(coefficients)
    }

    pub(crate) fn absorb_canonical_trace_row(
        &mut self,
        trace_row: &[u64],
    ) -> Result<(), SetupPublicPolynomialError> {
        if trace_row.len() != self.source_polynomial_degree_bound_exclusive {
            return Err(SetupPublicPolynomialError::InvalidInput);
        }
        let mut coefficients = Vec::new();
        coefficients
            .try_reserve_exact(trace_row.len())
            .map_err(|_| SetupPublicPolynomialError::AllocationLimitExceeded)?;
        for trace_value in trace_row {
            coefficients.push(ProofBaseFieldElement::from_canonical(*trace_value)?);
        }
        self.absorb_source_polynomial_coefficients(coefficients)
    }

    pub(crate) fn finish(mut self) -> Result<([u8; 64], [u8; 64]), SetupPublicPolynomialError> {
        if self.source_polynomial_coefficients.len() != self.expected_column_count {
            return Err(SetupPublicPolynomialError::InvalidInput);
        }
        let evaluation_domain_size = self.evaluation_domain.size();
        let coset_domain_size = self.source_polynomial_degree_bound_exclusive;
        let coset_count = evaluation_domain_size
            .checked_div(coset_domain_size)
            .ok_or(SetupPublicPolynomialError::CountOverflow)?;
        if coset_count == 0
            || !coset_count.is_power_of_two()
            || coset_domain_size < 2
            || !coset_domain_size.is_power_of_two()
        {
            return Err(SetupPublicPolynomialError::InvalidInput);
        }
        let coset_leaf_count = coset_domain_size / 2;
        let row_width = u32::try_from(self.expected_column_count)
            .map_err(|_| SetupPublicPolynomialError::CountOverflow)?;
        #[cfg(all(test, not(target_arch = "wasm32")))]
        let root_construction_started_at = std::time::Instant::now();
        #[cfg(all(test, not(target_arch = "wasm32")))]
        println!(
            "setup public-polynomial root: domain {evaluation_domain_size}, source degree {coset_domain_size}, columns {row_width}, cosets {coset_count}",
        );
        let mut merkle_frontiers = SetupPublicPolynomialCosetMerkleFrontiers::new(
            self.public_polynomial_context_hash,
            coset_count,
            coset_leaf_count,
        )?;
        let mut evaluation_workspace = Vec::new();
        evaluation_workspace
            .try_reserve_exact(coset_domain_size)
            .map_err(|_| SetupPublicPolynomialError::AllocationLimitExceeded)?;
        let evaluation_domain_generator = self.evaluation_domain.generator();
        let expected_coset_generator = evaluation_domain_generator.power(
            u64::try_from(coset_count).map_err(|_| SetupPublicPolynomialError::CountOverflow)?,
        );
        // Write N = E K. Coset r evaluates exactly the full-domain positions
        // r + E t. Its two K/2-point halves therefore form natural Merkle
        // leaf r + E t and its opposite-domain point. The coordinate
        // frontiers transpose those strided leaves back into the original
        // contiguous order without changing any leaf or parent hash.
        for coset_index in 0..coset_count {
            let coset_offset = self.evaluation_domain.point(coset_index)?;
            let coset_domain =
                ProofEvaluationDomain::new(coset_domain_size, coset_offset.canonical())?;
            if coset_domain.generator() != expected_coset_generator {
                return Err(SetupPublicPolynomialError::InvalidInput);
            }
            let mut leaf_hash_arena = SetupPublicPolynomialLeafHashArena::new_strided(
                self.public_polynomial_context_hash,
                coset_leaf_count,
                row_width,
                coset_index,
                coset_count,
            )?;
            for source_coefficients in &self.source_polynomial_coefficients {
                evaluation_workspace.clear();
                evaluation_workspace.extend_from_slice(source_coefficients);
                coset_domain.evaluate_base_polynomial_in_place(&mut evaluation_workspace)?;
                leaf_hash_arena.absorb_extension_column(&evaluation_workspace)?;
            }
            merkle_frontiers.absorb_coset_leaf_hashes(leaf_hash_arena)?;
        }
        let root = merkle_frontiers.finish()?;
        #[cfg(all(test, not(target_arch = "wasm32")))]
        println!(
            "setup public-polynomial root complete: domain {evaluation_domain_size}, source degree {coset_domain_size}, columns {row_width} ({:?})",
            root_construction_started_at.elapsed(),
        );
        self.source_polynomial_coefficients.clear();
        Ok((self.public_polynomial_context_hash, root))
    }
}

impl SetupPublicPolynomialTree {
    /// Derives the lattice-anchor root directly from its sole canonical
    /// representation without retaining decoded trace rows. The returned
    /// dimensions are derived from the same parsed bytes and let the setup
    /// authority validate later on-demand row openings without a trace
    /// catalog.
    pub(crate) fn construct_lattice_anchor_root_from_canonical_bytes(
        context: &SetupPublicPolynomialContext,
        evaluation_domain_size: usize,
        canonical_commitment_bytes: &[u8],
    ) -> Result<([u8; 64], [u8; 64], usize, u32), SetupPublicPolynomialError> {
        let commitment =
            parse_lattice_anchor_commitment_canonical_bytes(canonical_commitment_bytes)
                .map_err(|_| SetupPublicPolynomialError::InvalidLatticeAnchor)?;
        let commitment_data_prime_index = u16::try_from(commitment.commitment_data_prime_index)
            .map_err(|_| SetupPublicPolynomialError::CountOverflow)?;
        if context.root_role != SetupPublicPolynomialRootRole::LatticeAnchor
            || context.commitment_data_prime_index != Some(commitment_data_prime_index)
        {
            return Err(SetupPublicPolynomialError::InvalidLatticeAnchor);
        }
        let source_polynomial_degree_bound_exclusive = commitment.ring_degree / 2;
        if source_polynomial_degree_bound_exclusive == 0
            || source_polynomial_degree_bound_exclusive.checked_mul(2)
                != Some(commitment.ring_degree)
        {
            return Err(SetupPublicPolynomialError::InvalidLatticeAnchor);
        }
        let row_width = commitment
            .rows
            .len()
            .checked_mul(2)
            .and_then(|row_width| u32::try_from(row_width).ok())
            .ok_or(SetupPublicPolynomialError::CountOverflow)?;
        let mut root_builder = SetupPublicPolynomialRootBuilder::new(
            context,
            evaluation_domain_size,
            source_polynomial_degree_bound_exclusive,
            row_width,
        )?;
        for logical_row in &commitment.rows {
            if logical_row.len() != commitment.ring_degree {
                return Err(SetupPublicPolynomialError::InvalidLatticeAnchor);
            }
            let (low_trace_values, high_trace_values) =
                logical_row.split_at(source_polynomial_degree_bound_exclusive);
            root_builder.absorb_canonical_trace_row(low_trace_values)?;
            root_builder.absorb_canonical_trace_row(high_trace_values)?;
        }
        let (public_polynomial_context_hash, root) = root_builder.finish()?;
        Ok((
            public_polynomial_context_hash,
            root,
            source_polynomial_degree_bound_exclusive,
            row_width,
        ))
    }

    /// Decodes the sole canonical lattice-anchor representation and derives
    /// the role-one tree from the low and high trace-value halves of each
    /// logical row, in row-major order. The selected prime is checked against
    /// the typed context; neither an object hash nor a claimed Merkle root is
    /// accepted.
    #[cfg(test)]
    pub(crate) fn from_lattice_anchor_canonical_bytes(
        context: &SetupPublicPolynomialContext,
        evaluation_domain_size: usize,
        canonical_commitment_bytes: &[u8],
    ) -> Result<Self, SetupPublicPolynomialError> {
        let commitment =
            parse_lattice_anchor_commitment_canonical_bytes(canonical_commitment_bytes)
                .map_err(|_| SetupPublicPolynomialError::InvalidLatticeAnchor)?;
        let commitment_data_prime_index = u16::try_from(commitment.commitment_data_prime_index)
            .map_err(|_| SetupPublicPolynomialError::CountOverflow)?;
        if context.root_role != SetupPublicPolynomialRootRole::LatticeAnchor
            || context.commitment_data_prime_index != Some(commitment_data_prime_index)
        {
            return Err(SetupPublicPolynomialError::InvalidLatticeAnchor);
        }
        let physical_column_trace_value_count = commitment.ring_degree / 2;
        if physical_column_trace_value_count == 0
            || physical_column_trace_value_count.checked_mul(2) != Some(commitment.ring_degree)
        {
            return Err(SetupPublicPolynomialError::InvalidLatticeAnchor);
        }
        let physical_column_count = commitment
            .rows
            .len()
            .checked_mul(2)
            .ok_or(SetupPublicPolynomialError::CountOverflow)?;
        let mut ordered_trace_rows = Vec::with_capacity(physical_column_count);
        for logical_row in &commitment.rows {
            if logical_row.len() != commitment.ring_degree {
                return Err(SetupPublicPolynomialError::InvalidLatticeAnchor);
            }
            let (low_trace_values, high_trace_values) =
                logical_row.split_at(physical_column_trace_value_count);
            for physical_trace_column in [low_trace_values, high_trace_values] {
                ordered_trace_rows.push(
                    physical_trace_column
                        .iter()
                        .map(|trace_value| ProofBaseFieldElement::from_canonical(*trace_value))
                        .collect::<Result<Vec<_>, _>>()?,
                );
            }
        }
        Self::construct_from_trace_value_rows(SetupPublicPolynomialTreeInput {
            context,
            evaluation_domain_size,
            source_polynomial_degree_bound_exclusive: physical_column_trace_value_count,
            ordered_trace_rows: &ordered_trace_rows,
        })
    }

    pub(crate) fn construct(
        input: SetupPublicPolynomialTreeInput<'_>,
    ) -> Result<Self, SetupPublicPolynomialError> {
        if input.context.root_role == SetupPublicPolynomialRootRole::LatticeAnchor {
            return Err(SetupPublicPolynomialError::InvalidLatticeAnchor);
        }
        if input
            .ordered_trace_rows
            .iter()
            .any(|column| column.len() != input.source_polynomial_degree_bound_exclusive)
        {
            return Err(SetupPublicPolynomialError::InvalidInput);
        }
        Self::construct_from_trace_value_rows(input)
    }

    /// Derives a non-lattice public-polynomial root from canonical rows while
    /// retaining low-degree coefficients and evaluating one bounded coset at
    /// a time. This is the production setup-generation path for large public
    /// shares whose canonical coefficients are already retained by their
    /// authority.
    pub(crate) fn construct_root_from_canonical_trace_rows<'row>(
        context: &SetupPublicPolynomialContext,
        evaluation_domain_size: usize,
        source_polynomial_degree_bound_exclusive: usize,
        row_width: usize,
        ordered_trace_rows: impl IntoIterator<Item = &'row [u64]>,
    ) -> Result<([u8; 64], [u8; 64]), SetupPublicPolynomialError> {
        if context.root_role == SetupPublicPolynomialRootRole::LatticeAnchor {
            return Err(SetupPublicPolynomialError::InvalidLatticeAnchor);
        }
        let row_width =
            u32::try_from(row_width).map_err(|_| SetupPublicPolynomialError::CountOverflow)?;
        let mut root_builder = SetupPublicPolynomialRootBuilder::new(
            context,
            evaluation_domain_size,
            source_polynomial_degree_bound_exclusive,
            row_width,
        )?;
        for trace_row in ordered_trace_rows {
            root_builder.absorb_canonical_trace_row(trace_row)?;
        }
        root_builder.finish()
    }

    fn construct_from_trace_value_rows(
        input: SetupPublicPolynomialTreeInput<'_>,
    ) -> Result<Self, SetupPublicPolynomialError> {
        if input.evaluation_domain_size < 2
            || !input.evaluation_domain_size.is_power_of_two()
            || input.source_polynomial_degree_bound_exclusive == 0
            || input.source_polynomial_degree_bound_exclusive > input.evaluation_domain_size
            || !input
                .source_polynomial_degree_bound_exclusive
                .is_power_of_two()
            || input.ordered_trace_rows.is_empty()
            || u32::try_from(input.ordered_trace_rows.len()).is_err()
            || input
                .ordered_trace_rows
                .iter()
                .any(|row| row.len() != input.source_polynomial_degree_bound_exclusive)
        {
            return Err(SetupPublicPolynomialError::InvalidInput);
        }
        let row_width = u32::try_from(input.ordered_trace_rows.len())
            .map_err(|_| SetupPublicPolynomialError::CountOverflow)?;
        let mut root_builder = SetupPublicPolynomialRootBuilder::new(
            input.context,
            input.evaluation_domain_size,
            input.source_polynomial_degree_bound_exclusive,
            row_width,
        )?;
        for trace_row in input.ordered_trace_rows {
            root_builder.absorb_trace_row(trace_row)?;
        }
        let (public_polynomial_context_hash, root) = root_builder.finish()?;
        let ordered_trace_rows = input.ordered_trace_rows.to_vec();
        Ok(Self {
            public_polynomial_context_hash,
            root_role: input.context.root_role(),
            schedule_position: input.context.schedule_position(),
            #[cfg(test)]
            evaluation_domain_size: input.evaluation_domain_size,
            source_polynomial_degree_bound_exclusive: input
                .source_polynomial_degree_bound_exclusive,
            row_width,
            root,
            ordered_trace_rows,
        })
    }

    pub(crate) const fn public_polynomial_context_hash(&self) -> [u8; 64] {
        self.public_polynomial_context_hash
    }

    pub(crate) const fn root_role(&self) -> SetupPublicPolynomialRootRole {
        self.root_role
    }

    pub(crate) const fn schedule_position(&self) -> Option<u32> {
        self.schedule_position
    }

    pub(crate) const fn source_polynomial_degree_bound_exclusive(&self) -> usize {
        self.source_polynomial_degree_bound_exclusive
    }

    #[cfg(test)]
    pub(crate) const fn evaluation_domain_size(&self) -> usize {
        self.evaluation_domain_size
    }

    pub(crate) fn ordered_trace_rows(&self) -> &[Vec<ProofBaseFieldElement>] {
        &self.ordered_trace_rows
    }

    pub(crate) const fn row_width(&self) -> u32 {
        self.row_width
    }

    #[cfg(test)]
    pub(crate) fn leaf_count(&self) -> usize {
        self.evaluation_domain_size / 2
    }

    pub(crate) const fn root(&self) -> [u8; 64] {
        self.root
    }
}

#[cfg(test)]
pub(super) fn canonical_setup_public_polynomial_phase_pair_leaf_bytes(
    public_polynomial_context_hash: [u8; 64],
    leaf_index: u64,
    first_point_values: &[ProofBaseFieldElement],
    opposite_point_values: &[ProofBaseFieldElement],
) -> Result<Vec<u8>, SetupPublicPolynomialError> {
    canonical_setup_public_polynomial_phase_pair_leaf_bytes_from_iterators(
        public_polynomial_context_hash,
        leaf_index,
        first_point_values.iter().copied(),
        opposite_point_values.iter().copied(),
    )
}

pub(super) fn canonical_setup_public_polynomial_phase_pair_leaf_bytes_from_iterators<
    FirstValues,
    OppositeValues,
>(
    public_polynomial_context_hash: [u8; 64],
    leaf_index: u64,
    first_point_values: FirstValues,
    opposite_point_values: OppositeValues,
) -> Result<Vec<u8>, SetupPublicPolynomialError>
where
    FirstValues: ExactSizeIterator<Item = ProofBaseFieldElement>,
    OppositeValues: ExactSizeIterator<Item = ProofBaseFieldElement>,
{
    let row_width = first_point_values.len();
    if row_width == 0 || opposite_point_values.len() != row_width {
        return Err(SetupPublicPolynomialError::InvalidInput);
    }
    let row_width_u32 =
        u32::try_from(row_width).map_err(|_| SetupPublicPolynomialError::CountOverflow)?;
    let mut canonical_bytes = setup_public_polynomial_leaf_canonical_prefix(
        public_polynomial_context_hash,
        leaf_index,
        row_width_u32,
    )?;
    for (first_point_value, opposite_point_value) in first_point_values.zip(opposite_point_values) {
        canonical_bytes.extend_from_slice(&first_point_value.canonical().to_le_bytes());
        canonical_bytes.extend_from_slice(&opposite_point_value.canonical().to_le_bytes());
    }
    if canonical_bytes.len() != setup_public_polynomial_leaf_byte_length(row_width_u32)? {
        return Err(SetupPublicPolynomialError::CanonicalEncoding);
    }
    Ok(canonical_bytes)
}

fn setup_public_polynomial_leaf_canonical_prefix(
    public_polynomial_context_hash: [u8; 64],
    leaf_index: u64,
    row_width: u32,
) -> Result<Vec<u8>, SetupPublicPolynomialError> {
    let leaf_byte_length = setup_public_polynomial_leaf_byte_length(row_width)?;
    let mut canonical_bytes = Vec::new();
    canonical_bytes
        .try_reserve_exact(leaf_byte_length)
        .map_err(|_| SetupPublicPolynomialError::AllocationLimitExceeded)?;
    canonical_bytes.extend_from_slice(
        &SETUP_PUBLIC_POLYNOMIAL_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER.to_le_bytes(),
    );
    canonical_bytes.extend_from_slice(&SETUP_PUBLIC_POLYNOMIAL_LEAF_SCHEMA_VERSION.to_le_bytes());
    canonical_bytes.extend_from_slice(&3_u32.to_le_bytes());
    canonical_bytes.extend_from_slice(&CanonicalItemType::Hash512.canonical_code().to_le_bytes());
    canonical_bytes.extend_from_slice(&64_u32.to_le_bytes());
    canonical_bytes.extend_from_slice(&public_polynomial_context_hash);
    canonical_bytes
        .extend_from_slice(&CanonicalItemType::Unsigned64.canonical_code().to_le_bytes());
    canonical_bytes.extend_from_slice(&8_u32.to_le_bytes());
    canonical_bytes.extend_from_slice(&leaf_index.to_le_bytes());
    canonical_bytes.extend_from_slice(
        &setup_public_polynomial_leaf_index_and_list_header(leaf_index, row_width)?[14..],
    );
    if canonical_bytes.len() != SETUP_PUBLIC_POLYNOMIAL_FIXED_LEAF_BYTE_LENGTH {
        return Err(SetupPublicPolynomialError::CanonicalEncoding);
    }
    Ok(canonical_bytes)
}

pub(super) fn setup_public_polynomial_leaf_digest(
    canonical_bytes: &[u8],
) -> Result<[u8; 64], SetupPublicPolynomialError> {
    let domain_bytes = SETUP_PUBLIC_POLYNOMIAL_LEAF_HASH_DOMAIN.as_bytes();
    let domain_byte_length =
        u32::try_from(domain_bytes.len()).map_err(|_| SetupPublicPolynomialError::CountOverflow)?;
    let canonical_byte_length = u32::try_from(canonical_bytes.len())
        .map_err(|_| SetupPublicPolynomialError::CountOverflow)?;
    let mut state = Shake::v256();
    state.update(&FOUNDATION_TUPLE_SCHEMA_IDENTIFIER.to_le_bytes());
    state.update(&FOUNDATION_TUPLE_SCHEMA_VERSION.to_le_bytes());
    state.update(&2_u32.to_le_bytes());
    state.update(&CanonicalItemType::Ascii.canonical_code().to_le_bytes());
    state.update(
        &domain_byte_length
            .checked_add(4)
            .ok_or(SetupPublicPolynomialError::CountOverflow)?
            .to_le_bytes(),
    );
    state.update(&domain_byte_length.to_le_bytes());
    state.update(domain_bytes);
    state.update(&CanonicalItemType::RawBytes.canonical_code().to_le_bytes());
    state.update(
        &canonical_byte_length
            .checked_add(4)
            .ok_or(SetupPublicPolynomialError::CountOverflow)?
            .to_le_bytes(),
    );
    state.update(&canonical_byte_length.to_le_bytes());
    state.update(canonical_bytes);
    let mut digest = [0_u8; AUTHENTICATION_DIGEST_BYTE_LENGTH];
    state.finalize(&mut digest);
    Ok(digest)
}

pub(super) fn setup_public_polynomial_merkle_node_digest(
    public_polynomial_context_hash: [u8; 64],
    level: u32,
    parent_index: u64,
    left_child_digest: [u8; 64],
    right_child_digest: [u8; 64],
) -> Result<[u8; 64], SetupPublicPolynomialError> {
    let left_child_index = parent_index
        .checked_mul(2)
        .ok_or(SetupPublicPolynomialError::CountOverflow)?;
    let domain_bytes = SETUP_PUBLIC_POLYNOMIAL_NODE_HASH_DOMAIN.as_bytes();
    let domain_byte_length =
        u32::try_from(domain_bytes.len()).map_err(|_| SetupPublicPolynomialError::CountOverflow)?;
    let mut state = Shake::v256();
    state.update(&FOUNDATION_TUPLE_SCHEMA_IDENTIFIER.to_le_bytes());
    state.update(&FOUNDATION_TUPLE_SCHEMA_VERSION.to_le_bytes());
    state.update(&6_u32.to_le_bytes());
    state.update(&CanonicalItemType::Ascii.canonical_code().to_le_bytes());
    state.update(
        &domain_byte_length
            .checked_add(4)
            .ok_or(SetupPublicPolynomialError::CountOverflow)?
            .to_le_bytes(),
    );
    state.update(&domain_byte_length.to_le_bytes());
    state.update(domain_bytes);
    state.update(&CanonicalItemType::Hash512.canonical_code().to_le_bytes());
    state.update(&64_u32.to_le_bytes());
    state.update(&public_polynomial_context_hash);
    state.update(&CanonicalItemType::Unsigned32.canonical_code().to_le_bytes());
    state.update(&4_u32.to_le_bytes());
    state.update(&level.to_le_bytes());
    state.update(&CanonicalItemType::Unsigned64.canonical_code().to_le_bytes());
    state.update(&8_u32.to_le_bytes());
    state.update(&left_child_index.to_le_bytes());
    state.update(&CanonicalItemType::Hash512.canonical_code().to_le_bytes());
    state.update(&64_u32.to_le_bytes());
    state.update(&left_child_digest);
    state.update(&CanonicalItemType::Hash512.canonical_code().to_le_bytes());
    state.update(&64_u32.to_le_bytes());
    state.update(&right_child_digest);
    let mut digest = [0_u8; AUTHENTICATION_DIGEST_BYTE_LENGTH];
    state.finalize(&mut digest);
    Ok(digest)
}

pub(super) fn setup_public_polynomial_leaf_byte_length(
    row_width: u32,
) -> Result<usize, SetupPublicPolynomialError> {
    if row_width == 0 {
        return Err(SetupPublicPolynomialError::InvalidInput);
    }
    usize::try_from(row_width)
        .ok()
        .and_then(|width| {
            width.checked_mul(SETUP_PUBLIC_POLYNOMIAL_INTERLEAVED_VALUE_BYTE_LENGTH_PER_COLUMN)
        })
        .and_then(|value_byte_length| {
            SETUP_PUBLIC_POLYNOMIAL_FIXED_LEAF_BYTE_LENGTH.checked_add(value_byte_length)
        })
        .ok_or(SetupPublicPolynomialError::CountOverflow)
}

pub(crate) struct SetupPublicPolynomialLeafHashArena {
    public_polynomial_context_hash: [u8; 64],
    leaf_hash_states: Vec<Shake>,
    leaf_count: usize,
    expected_column_count: usize,
    absorbed_column_count: usize,
    next_leaf_index: usize,
    first_leaf_index: usize,
    leaf_index_stride: usize,
}

impl SetupPublicPolynomialLeafHashArena {
    #[cfg(test)]
    pub(crate) fn new(
        public_polynomial_context_hash: [u8; 64],
        leaf_count: usize,
        row_width: u32,
    ) -> Result<Self, SetupPublicPolynomialError> {
        Self::new_strided(public_polynomial_context_hash, leaf_count, row_width, 0, 1)
    }

    fn new_strided(
        public_polynomial_context_hash: [u8; 64],
        leaf_count: usize,
        row_width: u32,
        first_leaf_index: usize,
        leaf_index_stride: usize,
    ) -> Result<Self, SetupPublicPolynomialError> {
        if leaf_count == 0
            || !leaf_count.is_power_of_two()
            || row_width == 0
            || leaf_index_stride == 0
        {
            return Err(SetupPublicPolynomialError::InvalidInput);
        }
        let final_leaf_index = leaf_count
            .checked_sub(1)
            .and_then(|last_local_index| last_local_index.checked_mul(leaf_index_stride))
            .and_then(|last_offset| first_leaf_index.checked_add(last_offset))
            .ok_or(SetupPublicPolynomialError::CountOverflow)?;
        let _ = u64::try_from(final_leaf_index)
            .map_err(|_| SetupPublicPolynomialError::CountOverflow)?;
        let expected_column_count =
            usize::try_from(row_width).map_err(|_| SetupPublicPolynomialError::CountOverflow)?;
        let common_leaf_hash_state = setup_public_polynomial_common_leaf_hash_state(
            public_polynomial_context_hash,
            row_width,
        )?;
        let mut leaf_hash_states = Vec::new();
        leaf_hash_states
            .try_reserve_exact(leaf_count)
            .map_err(|_| SetupPublicPolynomialError::AllocationLimitExceeded)?;
        for local_leaf_index in 0..leaf_count {
            let leaf_index = local_leaf_index
                .checked_mul(leaf_index_stride)
                .and_then(|offset| first_leaf_index.checked_add(offset))
                .ok_or(SetupPublicPolynomialError::CountOverflow)?;
            let mut leaf_hash_state = common_leaf_hash_state.clone();
            leaf_hash_state.update(&setup_public_polynomial_leaf_index_and_list_header(
                u64::try_from(leaf_index).map_err(|_| SetupPublicPolynomialError::CountOverflow)?,
                row_width,
            )?);
            leaf_hash_states.push(leaf_hash_state);
        }
        Ok(Self {
            public_polynomial_context_hash,
            leaf_hash_states,
            leaf_count,
            expected_column_count,
            absorbed_column_count: 0,
            next_leaf_index: 0,
            first_leaf_index,
            leaf_index_stride,
        })
    }

    fn absorb_extension_column(
        &mut self,
        extension_column: &[ProofBaseFieldElement],
    ) -> Result<(), SetupPublicPolynomialError> {
        let expected_extension_value_count = self
            .leaf_count
            .checked_mul(2)
            .ok_or(SetupPublicPolynomialError::CountOverflow)?;
        if self.absorbed_column_count >= self.expected_column_count
            || extension_column.len() != expected_extension_value_count
        {
            return Err(SetupPublicPolynomialError::InvalidInput);
        }
        self.absorb_extension_column_chunk(
            0,
            &extension_column[..self.leaf_count],
            &extension_column[self.leaf_count..],
        )
    }

    /// Absorbs one bounded range from the next canonical column. Both slices
    /// name the same leaf indexes in the first and opposite domain halves.
    /// Completing the final range advances exactly one column; a changed
    /// range start or column order cannot silently advance the arena.
    pub(crate) fn absorb_extension_column_chunk(
        &mut self,
        first_leaf_index: usize,
        first_point_values: &[ProofBaseFieldElement],
        opposite_point_values: &[ProofBaseFieldElement],
    ) -> Result<(), SetupPublicPolynomialError> {
        let end_leaf_index = first_leaf_index
            .checked_add(first_point_values.len())
            .ok_or(SetupPublicPolynomialError::CountOverflow)?;
        if self.absorbed_column_count >= self.expected_column_count
            || first_point_values.is_empty()
            || first_point_values.len() != opposite_point_values.len()
            || first_leaf_index != self.next_leaf_index
            || end_leaf_index > self.leaf_count
        {
            return Err(SetupPublicPolynomialError::InvalidInput);
        }
        let leaf_hash_states = self
            .leaf_hash_states
            .get_mut(first_leaf_index..end_leaf_index)
            .ok_or(SetupPublicPolynomialError::InvalidInput)?;
        for ((leaf_hash_state, first_point_value), opposite_point_value) in leaf_hash_states
            .iter_mut()
            .zip(first_point_values)
            .zip(opposite_point_values)
        {
            let mut interleaved_values =
                [0_u8; SETUP_PUBLIC_POLYNOMIAL_INTERLEAVED_VALUE_BYTE_LENGTH_PER_COLUMN];
            interleaved_values[..SETUP_PUBLIC_POLYNOMIAL_FIELD_ELEMENT_BYTE_LENGTH]
                .copy_from_slice(&first_point_value.canonical().to_le_bytes());
            interleaved_values[SETUP_PUBLIC_POLYNOMIAL_FIELD_ELEMENT_BYTE_LENGTH..]
                .copy_from_slice(&opposite_point_value.canonical().to_le_bytes());
            leaf_hash_state.update(&interleaved_values);
        }
        self.next_leaf_index = end_leaf_index;
        if self.next_leaf_index == self.leaf_count {
            self.next_leaf_index = 0;
            self.absorbed_column_count += 1;
        }
        Ok(())
    }

    #[cfg(test)]
    fn finish_root(self) -> Result<[u8; 64], SetupPublicPolynomialError> {
        if self.absorbed_column_count != self.expected_column_count
            || self.next_leaf_index != 0
            || self.first_leaf_index != 0
            || self.leaf_index_stride != 1
        {
            return Err(SetupPublicPolynomialError::InvalidInput);
        }
        let mut root_accumulator = SetupPublicPolynomialOnlineMerkleRoot::new(
            self.public_polynomial_context_hash,
            self.leaf_count,
            self.leaf_hash_states.len(),
        )?;
        for leaf_hash_state in self.leaf_hash_states {
            let mut leaf_digest = [0_u8; AUTHENTICATION_DIGEST_BYTE_LENGTH];
            leaf_hash_state.finalize(&mut leaf_digest);
            root_accumulator.absorb_node(leaf_digest)?;
        }
        root_accumulator.finish()
    }

    fn finish_leaf_hashes(
        self,
        mut absorb: impl FnMut(
            usize,
            [u8; AUTHENTICATION_DIGEST_BYTE_LENGTH],
        ) -> Result<(), SetupPublicPolynomialError>,
    ) -> Result<(), SetupPublicPolynomialError> {
        if self.absorbed_column_count != self.expected_column_count || self.next_leaf_index != 0 {
            return Err(SetupPublicPolynomialError::InvalidInput);
        }
        for (local_leaf_index, leaf_hash_state) in self.leaf_hash_states.into_iter().enumerate() {
            let mut leaf_digest = [0_u8; AUTHENTICATION_DIGEST_BYTE_LENGTH];
            leaf_hash_state.finalize(&mut leaf_digest);
            absorb(local_leaf_index, leaf_digest)?;
        }
        Ok(())
    }

    #[cfg(test)]
    fn finish_leaf_digests_for_test(
        self,
    ) -> Result<Vec<[u8; AUTHENTICATION_DIGEST_BYTE_LENGTH]>, SetupPublicPolynomialError> {
        if self.absorbed_column_count != self.expected_column_count {
            return Err(SetupPublicPolynomialError::InvalidInput);
        }
        let mut leaf_digests = Vec::new();
        leaf_digests
            .try_reserve_exact(self.leaf_count)
            .map_err(|_| SetupPublicPolynomialError::AllocationLimitExceeded)?;
        for leaf_hash_state in self.leaf_hash_states {
            let mut leaf_digest = [0_u8; AUTHENTICATION_DIGEST_BYTE_LENGTH];
            leaf_hash_state.finalize(&mut leaf_digest);
            leaf_digests.push(leaf_digest);
        }
        Ok(leaf_digests)
    }
}

fn setup_public_polynomial_common_leaf_hash_state(
    public_polynomial_context_hash: [u8; 64],
    row_width: u32,
) -> Result<Shake, SetupPublicPolynomialError> {
    let leaf_byte_length = setup_public_polynomial_leaf_byte_length(row_width)?;
    let leaf_byte_length =
        u32::try_from(leaf_byte_length).map_err(|_| SetupPublicPolynomialError::CountOverflow)?;
    let domain_bytes = SETUP_PUBLIC_POLYNOMIAL_LEAF_HASH_DOMAIN.as_bytes();
    let domain_byte_length =
        u32::try_from(domain_bytes.len()).map_err(|_| SetupPublicPolynomialError::CountOverflow)?;
    let domain_item_byte_length = domain_byte_length
        .checked_add(4)
        .ok_or(SetupPublicPolynomialError::CountOverflow)?;
    let leaf_item_byte_length = leaf_byte_length
        .checked_add(4)
        .ok_or(SetupPublicPolynomialError::CountOverflow)?;
    let mut prefix = Vec::with_capacity(163);
    prefix.extend_from_slice(&FOUNDATION_TUPLE_SCHEMA_IDENTIFIER.to_le_bytes());
    prefix.extend_from_slice(&FOUNDATION_TUPLE_SCHEMA_VERSION.to_le_bytes());
    prefix.extend_from_slice(&2_u32.to_le_bytes());
    prefix.extend_from_slice(&CanonicalItemType::Ascii.canonical_code().to_le_bytes());
    prefix.extend_from_slice(&domain_item_byte_length.to_le_bytes());
    prefix.extend_from_slice(&domain_byte_length.to_le_bytes());
    prefix.extend_from_slice(domain_bytes);
    prefix.extend_from_slice(&CanonicalItemType::RawBytes.canonical_code().to_le_bytes());
    prefix.extend_from_slice(&leaf_item_byte_length.to_le_bytes());
    prefix.extend_from_slice(&leaf_byte_length.to_le_bytes());
    prefix.extend_from_slice(
        &SETUP_PUBLIC_POLYNOMIAL_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER.to_le_bytes(),
    );
    prefix.extend_from_slice(&SETUP_PUBLIC_POLYNOMIAL_LEAF_SCHEMA_VERSION.to_le_bytes());
    prefix.extend_from_slice(&3_u32.to_le_bytes());
    prefix.extend_from_slice(&CanonicalItemType::Hash512.canonical_code().to_le_bytes());
    prefix.extend_from_slice(&64_u32.to_le_bytes());
    prefix.extend_from_slice(&public_polynomial_context_hash);
    debug_assert_eq!(prefix.len(), 163);
    let mut state = Shake::v256();
    state.update(&prefix);
    Ok(state)
}

fn setup_public_polynomial_leaf_index_and_list_header(
    leaf_index: u64,
    row_width: u32,
) -> Result<[u8; 26], SetupPublicPolynomialError> {
    let interleaved_value_count = row_width
        .checked_mul(2)
        .ok_or(SetupPublicPolynomialError::CountOverflow)?;
    let list_value_byte_length = row_width
        .checked_mul(
            u32::try_from(SETUP_PUBLIC_POLYNOMIAL_INTERLEAVED_VALUE_BYTE_LENGTH_PER_COLUMN)
                .map_err(|_| SetupPublicPolynomialError::CountOverflow)?,
        )
        .ok_or(SetupPublicPolynomialError::CountOverflow)?;
    let list_item_byte_length = list_value_byte_length
        .checked_add(6)
        .ok_or(SetupPublicPolynomialError::CountOverflow)?;
    let mut header = [0_u8; 26];
    header[0..2].copy_from_slice(&CanonicalItemType::Unsigned64.canonical_code().to_le_bytes());
    header[2..6].copy_from_slice(&8_u32.to_le_bytes());
    header[6..14].copy_from_slice(&leaf_index.to_le_bytes());
    header[14..16].copy_from_slice(
        &CanonicalItemType::HomogeneousList
            .canonical_code()
            .to_le_bytes(),
    );
    header[16..20].copy_from_slice(&list_item_byte_length.to_le_bytes());
    header[20..22].copy_from_slice(
        &CanonicalItemType::FieldElement
            .canonical_code()
            .to_le_bytes(),
    );
    header[22..26].copy_from_slice(&interleaved_value_count.to_le_bytes());
    Ok(header)
}

struct SetupPublicPolynomialCosetMerkleFrontiers {
    public_polynomial_context_hash: [u8; 64],
    coset_count: usize,
    coset_leaf_count: usize,
    subtree_height: usize,
    pending_left_digests: Vec<[u8; AUTHENTICATION_DIGEST_BYTE_LENGTH]>,
    absorbed_coset_count: usize,
    upper_root: SetupPublicPolynomialOnlineMerkleRoot,
}

impl SetupPublicPolynomialCosetMerkleFrontiers {
    fn new(
        public_polynomial_context_hash: [u8; 64],
        coset_count: usize,
        coset_leaf_count: usize,
    ) -> Result<Self, SetupPublicPolynomialError> {
        if coset_count == 0
            || !coset_count.is_power_of_two()
            || coset_leaf_count == 0
            || !coset_leaf_count.is_power_of_two()
        {
            return Err(SetupPublicPolynomialError::InvalidInput);
        }
        let subtree_height = usize::try_from(coset_count.trailing_zeros())
            .map_err(|_| SetupPublicPolynomialError::CountOverflow)?;
        let pending_digest_count = coset_leaf_count
            .checked_mul(subtree_height)
            .ok_or(SetupPublicPolynomialError::CountOverflow)?;
        let mut pending_left_digests = Vec::new();
        pending_left_digests
            .try_reserve_exact(pending_digest_count)
            .map_err(|_| SetupPublicPolynomialError::AllocationLimitExceeded)?;
        pending_left_digests.resize(
            pending_digest_count,
            [0_u8; AUTHENTICATION_DIGEST_BYTE_LENGTH],
        );
        Ok(Self {
            public_polynomial_context_hash,
            coset_count,
            coset_leaf_count,
            subtree_height,
            pending_left_digests,
            absorbed_coset_count: 0,
            upper_root: SetupPublicPolynomialOnlineMerkleRoot::new_at_level(
                public_polynomial_context_hash,
                u32::try_from(subtree_height)
                    .map_err(|_| SetupPublicPolynomialError::CountOverflow)?,
                coset_leaf_count,
            )?,
        })
    }

    fn absorb_coset_leaf_hashes(
        &mut self,
        leaf_hash_arena: SetupPublicPolynomialLeafHashArena,
    ) -> Result<(), SetupPublicPolynomialError> {
        if self.absorbed_coset_count >= self.coset_count
            || leaf_hash_arena.public_polynomial_context_hash != self.public_polynomial_context_hash
            || leaf_hash_arena.leaf_count != self.coset_leaf_count
            || leaf_hash_arena.first_leaf_index != self.absorbed_coset_count
            || leaf_hash_arena.leaf_index_stride != self.coset_count
        {
            return Err(SetupPublicPolynomialError::InvalidInput);
        }
        let coset_index = self.absorbed_coset_count;
        leaf_hash_arena.finish_leaf_hashes(|local_leaf_index, mut current_digest| {
            let mut current_node_index = local_leaf_index
                .checked_mul(self.coset_count)
                .and_then(|block_start| block_start.checked_add(coset_index))
                .and_then(|leaf_index| u64::try_from(leaf_index).ok())
                .ok_or(SetupPublicPolynomialError::CountOverflow)?;
            let mut level = 0_usize;
            while level < self.subtree_height && (coset_index >> level) & 1 == 1 {
                let pending_index = local_leaf_index
                    .checked_mul(self.subtree_height)
                    .and_then(|block_start| block_start.checked_add(level))
                    .ok_or(SetupPublicPolynomialError::CountOverflow)?;
                let left_digest = *self
                    .pending_left_digests
                    .get(pending_index)
                    .ok_or(SetupPublicPolynomialError::InvalidInput)?;
                current_digest = setup_public_polynomial_merkle_node_digest(
                    self.public_polynomial_context_hash,
                    u32::try_from(level + 1)
                        .map_err(|_| SetupPublicPolynomialError::CountOverflow)?,
                    current_node_index / 2,
                    left_digest,
                    current_digest,
                )?;
                current_node_index /= 2;
                level += 1;
            }
            if level == self.subtree_height {
                if coset_index + 1 != self.coset_count {
                    return Err(SetupPublicPolynomialError::InvalidInput);
                }
                self.upper_root.absorb_node(current_digest)
            } else {
                let pending_index = local_leaf_index
                    .checked_mul(self.subtree_height)
                    .and_then(|block_start| block_start.checked_add(level))
                    .ok_or(SetupPublicPolynomialError::CountOverflow)?;
                *self
                    .pending_left_digests
                    .get_mut(pending_index)
                    .ok_or(SetupPublicPolynomialError::InvalidInput)? = current_digest;
                Ok(())
            }
        })?;
        self.absorbed_coset_count += 1;
        Ok(())
    }

    fn finish(self) -> Result<[u8; 64], SetupPublicPolynomialError> {
        if self.absorbed_coset_count != self.coset_count {
            return Err(SetupPublicPolynomialError::InvalidInput);
        }
        self.upper_root.finish()
    }
}

struct SetupPublicPolynomialOnlineMerkleRoot {
    public_polynomial_context_hash: [u8; 64],
    base_level: u32,
    pending_left_digests: Vec<[u8; AUTHENTICATION_DIGEST_BYTE_LENGTH]>,
    occupied_level_mask: u64,
    absorbed_leaf_count: u64,
    expected_leaf_count: u64,
    root: Option<[u8; AUTHENTICATION_DIGEST_BYTE_LENGTH]>,
}

impl SetupPublicPolynomialOnlineMerkleRoot {
    #[cfg(test)]
    fn new(
        public_polynomial_context_hash: [u8; 64],
        leaf_count: usize,
        supplied_leaf_count: usize,
    ) -> Result<Self, SetupPublicPolynomialError> {
        if leaf_count == 0
            || !leaf_count.is_power_of_two()
            || supplied_leaf_count != leaf_count
            || leaf_count.trailing_zeros() >= u64::BITS
        {
            return Err(SetupPublicPolynomialError::InvalidInput);
        }
        Self::new_at_level(public_polynomial_context_hash, 0, leaf_count)
    }

    fn new_at_level(
        public_polynomial_context_hash: [u8; 64],
        base_level: u32,
        node_count: usize,
    ) -> Result<Self, SetupPublicPolynomialError> {
        if node_count == 0
            || !node_count.is_power_of_two()
            || node_count.trailing_zeros() >= u64::BITS
            || base_level
                .checked_add(node_count.trailing_zeros())
                .is_none()
        {
            return Err(SetupPublicPolynomialError::InvalidInput);
        }
        let tree_height = usize::try_from(node_count.trailing_zeros())
            .map_err(|_| SetupPublicPolynomialError::CountOverflow)?;
        let mut pending_left_digests = Vec::new();
        pending_left_digests
            .try_reserve_exact(tree_height)
            .map_err(|_| SetupPublicPolynomialError::AllocationLimitExceeded)?;
        pending_left_digests.resize(tree_height, [0_u8; AUTHENTICATION_DIGEST_BYTE_LENGTH]);
        Ok(Self {
            public_polynomial_context_hash,
            base_level,
            pending_left_digests,
            occupied_level_mask: 0,
            absorbed_leaf_count: 0,
            expected_leaf_count: u64::try_from(node_count)
                .map_err(|_| SetupPublicPolynomialError::CountOverflow)?,
            root: None,
        })
    }

    fn absorb_node(
        &mut self,
        node_digest: [u8; AUTHENTICATION_DIGEST_BYTE_LENGTH],
    ) -> Result<(), SetupPublicPolynomialError> {
        if self.absorbed_leaf_count >= self.expected_leaf_count || self.root.is_some() {
            return Err(SetupPublicPolynomialError::InvalidInput);
        }
        let mut current_digest = node_digest;
        let mut current_node_index = self.absorbed_leaf_count;
        let mut level = 0_usize;
        while level < self.pending_left_digests.len()
            && self.occupied_level_mask & (1_u64 << level) != 0
        {
            current_digest = setup_public_polynomial_merkle_node_digest(
                self.public_polynomial_context_hash,
                self.base_level
                    .checked_add(
                        u32::try_from(level + 1)
                            .map_err(|_| SetupPublicPolynomialError::CountOverflow)?,
                    )
                    .ok_or(SetupPublicPolynomialError::CountOverflow)?,
                current_node_index / 2,
                self.pending_left_digests[level],
                current_digest,
            )?;
            self.occupied_level_mask &= !(1_u64 << level);
            current_node_index /= 2;
            level += 1;
        }
        self.absorbed_leaf_count += 1;
        if level == self.pending_left_digests.len() {
            if self.absorbed_leaf_count != self.expected_leaf_count || self.occupied_level_mask != 0
            {
                return Err(SetupPublicPolynomialError::InvalidInput);
            }
            self.root = Some(current_digest);
        } else {
            self.pending_left_digests[level] = current_digest;
            self.occupied_level_mask |= 1_u64 << level;
        }
        Ok(())
    }

    fn finish(self) -> Result<[u8; 64], SetupPublicPolynomialError> {
        if self.absorbed_leaf_count != self.expected_leaf_count || self.occupied_level_mask != 0 {
            return Err(SetupPublicPolynomialError::InvalidInput);
        }
        self.root.ok_or(SetupPublicPolynomialError::InvalidInput)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SetupPublicPolynomialCompactRootMemoryPlan {
    #[cfg(test)]
    retained_source_coefficients_payload_byte_length: u64,
    #[cfg(test)]
    coset_evaluation_workspace_payload_byte_length: u64,
    #[cfg(test)]
    coset_leaf_hash_state_payload_byte_length: u64,
    #[cfg(test)]
    coordinate_frontier_payload_byte_length: u64,
    #[cfg(test)]
    upper_merkle_stack_payload_byte_length: u64,
    #[cfg(test)]
    generation_payload_peak_byte_length: u64,
    owned_payload_peak_byte_length: u64,
}

pub(crate) const WASM_SETUP_PUBLIC_POLYNOMIAL_LEAF_HASH_STATE_BYTE_LENGTH: usize = 216;

impl SetupPublicPolynomialCompactRootMemoryPlan {
    #[cfg(test)]
    pub(crate) const fn retained_source_coefficients_payload_byte_length(self) -> u64 {
        self.retained_source_coefficients_payload_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn coset_evaluation_workspace_payload_byte_length(self) -> u64 {
        self.coset_evaluation_workspace_payload_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn coset_leaf_hash_state_payload_byte_length(self) -> u64 {
        self.coset_leaf_hash_state_payload_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn coordinate_frontier_payload_byte_length(self) -> u64 {
        self.coordinate_frontier_payload_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn upper_merkle_stack_payload_byte_length(self) -> u64 {
        self.upper_merkle_stack_payload_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn generation_payload_peak_byte_length(self) -> u64 {
        self.generation_payload_peak_byte_length
    }

    pub(crate) const fn owned_payload_peak_byte_length(self) -> u64 {
        self.owned_payload_peak_byte_length
    }
}

#[cfg(test)]
pub(crate) fn setup_public_polynomial_compact_root_memory_plan(
    evaluation_domain_size: usize,
    source_polynomial_degree_bound_exclusive: usize,
    row_width: u32,
) -> Result<SetupPublicPolynomialCompactRootMemoryPlan, SetupPublicPolynomialError> {
    setup_public_polynomial_compact_root_memory_plan_for_leaf_hash_state_byte_length(
        evaluation_domain_size,
        source_polynomial_degree_bound_exclusive,
        row_width,
        std::mem::size_of::<Shake>(),
    )
}

/// Exact Wasm32 payload accounting for the tiny-keccak SHAKE states retained
/// for one low-degree coset at a time. Native layout is kept separate because
/// desktop `usize` alignment makes the same state larger.
pub(crate) fn setup_public_polynomial_wasm_compact_root_memory_plan(
    evaluation_domain_size: usize,
    source_polynomial_degree_bound_exclusive: usize,
    row_width: u32,
) -> Result<SetupPublicPolynomialCompactRootMemoryPlan, SetupPublicPolynomialError> {
    setup_public_polynomial_compact_root_memory_plan_for_leaf_hash_state_byte_length(
        evaluation_domain_size,
        source_polynomial_degree_bound_exclusive,
        row_width,
        WASM_SETUP_PUBLIC_POLYNOMIAL_LEAF_HASH_STATE_BYTE_LENGTH,
    )
}

fn setup_public_polynomial_compact_root_memory_plan_for_leaf_hash_state_byte_length(
    evaluation_domain_size: usize,
    source_polynomial_degree_bound_exclusive: usize,
    row_width: u32,
    leaf_hash_state_byte_length: usize,
) -> Result<SetupPublicPolynomialCompactRootMemoryPlan, SetupPublicPolynomialError> {
    if evaluation_domain_size < 2
        || !evaluation_domain_size.is_power_of_two()
        || source_polynomial_degree_bound_exclusive == 0
        || source_polynomial_degree_bound_exclusive > evaluation_domain_size
        || !source_polynomial_degree_bound_exclusive.is_power_of_two()
        || row_width == 0
        || leaf_hash_state_byte_length == 0
    {
        return Err(SetupPublicPolynomialError::InvalidInput);
    }
    let checked_multiply = |left: usize, right: usize| {
        u64::try_from(left)
            .ok()
            .and_then(|left| {
                u64::try_from(right)
                    .ok()
                    .and_then(|right| left.checked_mul(right))
            })
            .ok_or(SetupPublicPolynomialError::CountOverflow)
    };
    let checked_add = |left: u64, right: u64| {
        left.checked_add(right)
            .ok_or(SetupPublicPolynomialError::CountOverflow)
    };
    let coset_count = evaluation_domain_size
        .checked_div(source_polynomial_degree_bound_exclusive)
        .ok_or(SetupPublicPolynomialError::CountOverflow)?;
    let coset_leaf_count = source_polynomial_degree_bound_exclusive / 2;
    if coset_count == 0 || !coset_count.is_power_of_two() || coset_leaf_count == 0 {
        return Err(SetupPublicPolynomialError::InvalidInput);
    }
    let field_element_byte_length = std::mem::size_of::<ProofBaseFieldElement>();
    let field_element_byte_length_u64 = u64::try_from(field_element_byte_length)
        .map_err(|_| SetupPublicPolynomialError::CountOverflow)?;
    let retained_source_coefficients_payload_byte_length = checked_multiply(
        usize::try_from(row_width).map_err(|_| SetupPublicPolynomialError::CountOverflow)?,
        source_polynomial_degree_bound_exclusive,
    )
    .and_then(|element_count| {
        element_count
            .checked_mul(field_element_byte_length_u64)
            .ok_or(SetupPublicPolynomialError::CountOverflow)
    })?;
    let coset_evaluation_workspace_payload_byte_length = checked_multiply(
        source_polynomial_degree_bound_exclusive,
        field_element_byte_length,
    )?;
    let coset_leaf_hash_state_payload_byte_length =
        checked_multiply(coset_leaf_count, leaf_hash_state_byte_length)?;
    let coordinate_frontier_payload_byte_length = checked_multiply(
        coset_leaf_count,
        usize::try_from(coset_count.trailing_zeros())
            .map_err(|_| SetupPublicPolynomialError::CountOverflow)?,
    )
    .and_then(|digest_count| {
        digest_count
            .checked_mul(AUTHENTICATION_DIGEST_BYTE_LENGTH as u64)
            .ok_or(SetupPublicPolynomialError::CountOverflow)
    })?;
    let upper_merkle_stack_payload_byte_length = checked_multiply(
        usize::try_from(coset_leaf_count.trailing_zeros())
            .map_err(|_| SetupPublicPolynomialError::CountOverflow)?,
        AUTHENTICATION_DIGEST_BYTE_LENGTH,
    )?;
    let generation_payload_peak_byte_length = [
        retained_source_coefficients_payload_byte_length,
        coset_evaluation_workspace_payload_byte_length,
        coset_leaf_hash_state_payload_byte_length,
        coordinate_frontier_payload_byte_length,
        upper_merkle_stack_payload_byte_length,
    ]
    .into_iter()
    .try_fold(0_u64, checked_add)?;
    Ok(SetupPublicPolynomialCompactRootMemoryPlan {
        #[cfg(test)]
        retained_source_coefficients_payload_byte_length,
        #[cfg(test)]
        coset_evaluation_workspace_payload_byte_length,
        #[cfg(test)]
        coset_leaf_hash_state_payload_byte_length,
        #[cfg(test)]
        coordinate_frontier_payload_byte_length,
        #[cfg(test)]
        upper_merkle_stack_payload_byte_length,
        #[cfg(test)]
        generation_payload_peak_byte_length,
        owned_payload_peak_byte_length: generation_payload_peak_byte_length,
    })
}

#[cfg(test)]
fn materialized_merkle_root_for_test(
    public_polynomial_context_hash: [u8; 64],
    mut current_level: Vec<[u8; AUTHENTICATION_DIGEST_BYTE_LENGTH]>,
) -> Result<[u8; AUTHENTICATION_DIGEST_BYTE_LENGTH], SetupPublicPolynomialError> {
    if current_level.is_empty() || !current_level.len().is_power_of_two() {
        return Err(SetupPublicPolynomialError::InvalidInput);
    }
    let mut level = 1_u32;
    while current_level.len() > 1 {
        let mut parent_level = Vec::with_capacity(current_level.len() / 2);
        for (parent_index, children) in current_level.chunks_exact(2).enumerate() {
            parent_level.push(setup_public_polynomial_merkle_node_digest(
                public_polynomial_context_hash,
                level,
                u64::try_from(parent_index)
                    .map_err(|_| SetupPublicPolynomialError::CountOverflow)?,
                children[0],
                children[1],
            )?);
        }
        current_level = parent_level;
        level = level
            .checked_add(1)
            .ok_or(SetupPublicPolynomialError::CountOverflow)?;
    }
    current_level
        .pop()
        .ok_or(SetupPublicPolynomialError::InvalidInput)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::{
        parameters::POLYNOMIAL_DEGREE,
        proof_suite::{
            MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH, PROOF_BASE_FIELD_MODULUS,
            selected_relinearization_relation_plan_inputs,
        },
        setup::{
            LatticeAnchorCommitment, SETUP_COMMITMENT_MODULE_RANK,
            lattice_anchor_commitment_canonical_bytes,
        },
    };

    fn lattice_anchor_context() -> SetupPublicPolynomialContext {
        SetupPublicPolynomialContext::lattice_anchor([0x31; 64], [0x71; 64], 2, 1)
            .expect("the selected role-one context is canonical")
    }

    fn public_key_share_context() -> SetupPublicPolynomialContext {
        SetupPublicPolynomialContext::public_key_share([0x31; 64], [0x71; 64], 2)
            .expect("the public-key-share context is canonical")
    }

    fn construct_test_tree(
        second_row_constant: u64,
    ) -> Result<SetupPublicPolynomialTree, SetupPublicPolynomialError> {
        let context = public_key_share_context();
        let ordered_trace_rows = vec![
            vec![
                ProofBaseFieldElement::from_canonical(3)?,
                ProofBaseFieldElement::from_canonical(5)?,
                ProofBaseFieldElement::from_canonical(0)?,
                ProofBaseFieldElement::from_canonical(1)?,
            ],
            vec![
                ProofBaseFieldElement::from_canonical(second_row_constant)?,
                ProofBaseFieldElement::ZERO,
                ProofBaseFieldElement::ZERO,
                ProofBaseFieldElement::ZERO,
            ],
        ];
        SetupPublicPolynomialTree::construct(SetupPublicPolynomialTreeInput {
            context: &context,
            evaluation_domain_size: 8,
            source_polynomial_degree_bound_exclusive: 4,
            ordered_trace_rows: &ordered_trace_rows,
        })
    }

    fn extension_columns_for_test(
        ordered_trace_rows: &[Vec<ProofBaseFieldElement>],
        source_polynomial_degree_bound_exclusive: usize,
        evaluation_domain_size: usize,
    ) -> Result<Vec<Vec<ProofBaseFieldElement>>, SetupPublicPolynomialError> {
        let trace_domain =
            ProofEvaluationDomain::new_subgroup(source_polynomial_degree_bound_exclusive)?;
        let evaluation_domain =
            ProofEvaluationDomain::new(evaluation_domain_size, PROOF_EVALUATION_COSET_OFFSET)?;
        ordered_trace_rows
            .iter()
            .map(|trace_row| {
                let mut extension_column = trace_row.clone();
                trace_domain.interpolate_base_polynomial_in_place(&mut extension_column)?;
                evaluation_domain.evaluate_base_polynomial_in_place(&mut extension_column)?;
                Ok(extension_column)
            })
            .collect()
    }

    fn canonical_leaf_bytes_for_tree(
        tree: &SetupPublicPolynomialTree,
        leaf_index: usize,
    ) -> Result<Vec<u8>, SetupPublicPolynomialError> {
        let extension_columns = extension_columns_for_test(
            tree.ordered_trace_rows(),
            tree.source_polynomial_degree_bound_exclusive(),
            tree.evaluation_domain_size(),
        )?;
        let opposite_index = leaf_index
            .checked_add(tree.leaf_count())
            .ok_or(SetupPublicPolynomialError::CountOverflow)?;
        let first_point_values = extension_columns
            .iter()
            .map(|column| column[leaf_index])
            .collect::<Vec<_>>();
        let opposite_point_values = extension_columns
            .iter()
            .map(|column| column[opposite_index])
            .collect::<Vec<_>>();
        canonical_setup_public_polynomial_phase_pair_leaf_bytes(
            tree.public_polynomial_context_hash(),
            u64::try_from(leaf_index).map_err(|_| SetupPublicPolynomialError::CountOverflow)?,
            &first_point_values,
            &opposite_point_values,
        )
    }

    fn synthetic_extension_columns(
        row_width: usize,
        evaluation_domain_size: usize,
    ) -> Vec<Vec<ProofBaseFieldElement>> {
        (0..row_width)
            .map(|column_index| {
                (0..evaluation_domain_size)
                    .map(|evaluation_index| {
                        let value = (column_index as u64)
                            .checked_mul(257)
                            .and_then(|value| value.checked_add(evaluation_index as u64 * 17))
                            .expect("the synthetic field value fits u64")
                            % PROOF_BASE_FIELD_MODULUS;
                        ProofBaseFieldElement::from_canonical(value)
                            .expect("the synthetic field value is canonical")
                    })
                    .collect()
            })
            .collect()
    }

    fn streamed_leaf_digests_for_test(
        context_hash: [u8; 64],
        extension_columns: &[Vec<ProofBaseFieldElement>],
    ) -> Vec<[u8; 64]> {
        let evaluation_domain_size = extension_columns[0].len();
        let mut arena = SetupPublicPolynomialLeafHashArena::new(
            context_hash,
            evaluation_domain_size / 2,
            u32::try_from(extension_columns.len()).expect("the test width fits u32"),
        )
        .expect("the leaf state arena initializes");
        for extension_column in extension_columns {
            arena
                .absorb_extension_column(extension_column)
                .expect("the column is canonical");
        }
        arena
            .finish_leaf_digests_for_test()
            .expect("all expected columns were absorbed")
    }

    fn one_shot_leaf_digests_for_test(
        context_hash: [u8; 64],
        extension_columns: &[Vec<ProofBaseFieldElement>],
    ) -> Vec<[u8; 64]> {
        let leaf_count = extension_columns[0].len() / 2;
        (0..leaf_count)
            .map(|leaf_index| {
                let first_point_values = extension_columns
                    .iter()
                    .map(|column| column[leaf_index])
                    .collect::<Vec<_>>();
                let opposite_point_values = extension_columns
                    .iter()
                    .map(|column| column[leaf_count + leaf_index])
                    .collect::<Vec<_>>();
                let canonical_bytes = canonical_setup_public_polynomial_phase_pair_leaf_bytes(
                    context_hash,
                    u64::try_from(leaf_index).expect("the test leaf index fits u64"),
                    &first_point_values,
                    &opposite_point_values,
                )
                .expect("the test leaf is canonical");
                setup_public_polynomial_leaf_digest(&canonical_bytes)
                    .expect("the canonical leaf hashes")
            })
            .collect()
    }

    #[test]
    fn lattice_anchor_context_requires_one_selected_commitment_prime() {
        assert_eq!(
            SetupPublicPolynomialContext::lattice_anchor([0x31; 64], [0x71; 64], 2, 3),
            Err(SetupPublicPolynomialError::InvalidContext),
        );
        assert_eq!(
            SetupPublicPolynomialContext::new(
                [0x31; 64],
                SetupPublicPolynomialRootRole::LatticeAnchor,
                Some([0x71; 64]),
                None,
                None,
                Some(1),
            ),
            Err(SetupPublicPolynomialError::InvalidContext),
        );
    }

    #[test]
    fn coefficient_mutation_changes_the_recomputed_public_polynomial_root() {
        let original = construct_test_tree(7).expect("the original tree is canonical");
        let changed = construct_test_tree(8).expect("the changed tree is canonical");

        assert_eq!(original.row_width(), 2);
        assert_eq!(original.leaf_count(), 4);
        assert_ne!(original.root(), changed.root());
        assert_ne!(
            canonical_leaf_bytes_for_tree(&original, 0).expect("the leaf encodes"),
            canonical_leaf_bytes_for_tree(&changed, 0).expect("the leaf encodes"),
        );
    }

    #[test]
    fn root_only_canonical_rows_match_the_retained_tree_and_require_the_exact_width() {
        let canonical_rows = [[3, 5, 0, 1], [7, 0, 0, 0]];
        let field_rows = canonical_rows
            .iter()
            .map(|row| {
                row.iter()
                    .map(|value| ProofBaseFieldElement::from_canonical(*value))
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()
            .expect("the test rows are canonical");
        let contexts = [
            public_key_share_context(),
            SetupPublicPolynomialContext::galois_common([0x91; 64], 3)
                .expect("the Galois-common context is canonical"),
        ];
        for context in &contexts {
            let retained_tree =
                SetupPublicPolynomialTree::construct(SetupPublicPolynomialTreeInput {
                    context,
                    evaluation_domain_size: 8,
                    source_polynomial_degree_bound_exclusive: 4,
                    ordered_trace_rows: &field_rows,
                })
                .expect("the retained tree is canonical");
            let (context_hash, root) =
                SetupPublicPolynomialTree::construct_root_from_canonical_trace_rows(
                    context,
                    8,
                    4,
                    canonical_rows.len(),
                    canonical_rows.iter().map(|row| row.as_slice()),
                )
                .expect("the root-only construction is canonical");
            assert_eq!(context_hash, retained_tree.public_polynomial_context_hash());
            assert_eq!(root, retained_tree.root());
        }

        assert_eq!(
            SetupPublicPolynomialTree::construct_root_from_canonical_trace_rows(
                &contexts[0],
                8,
                4,
                canonical_rows.len(),
                canonical_rows.iter().take(1).map(|row| row.as_slice()),
            ),
            Err(SetupPublicPolynomialError::InvalidInput),
        );
        assert_eq!(
            SetupPublicPolynomialTree::construct_root_from_canonical_trace_rows(
                &contexts[0],
                8,
                4,
                canonical_rows.len(),
                [
                    canonical_rows[0][..3].as_ref(),
                    canonical_rows[1].as_slice()
                ],
            ),
            Err(SetupPublicPolynomialError::InvalidInput),
        );
    }

    #[test]
    fn coset_frontier_root_matches_full_domain_materialization() {
        let context = public_key_share_context();
        for (source_degree_bound, evaluation_domain_size) in [
            (2_usize, 2_usize),
            (2, 8),
            (4, 8),
            (4, 16),
            (8, 32),
            (8, 64),
        ] {
            for row_width in [1_usize, 3] {
                let ordered_trace_rows = (0..row_width)
                    .map(|column_index| {
                        (0..source_degree_bound)
                            .map(|trace_index| {
                                ProofBaseFieldElement::from_canonical(
                                    u64::try_from(
                                        1 + column_index * source_degree_bound + trace_index,
                                    )
                                    .expect("the test trace value fits u64"),
                                )
                                .expect("the test trace value is canonical")
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();
                let extension_columns = extension_columns_for_test(
                    &ordered_trace_rows,
                    source_degree_bound,
                    evaluation_domain_size,
                )
                .expect("the full-domain reference extends");
                let expected_root = materialized_merkle_root_for_test(
                    context.context_hash().expect("the context hashes"),
                    one_shot_leaf_digests_for_test(
                        context.context_hash().expect("the context hashes"),
                        &extension_columns,
                    ),
                )
                .expect("the full-domain reference root is canonical");
                let tree = SetupPublicPolynomialTree::construct(SetupPublicPolynomialTreeInput {
                    context: &context,
                    evaluation_domain_size,
                    source_polynomial_degree_bound_exclusive: source_degree_bound,
                    ordered_trace_rows: &ordered_trace_rows,
                })
                .expect("the coset-frontier tree is canonical");
                assert_eq!(tree.root(), expected_root);
            }
        }
    }

    #[test]
    fn interleaved_v3_leaf_encoding_has_exact_bytes_and_length() {
        for row_width in [1_usize, 2, 100] {
            let first_point_values = (0..row_width)
                .map(|column_index| {
                    ProofBaseFieldElement::from_canonical(column_index as u64 + 1)
                        .expect("the first value is canonical")
                })
                .collect::<Vec<_>>();
            let opposite_point_values = (0..row_width)
                .map(|column_index| {
                    ProofBaseFieldElement::from_canonical(
                        PROOF_BASE_FIELD_MODULUS - 1 - column_index as u64,
                    )
                    .expect("the opposite value is canonical")
                })
                .collect::<Vec<_>>();
            let leaf_index = 0x0102_0304_0506_0708_u64;
            let canonical_bytes = canonical_setup_public_polynomial_phase_pair_leaf_bytes(
                [0x41; 64],
                leaf_index,
                &first_point_values,
                &opposite_point_values,
            )
            .expect("the leaf is canonical");
            assert_eq!(
                canonical_bytes.len(),
                SETUP_PUBLIC_POLYNOMIAL_FIXED_LEAF_BYTE_LENGTH + row_width * 16,
            );
            assert_eq!(
                canonical_bytes.len(),
                setup_public_polynomial_leaf_byte_length(
                    u32::try_from(row_width).expect("the test width fits u32"),
                )
                .expect("the leaf length is defined"),
            );
            assert_eq!(&canonical_bytes[0..2], &0x121c_u16.to_le_bytes());
            assert_eq!(&canonical_bytes[2..4], &3_u16.to_le_bytes());
            assert_eq!(&canonical_bytes[4..8], &3_u32.to_le_bytes());
            assert_eq!(&canonical_bytes[8..10], &0x0006_u16.to_le_bytes());
            assert_eq!(&canonical_bytes[10..14], &64_u32.to_le_bytes());
            assert_eq!(&canonical_bytes[14..78], &[0x41; 64]);
            assert_eq!(&canonical_bytes[78..80], &0x0005_u16.to_le_bytes());
            assert_eq!(&canonical_bytes[80..84], &8_u32.to_le_bytes());
            assert_eq!(&canonical_bytes[84..92], &leaf_index.to_le_bytes());
            assert_eq!(&canonical_bytes[92..94], &0x000e_u16.to_le_bytes());
            assert_eq!(
                &canonical_bytes[94..98],
                &u32::try_from(6 + row_width * 16)
                    .expect("the list length fits u32")
                    .to_le_bytes(),
            );
            assert_eq!(&canonical_bytes[98..100], &0x0008_u16.to_le_bytes());
            assert_eq!(
                &canonical_bytes[100..104],
                &u32::try_from(row_width * 2)
                    .expect("the value count fits u32")
                    .to_le_bytes(),
            );
            for column_index in 0..row_width {
                let value_offset = 104 + column_index * 16;
                assert_eq!(
                    &canonical_bytes[value_offset..value_offset + 8],
                    &first_point_values[column_index].canonical().to_le_bytes(),
                );
                assert_eq!(
                    &canonical_bytes[value_offset + 8..value_offset + 16],
                    &opposite_point_values[column_index]
                        .canonical()
                        .to_le_bytes(),
                );
            }
            let expected_digest = hash_foundation_tuple_512(
                SETUP_PUBLIC_POLYNOMIAL_LEAF_HASH_DOMAIN,
                &[CanonicalItem::variable_bytes(&canonical_bytes)
                    .expect("the test leaf is bounded")],
            )
            .expect("the foundation hash input is canonical")
            .into_bytes();
            assert_eq!(
                setup_public_polynomial_leaf_digest(&canonical_bytes)
                    .expect("the streaming leaf digest derives"),
                expected_digest,
                "the bounded streaming digest must preserve the deployed foundation hash",
            );
        }
    }

    #[test]
    fn compact_tiny_keccak_leaf_states_match_one_shot_foundation_hashing() {
        for row_width in [1_usize, 2, 100] {
            let mut extension_columns = synthetic_extension_columns(row_width, 8);
            extension_columns[0][0] = ProofBaseFieldElement::ZERO;
            extension_columns[0][4] =
                ProofBaseFieldElement::from_canonical(PROOF_BASE_FIELD_MODULUS - 1)
                    .expect("the maximum field value is canonical");
            assert_eq!(
                streamed_leaf_digests_for_test([0x5a; 64], &extension_columns),
                one_shot_leaf_digests_for_test([0x5a; 64], &extension_columns),
            );
        }
    }

    #[test]
    fn streaming_merkle_node_digest_matches_foundation_hashing() {
        for (level, parent_index) in [(1_u32, 0_u64), (u32::MAX, u64::MAX / 2)] {
            let context_hash = [0x23; 64];
            let left_child_digest = [0x45; 64];
            let right_child_digest = [0x67; 64];
            let left_child_index = parent_index
                .checked_mul(2)
                .expect("the selected parent index has two children");
            let expected = hash_foundation_tuple_512(
                SETUP_PUBLIC_POLYNOMIAL_NODE_HASH_DOMAIN,
                &[
                    CanonicalItem::hash512(context_hash),
                    CanonicalItem::unsigned32(level),
                    CanonicalItem::unsigned64(left_child_index),
                    CanonicalItem::hash512(left_child_digest),
                    CanonicalItem::hash512(right_child_digest),
                ],
            )
            .expect("the foundation node hash input is canonical")
            .into_bytes();
            assert_eq!(
                setup_public_polynomial_merkle_node_digest(
                    context_hash,
                    level,
                    parent_index,
                    left_child_digest,
                    right_child_digest,
                )
                .expect("the streaming node digest derives"),
                expected,
            );
        }
        assert_eq!(
            setup_public_polynomial_merkle_node_digest(
                [0x23; 64],
                1,
                u64::MAX,
                [0x45; 64],
                [0x67; 64],
            ),
            Err(SetupPublicPolynomialError::CountOverflow),
        );
    }

    #[test]
    fn online_merkle_root_matches_the_materialized_reference_tree() {
        for evaluation_domain_size in [2_usize, 4, 8, 16] {
            for row_width in [1_usize, 2, 5] {
                let extension_columns =
                    synthetic_extension_columns(row_width, evaluation_domain_size);
                let context_hash = [u8::try_from(evaluation_domain_size + row_width)
                    .expect("the test discriminator fits u8");
                    64];
                let one_shot_leaf_digests =
                    one_shot_leaf_digests_for_test(context_hash, &extension_columns);
                let expected_root =
                    materialized_merkle_root_for_test(context_hash, one_shot_leaf_digests)
                        .expect("the materialized reference root is canonical");
                let mut arena = SetupPublicPolynomialLeafHashArena::new(
                    context_hash,
                    evaluation_domain_size / 2,
                    u32::try_from(row_width).expect("the test width fits u32"),
                )
                .expect("the leaf state arena initializes");
                for extension_column in &extension_columns {
                    arena
                        .absorb_extension_column(extension_column)
                        .expect("the column is canonical");
                }
                assert_eq!(
                    arena.finish_root().expect("the online root completes"),
                    expected_root,
                );
            }
        }
    }

    #[test]
    fn coset_frontiers_refuse_changed_coordinate_schedules() {
        let context_hash = [0x36; 64];
        let mut frontiers = SetupPublicPolynomialCosetMerkleFrontiers::new(context_hash, 4, 2)
            .expect("the test frontiers initialize");
        let extension_column = synthetic_extension_columns(1, 4)
            .pop()
            .expect("the test column exists");
        let mut wrong_first_coset =
            SetupPublicPolynomialLeafHashArena::new_strided(context_hash, 2, 1, 1, 4)
                .expect("the changed schedule is representable");
        wrong_first_coset
            .absorb_extension_column(&extension_column)
            .expect("the changed-schedule arena is complete");
        assert_eq!(
            frontiers.absorb_coset_leaf_hashes(wrong_first_coset),
            Err(SetupPublicPolynomialError::InvalidInput),
        );

        let mut wrong_stride =
            SetupPublicPolynomialLeafHashArena::new_strided(context_hash, 2, 1, 0, 2)
                .expect("the changed stride is representable");
        wrong_stride
            .absorb_extension_column(&extension_column)
            .expect("the changed-stride arena is complete");
        assert_eq!(
            frontiers.absorb_coset_leaf_hashes(wrong_stride),
            Err(SetupPublicPolynomialError::InvalidInput),
        );

        let mut first_coset =
            SetupPublicPolynomialLeafHashArena::new_strided(context_hash, 2, 1, 0, 4)
                .expect("the first schedule is canonical");
        first_coset
            .absorb_extension_column(&extension_column)
            .expect("the first arena is complete");
        frontiers
            .absorb_coset_leaf_hashes(first_coset)
            .expect("the first coordinate schedule is accepted");

        let mut repeated_first_coset =
            SetupPublicPolynomialLeafHashArena::new_strided(context_hash, 2, 1, 0, 4)
                .expect("the repeated schedule is representable");
        repeated_first_coset
            .absorb_extension_column(&extension_column)
            .expect("the repeated-schedule arena is complete");
        assert_eq!(
            frontiers.absorb_coset_leaf_hashes(repeated_first_coset),
            Err(SetupPublicPolynomialError::InvalidInput),
        );
    }

    #[test]
    fn leaf_order_index_and_context_are_root_binding() {
        let extension_columns = synthetic_extension_columns(3, 8);
        let original_leaf_digests = one_shot_leaf_digests_for_test([0x11; 64], &extension_columns);
        let original_root =
            materialized_merkle_root_for_test([0x11; 64], original_leaf_digests.clone())
                .expect("the original root is canonical");

        let mut reordered_columns = extension_columns.clone();
        reordered_columns.swap(0, 2);
        let reordered_root = materialized_merkle_root_for_test(
            [0x11; 64],
            one_shot_leaf_digests_for_test([0x11; 64], &reordered_columns),
        )
        .expect("the reordered root is canonical");
        let changed_context_root = materialized_merkle_root_for_test(
            [0x12; 64],
            one_shot_leaf_digests_for_test([0x12; 64], &extension_columns),
        )
        .expect("the changed-context root is canonical");
        assert_ne!(original_root, reordered_root);
        assert_ne!(original_root, changed_context_root);

        let first_point_values = extension_columns
            .iter()
            .map(|column| column[0])
            .collect::<Vec<_>>();
        let opposite_point_values = extension_columns
            .iter()
            .map(|column| column[4])
            .collect::<Vec<_>>();
        let leaf_zero = canonical_setup_public_polynomial_phase_pair_leaf_bytes(
            [0x11; 64],
            0,
            &first_point_values,
            &opposite_point_values,
        )
        .expect("leaf zero is canonical");
        let leaf_one = canonical_setup_public_polynomial_phase_pair_leaf_bytes(
            [0x11; 64],
            1,
            &first_point_values,
            &opposite_point_values,
        )
        .expect("leaf one is canonical");
        assert_ne!(
            setup_public_polynomial_leaf_digest(&leaf_zero).expect("leaf zero hashes"),
            setup_public_polynomial_leaf_digest(&leaf_one).expect("leaf one hashes"),
        );
    }

    #[test]
    fn tiny_keccak_state_layout_and_coset_frontier_peak_accounting_are_exact() {
        assert_eq!(std::mem::size_of::<ProofBaseFieldElement>(), 8);
        #[cfg(target_arch = "wasm32")]
        assert_eq!(std::mem::size_of::<Shake>(), 216);
        #[cfg(all(not(target_arch = "wasm32"), target_pointer_width = "64"))]
        assert_eq!(std::mem::size_of::<Shake>(), 224);

        let (_, round_two_input) = selected_relinearization_relation_plan_inputs()
            .expect("the selected round-two relation input derives");
        let relation_geometry = round_two_input.geometry;
        let selected_root_row_width = relation_geometry
            .decomposition_blocks
            .len()
            .checked_mul(
                relation_geometry
                    .data_moduli
                    .len()
                    .checked_add(relation_geometry.special_moduli.len())
                    .expect("the selected extended-limb count fits usize"),
            )
            .and_then(|count| count.checked_mul(2))
            .and_then(|count| u32::try_from(count).ok())
            .expect("the selected root row width fits u32");
        assert_eq!(selected_root_row_width, 416);
        let evaluation_domain_size = usize::try_from(relation_geometry.evaluation_domain_size)
            .expect("the selected evaluation domain fits usize");
        assert_eq!(evaluation_domain_size, 16_777_216);
        let public_polynomial_degree_bound_exclusive =
            usize::try_from(relation_geometry.public_polynomial_column_degree_bound_exclusive)
                .expect("the selected public-polynomial degree bound fits usize");
        assert_eq!(public_polynomial_degree_bound_exclusive, 16_384);

        let wasm_plan = setup_public_polynomial_wasm_compact_root_memory_plan(
            evaluation_domain_size,
            public_polynomial_degree_bound_exclusive,
            selected_root_row_width,
        )
        .expect("the selected Wasm root plan is representable");
        assert_eq!(
            wasm_plan.retained_source_coefficients_payload_byte_length(),
            54_525_952,
        );
        assert_eq!(
            wasm_plan.coset_evaluation_workspace_payload_byte_length(),
            131_072,
        );
        assert_eq!(
            wasm_plan.coset_leaf_hash_state_payload_byte_length(),
            1_769_472,
        );
        assert_eq!(
            wasm_plan.coordinate_frontier_payload_byte_length(),
            5_242_880,
        );
        assert_eq!(wasm_plan.upper_merkle_stack_payload_byte_length(), 832,);
        assert_eq!(wasm_plan.generation_payload_peak_byte_length(), 61_670_208,);
        assert_eq!(wasm_plan.owned_payload_peak_byte_length(), 61_670_208);
        assert!(
            wasm_plan.owned_payload_peak_byte_length()
                <= MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH,
        );
        assert_eq!(
            MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
                - wasm_plan.owned_payload_peak_byte_length(),
            609_418_432,
        );

        let current_target_plan = setup_public_polynomial_compact_root_memory_plan(
            evaluation_domain_size,
            public_polynomial_degree_bound_exclusive,
            selected_root_row_width,
        )
        .expect("the current-target root plan is representable");
        assert_eq!(
            current_target_plan.coset_leaf_hash_state_payload_byte_length(),
            8_192 * std::mem::size_of::<Shake>() as u64,
        );
        assert_eq!(
            current_target_plan.owned_payload_peak_byte_length(),
            61_735_744,
        );
        assert!(matches!(
            SetupPublicPolynomialRootBuilder::new(
                &public_key_share_context(),
                evaluation_domain_size,
                public_polynomial_degree_bound_exclusive,
                u32::MAX,
            ),
            Err(SetupPublicPolynomialError::AllocationLimitExceeded),
        ));
    }

    #[test]
    fn nonconstant_trace_row_requires_interpolation_before_low_degree_extension() {
        let trace_domain = ProofEvaluationDomain::new_subgroup(4)
            .expect("the four-point trace subgroup is available");
        let trace_values = vec![
            ProofBaseFieldElement::from_canonical(3).unwrap(),
            ProofBaseFieldElement::from_canonical(5).unwrap(),
            ProofBaseFieldElement::ZERO,
            ProofBaseFieldElement::ONE,
        ];

        let mut monomial_interpretation = trace_values.clone();
        trace_domain
            .evaluate_base_polynomial_in_place(&mut monomial_interpretation)
            .expect("the monomial interpretation evaluates");
        assert_ne!(monomial_interpretation, trace_values);

        let mut interpolation_coefficients = trace_values.clone();
        trace_domain
            .interpolate_base_polynomial_in_place(&mut interpolation_coefficients)
            .expect("the trace row interpolates");
        trace_domain
            .evaluate_base_polynomial_in_place(&mut interpolation_coefficients)
            .expect("the interpolation polynomial evaluates");
        assert_eq!(interpolation_coefficients, trace_values);
    }

    #[test]
    fn canonical_lattice_anchor_provider_uses_relation_column_order_and_rejects_detached_columns() {
        let context = lattice_anchor_context();
        let physical_column_trace_value_count = POLYNOMIAL_DEGREE / 2;
        let mut commitment = LatticeAnchorCommitment {
            commitment_data_prime_index: 1,
            ring_degree: POLYNOMIAL_DEGREE,
            rows: vec![
                vec![0; POLYNOMIAL_DEGREE];
                SETUP_COMMITMENT_MODULE_RANK
                    .checked_add(1)
                    .expect("the anchor row count fits usize")
            ],
        };
        commitment.rows[0][0] = 3;
        commitment.rows[0][physical_column_trace_value_count - 1] = 5;
        commitment.rows[0][physical_column_trace_value_count] = 7;
        commitment.rows[0][POLYNOMIAL_DEGREE - 1] = 11;
        commitment.rows[1][0] = 13;
        commitment.rows[1][physical_column_trace_value_count - 1] = 17;
        commitment.rows[1][physical_column_trace_value_count] = 19;
        commitment.rows[1][POLYNOMIAL_DEGREE - 1] = 23;
        let canonical_bytes = lattice_anchor_commitment_canonical_bytes(&commitment)
            .expect("the anchor bytes are canonical");
        let original = SetupPublicPolynomialTree::from_lattice_anchor_canonical_bytes(
            &context,
            2 * POLYNOMIAL_DEGREE,
            &canonical_bytes,
        )
        .expect("the canonical anchor builds its role-one tree");
        let original_root = original.root();
        let (streamed_context_hash, streamed_root, streamed_source_degree, streamed_row_width) =
            SetupPublicPolynomialTree::construct_lattice_anchor_root_from_canonical_bytes(
                &context,
                2 * POLYNOMIAL_DEGREE,
                &canonical_bytes,
            )
            .expect("the canonical anchor streams its role-one root");
        assert_eq!(
            streamed_context_hash,
            original.public_polynomial_context_hash()
        );
        assert_eq!(streamed_root, original_root);
        assert_eq!(
            streamed_source_degree,
            original.source_polynomial_degree_bound_exclusive()
        );
        assert_eq!(streamed_row_width, original.row_width());
        assert_eq!(original.row_width(), 4);
        assert_eq!(
            original.source_polynomial_degree_bound_exclusive(),
            physical_column_trace_value_count,
        );
        let expected_physical_columns = [
            &commitment.rows[0][..physical_column_trace_value_count],
            &commitment.rows[0][physical_column_trace_value_count..],
            &commitment.rows[1][..physical_column_trace_value_count],
            &commitment.rows[1][physical_column_trace_value_count..],
        ];
        for (physical_column, expected_coefficients) in original
            .ordered_trace_rows()
            .iter()
            .zip(expected_physical_columns)
        {
            assert_eq!(
                physical_column
                    .iter()
                    .map(|coefficient| coefficient.canonical())
                    .collect::<Vec<_>>(),
                expected_coefficients,
            );
        }

        let mut wrong_order_rows = original.ordered_trace_rows().to_vec();
        wrong_order_rows.swap(1, 2);
        drop(original);
        assert_eq!(
            SetupPublicPolynomialTree::construct(SetupPublicPolynomialTreeInput {
                context: &context,
                evaluation_domain_size: 2 * POLYNOMIAL_DEGREE,
                source_polynomial_degree_bound_exclusive: physical_column_trace_value_count,
                ordered_trace_rows: &wrong_order_rows,
            })
            .map(|tree| tree.root()),
            Err(SetupPublicPolynomialError::InvalidLatticeAnchor),
        );
        let wrong_order_tree = SetupPublicPolynomialTree::construct_from_trace_value_rows(
            SetupPublicPolynomialTreeInput {
                context: &context,
                evaluation_domain_size: 2 * POLYNOMIAL_DEGREE,
                source_polynomial_degree_bound_exclusive: physical_column_trace_value_count,
                ordered_trace_rows: &wrong_order_rows,
            },
        )
        .expect("the detached columns remain individually well formed");
        assert_ne!(original_root, wrong_order_tree.root());
        drop(wrong_order_tree);

        commitment.rows[1][3] = 1;
        let changed_bytes = lattice_anchor_commitment_canonical_bytes(&commitment)
            .expect("the changed anchor bytes are canonical");
        let changed = SetupPublicPolynomialTree::from_lattice_anchor_canonical_bytes(
            &context,
            2 * POLYNOMIAL_DEGREE,
            &changed_bytes,
        )
        .expect("the changed anchor builds its role-one tree");
        assert_ne!(original_root, changed.root());

        let wrong_prime_context =
            SetupPublicPolynomialContext::lattice_anchor([0x31; 64], [0x71; 64], 2, 2)
                .expect("the other selected prime context is canonical");
        assert_eq!(
            SetupPublicPolynomialTree::from_lattice_anchor_canonical_bytes(
                &wrong_prime_context,
                2 * POLYNOMIAL_DEGREE,
                &changed_bytes,
            )
            .map(|tree| tree.root()),
            Err(SetupPublicPolynomialError::InvalidLatticeAnchor),
        );
    }
}
