use core::mem::size_of;

use crate::bgv::key_switch_topology::canonical_residue_byte_length;
use crate::foundation::{
    CanonicalItem, CanonicalStreamDomain, CanonicalStreamReadbackVerifier, CanonicalStreamVerifier,
    CanonicalStreamWriter, FOUNDATION_PROFILE, Hash512, RefusalReason, SelectedSuiteCapability,
    StreamDescriptor, VerificationResult, VerifiedCanonicalStreamSummary,
    hash_foundation_tuple_512,
};

use super::ProofBaseFieldElement;

const COMPONENT_MATERIAL_ROOT_DOMAIN: &str =
    "sealed-lattice/setup/evaluator-key/component-material-root/v1";

/// Suite-owned shape for one hybrid key-switch component.
///
/// The payload carries no shape header. Production construction therefore
/// requires the opaque selected-suite capability; hostile bytes cannot choose
/// the block count, modulus order, residue width, or ring degree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct KeySwitchComponentMaterialTopology {
    ordered_moduli: Box<[u64]>,
    residue_byte_lengths: Box<[u8]>,
    data_block_count: usize,
    polynomial_degree: usize,
    expected_byte_length: u64,
}

impl KeySwitchComponentMaterialTopology {
    pub(crate) fn from_selected_suite_at_level(
        selected_suite: &SelectedSuiteCapability,
        catalog_level: usize,
    ) -> Result<Self, RefusalReason> {
        let active_data_prime_count = catalog_level
            .checked_add(1)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        let active_data_primes = selected_suite
            .ordered_data_primes()
            .get(..active_data_prime_count)
            .ok_or(RefusalReason::UnsupportedVersionOrSuite)?;
        Self::from_suite_algebra(
            active_data_primes,
            selected_suite.ordered_special_primes(),
            usize::from(selected_suite.key_switch_data_primes_per_block()),
            usize::try_from(selected_suite.polynomial_degree())
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
        )
    }

    fn from_suite_algebra(
        ordered_data_moduli: &[u64],
        ordered_special_moduli: &[u64],
        data_primes_per_block: usize,
        polynomial_degree: usize,
    ) -> Result<Self, RefusalReason> {
        if ordered_data_moduli.is_empty()
            || ordered_special_moduli.is_empty()
            || data_primes_per_block == 0
            || data_primes_per_block > ordered_data_moduli.len()
            || polynomial_degree == 0
            || !polynomial_degree.is_power_of_two()
        {
            return Err(RefusalReason::UnsupportedVersionOrSuite);
        }

        let mut ordered_moduli = Vec::with_capacity(
            ordered_data_moduli
                .len()
                .checked_add(ordered_special_moduli.len())
                .ok_or(RefusalReason::OutsideSupportedProfile)?,
        );
        ordered_moduli.extend_from_slice(ordered_data_moduli);
        ordered_moduli.extend_from_slice(ordered_special_moduli);
        if ordered_moduli.iter().any(|modulus| *modulus < 2) {
            return Err(RefusalReason::UnsupportedVersionOrSuite);
        }
        for (modulus_index, modulus) in ordered_moduli.iter().enumerate() {
            if ordered_moduli[..modulus_index].contains(modulus) {
                return Err(RefusalReason::UnsupportedVersionOrSuite);
            }
        }

        let residue_byte_lengths = ordered_moduli
            .iter()
            .map(|modulus| {
                canonical_residue_byte_length(*modulus)
                    .and_then(|byte_length| {
                        u8::try_from(byte_length).map_err(|_| {
                            crate::encoding::CanonicalError::new(
                                crate::encoding::CanonicalErrorCode::InvalidProtocolObject,
                                "component-material residue width does not fit u8",
                            )
                        })
                    })
                    .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let data_block_count = ordered_data_moduli
            .len()
            .checked_add(data_primes_per_block - 1)
            .ok_or(RefusalReason::OutsideSupportedProfile)?
            / data_primes_per_block;
        let bytes_per_polynomial_coefficient =
            residue_byte_lengths
                .iter()
                .try_fold(0_u64, |total, byte_length| {
                    total
                        .checked_add(u64::from(*byte_length))
                        .ok_or(RefusalReason::OutsideSupportedProfile)
                })?;
        let expected_byte_length = u64::try_from(data_block_count)
            .ok()
            .and_then(|block_count| {
                u64::try_from(polynomial_degree)
                    .ok()
                    .and_then(|degree| block_count.checked_mul(degree))
            })
            .and_then(|coefficient_count| {
                coefficient_count.checked_mul(bytes_per_polynomial_coefficient)
            })
            .ok_or(RefusalReason::OutsideSupportedProfile)?;

        Ok(Self {
            ordered_moduli: ordered_moduli.into_boxed_slice(),
            residue_byte_lengths: residue_byte_lengths.into_boxed_slice(),
            data_block_count,
            polynomial_degree,
            expected_byte_length,
        })
    }

    pub(crate) const fn data_block_count(&self) -> usize {
        self.data_block_count
    }

    pub(crate) fn extended_limb_count(&self) -> usize {
        self.ordered_moduli.len()
    }

    pub(crate) fn ordered_moduli(&self) -> &[u64] {
        &self.ordered_moduli
    }

    pub(crate) const fn polynomial_degree(&self) -> usize {
        self.polynomial_degree
    }

    pub(crate) const fn expected_byte_length(&self) -> u64 {
        self.expected_byte_length
    }

    pub(crate) fn trace_column_count(&self) -> Result<usize, RefusalReason> {
        self.data_block_count
            .checked_mul(self.extended_limb_count())
            .and_then(|column_count| column_count.checked_mul(2))
            .ok_or(RefusalReason::OutsideSupportedProfile)
    }

    /// Maps one relation-plan column to its sole contiguous range in the
    /// authenticated headerless component stream. Full-ring residue vectors
    /// are split into their low and high trace halves in block, limb, half
    /// order, exactly matching the setup-polynomial relation plans.
    pub(crate) fn trace_column(
        &self,
        column_ordinal: usize,
    ) -> Result<KeySwitchComponentTraceColumn, RefusalReason> {
        let columns_per_block = self
            .extended_limb_count()
            .checked_mul(2)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        if column_ordinal >= self.trace_column_count()? || self.polynomial_degree < 2 {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let block_index = column_ordinal / columns_per_block;
        let column_within_block = column_ordinal % columns_per_block;
        let limb_index = column_within_block / 2;
        let half = if column_within_block % 2 == 0 {
            KeySwitchComponentTraceHalf::Low
        } else {
            KeySwitchComponentTraceHalf::High
        };
        let half_degree = self.polynomial_degree / 2;
        let coefficient_start = match half {
            KeySwitchComponentTraceHalf::Low => 0,
            KeySwitchComponentTraceHalf::High => half_degree,
        };
        let residue_byte_length = self.residue_byte_length(limb_index)?;
        let bytes_per_block =
            self.residue_byte_lengths
                .iter()
                .try_fold(0_u64, |total, byte_length| {
                    u64::try_from(self.polynomial_degree)
                        .ok()
                        .and_then(|degree| degree.checked_mul(u64::from(*byte_length)))
                        .and_then(|limb_byte_length| total.checked_add(limb_byte_length))
                        .ok_or(RefusalReason::OutsideSupportedProfile)
                })?;
        let bytes_before_limb = self.residue_byte_lengths[..limb_index].iter().try_fold(
            0_u64,
            |total, byte_length| {
                u64::try_from(self.polynomial_degree)
                    .ok()
                    .and_then(|degree| degree.checked_mul(u64::from(*byte_length)))
                    .and_then(|limb_byte_length| total.checked_add(limb_byte_length))
                    .ok_or(RefusalReason::OutsideSupportedProfile)
            },
        )?;
        let byte_offset = u64::try_from(block_index)
            .ok()
            .and_then(|block| block.checked_mul(bytes_per_block))
            .and_then(|offset| offset.checked_add(bytes_before_limb))
            .and_then(|offset| {
                u64::try_from(coefficient_start)
                    .ok()
                    .and_then(|start| start.checked_mul(u64::try_from(residue_byte_length).ok()?))
                    .and_then(|half_offset| offset.checked_add(half_offset))
            })
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        let byte_length = u64::try_from(half_degree)
            .ok()
            .and_then(|degree| degree.checked_mul(u64::try_from(residue_byte_length).ok()?))
            .ok_or(RefusalReason::OutsideSupportedProfile)?;

        Ok(KeySwitchComponentTraceColumn {
            column_ordinal,
            block_index,
            limb_index,
            half,
            modulus: self.modulus(limb_index)?,
            residue_byte_length,
            coefficient_start,
            coefficient_count: half_degree,
            byte_offset,
            byte_length,
        })
    }

    fn modulus(&self, limb_index: usize) -> Result<u64, RefusalReason> {
        self.ordered_moduli
            .get(limb_index)
            .copied()
            .ok_or(RefusalReason::WrongTypeOrLength)
    }

    fn residue_byte_length(&self, limb_index: usize) -> Result<usize, RefusalReason> {
        self.residue_byte_lengths
            .get(limb_index)
            .copied()
            .map(usize::from)
            .ok_or(RefusalReason::WrongTypeOrLength)
    }

    #[cfg(test)]
    pub(crate) fn for_test_suite(
        ordered_data_moduli: &[u64],
        ordered_special_moduli: &[u64],
        data_primes_per_block: usize,
        polynomial_degree: usize,
    ) -> Result<Self, RefusalReason> {
        Self::from_suite_algebra(
            ordered_data_moduli,
            ordered_special_moduli,
            data_primes_per_block,
            polynomial_degree,
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeySwitchComponentTraceHalf {
    Low,
    High,
}

/// Exact authenticated-stream coordinates for one setup-polynomial trace
/// column. The range is contiguous even when transport chunks do not align
/// with residue or column boundaries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct KeySwitchComponentTraceColumn {
    column_ordinal: usize,
    block_index: usize,
    limb_index: usize,
    half: KeySwitchComponentTraceHalf,
    modulus: u64,
    residue_byte_length: usize,
    coefficient_start: usize,
    coefficient_count: usize,
    byte_offset: u64,
    byte_length: u64,
}

impl KeySwitchComponentTraceColumn {
    pub(crate) const fn column_ordinal(self) -> usize {
        self.column_ordinal
    }

    pub(crate) const fn block_index(self) -> usize {
        self.block_index
    }

    pub(crate) const fn limb_index(self) -> usize {
        self.limb_index
    }

    pub(crate) const fn half(self) -> KeySwitchComponentTraceHalf {
        self.half
    }

    pub(crate) const fn modulus(self) -> u64 {
        self.modulus
    }

    pub(crate) const fn residue_byte_length(self) -> usize {
        self.residue_byte_length
    }

    pub(crate) const fn coefficient_start(self) -> usize {
        self.coefficient_start
    }

    pub(crate) const fn coefficient_count(self) -> usize {
        self.coefficient_count
    }

    pub(crate) const fn byte_offset(self) -> u64 {
        self.byte_offset
    }

    pub(crate) const fn byte_length(self) -> u64 {
        self.byte_length
    }

    /// Decodes one complete authenticated column range without retaining any
    /// other component bytes. Canonical residue checks are repeated at replay
    /// so a wrong byte range cannot silently become a different polynomial.
    pub(crate) fn decode_authenticated_bytes(
        self,
        bytes: &[u8],
    ) -> Result<Vec<ProofBaseFieldElement>, RefusalReason> {
        if u64::try_from(bytes.len()).ok() != Some(self.byte_length)
            || self.residue_byte_length == 0
            || bytes.len() % self.residue_byte_length != 0
            || bytes.len() / self.residue_byte_length != self.coefficient_count
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        bytes
            .chunks_exact(self.residue_byte_length)
            .map(|encoded_residue| {
                let mut residue_bytes = [0_u8; size_of::<u64>()];
                residue_bytes[..self.residue_byte_length].copy_from_slice(encoded_residue);
                let residue = u64::from_le_bytes(residue_bytes);
                if residue >= self.modulus {
                    return Err(RefusalReason::MalformedEncoding);
                }
                ProofBaseFieldElement::from_canonical(residue)
                    .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)
            })
            .collect()
    }
}

/// Exact authority-owned coordinates for one component stream.
///
/// The runtime constructs this only while borrowing the matching selected
/// suite and application capabilities. It is not serializable and has no
/// constructor at the worker command boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ComponentMaterialOwnershipBinding {
    suite_identifier: Hash512,
    action_context_hash: Hash512,
    application_context_hash: Hash512,
}

impl ComponentMaterialOwnershipBinding {
    pub(crate) const fn from_generated_application(
        suite_identifier: [u8; Hash512::BYTE_LENGTH],
        action_context_hash: [u8; Hash512::BYTE_LENGTH],
        application_context_hash: [u8; Hash512::BYTE_LENGTH],
    ) -> Self {
        Self {
            suite_identifier: Hash512::from_bytes(suite_identifier),
            action_context_hash: Hash512::from_bytes(action_context_hash),
            application_context_hash: Hash512::from_bytes(application_context_hash),
        }
    }

    pub(crate) const fn from_verified_application(
        suite_identifier: [u8; Hash512::BYTE_LENGTH],
        action_context_hash: [u8; Hash512::BYTE_LENGTH],
        application_context_hash: [u8; Hash512::BYTE_LENGTH],
    ) -> Self {
        Self::from_generated_application(
            suite_identifier,
            action_context_hash,
            application_context_hash,
        )
    }
}

/// Rust-minted terminal value for an authenticated, canonical, in-range
/// component stream. It contains no payload and cannot be reconstructed from a
/// transport digest or caller-supplied root.
#[derive(Debug)]
pub(crate) struct VerifiedKeySwitchComponentMaterial {
    material_root: Hash512,
    topology: KeySwitchComponentMaterialTopology,
    canonical_stream_summary: VerifiedCanonicalStreamSummary,
}

impl PartialEq for VerifiedKeySwitchComponentMaterial {
    fn eq(&self, other: &Self) -> bool {
        self.material_root == other.material_root
            && self.topology == other.topology
            && self.canonical_stream_summary.stream_domain()
                == other.canonical_stream_summary.stream_domain()
            && self.canonical_stream_summary.stream_descriptor()
                == other.canonical_stream_summary.stream_descriptor()
    }
}

impl Eq for VerifiedKeySwitchComponentMaterial {}

impl VerifiedKeySwitchComponentMaterial {
    pub(crate) const fn material_root(&self) -> Hash512 {
        self.material_root
    }

    pub(crate) const fn full_object_digest(&self) -> Hash512 {
        self.canonical_stream_summary.full_object_digest()
    }

    pub(crate) const fn total_byte_length(&self) -> u64 {
        self.canonical_stream_summary.total_byte_length()
    }

    pub(crate) const fn topology(&self) -> &KeySwitchComponentMaterialTopology {
        &self.topology
    }

    pub(crate) const fn stream_descriptor(&self) -> &StreamDescriptor {
        self.canonical_stream_summary.stream_descriptor()
    }

    pub(crate) fn binds_ownership(
        &self,
        ownership_binding: ComponentMaterialOwnershipBinding,
    ) -> bool {
        derive_component_material_root(
            ownership_binding,
            self.canonical_stream_summary.total_byte_length(),
            self.canonical_stream_summary.full_object_digest(),
        )
        .is_ok_and(|expected_root| expected_root == self.material_root)
    }

    /// Starts a fresh descriptor-authenticated replay pass. Checkpoint resume
    /// deliberately restarts authentication from the retained verifier-owned
    /// summary rather than serializing any caller-provided replay verdict.
    pub(crate) fn begin_authenticated_readback(
        &self,
    ) -> Result<CanonicalStreamReadbackVerifier, RefusalReason> {
        CanonicalStreamReadbackVerifier::new(
            CanonicalStreamDomain::EvaluatorKeyStore,
            self.canonical_stream_summary.clone(),
        )
    }

    /// Re-encodes the exact block, limb, coefficient order authenticated by
    /// this material terminal from a setup tree's low/high trace columns. A
    /// matching descriptor proves that the tree and the later component
    /// readback refer to the same canonical bytes; a detached root or digest
    /// cannot establish this linkage.
    pub(crate) fn authenticate_setup_tree_trace_columns(
        &self,
        ordered_trace_columns: &[Vec<ProofBaseFieldElement>],
    ) -> Result<(), RefusalReason> {
        let topology = &self.topology;
        let expected_column_count = topology.trace_column_count()?;
        let half_degree = topology.polynomial_degree / 2;
        if ordered_trace_columns.len() != expected_column_count
            || ordered_trace_columns
                .iter()
                .any(|column| column.len() != half_degree)
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }

        let chunk_byte_length = FOUNDATION_PROFILE.stream_chunk_byte_length;
        let mut descriptor_writer = CanonicalStreamWriter::new(
            CanonicalStreamDomain::EvaluatorKeyStore,
            topology.expected_byte_length,
        )?;
        let mut chunk_bytes = Vec::with_capacity(chunk_byte_length);
        let mut chunk_index = 0_usize;
        for block_index in 0..topology.data_block_count {
            for limb_index in 0..topology.extended_limb_count() {
                let modulus = topology.modulus(limb_index)?;
                let residue_byte_length = topology.residue_byte_length(limb_index)?;
                let column_pair_ordinal = block_index
                    .checked_mul(topology.extended_limb_count())
                    .and_then(|ordinal| ordinal.checked_add(limb_index))
                    .and_then(|ordinal| ordinal.checked_mul(2))
                    .ok_or(RefusalReason::OutsideSupportedProfile)?;
                for half_ordinal in 0..2_usize {
                    let column = ordered_trace_columns
                        .get(column_pair_ordinal + half_ordinal)
                        .ok_or(RefusalReason::WrongTypeOrLength)?;
                    for coefficient in column {
                        let canonical_coefficient = coefficient.canonical();
                        if canonical_coefficient >= modulus {
                            return Err(RefusalReason::MalformedEncoding);
                        }
                        let encoded_coefficient = canonical_coefficient.to_le_bytes();
                        let mut unread_bytes = &encoded_coefficient[..residue_byte_length];
                        while !unread_bytes.is_empty() {
                            let remaining_chunk_byte_length = chunk_byte_length
                                .checked_sub(chunk_bytes.len())
                                .ok_or(RefusalReason::OutsideSupportedProfile)?;
                            let copied_byte_length =
                                remaining_chunk_byte_length.min(unread_bytes.len());
                            chunk_bytes.extend_from_slice(&unread_bytes[..copied_byte_length]);
                            unread_bytes = &unread_bytes[copied_byte_length..];
                            if chunk_bytes.len() == chunk_byte_length {
                                descriptor_writer.absorb_chunk(chunk_index, &chunk_bytes)?;
                                chunk_index = chunk_index
                                    .checked_add(1)
                                    .ok_or(RefusalReason::OutsideSupportedProfile)?;
                                chunk_bytes.clear();
                            }
                        }
                    }
                }
            }
        }
        if !chunk_bytes.is_empty() {
            descriptor_writer.absorb_chunk(chunk_index, &chunk_bytes)?;
        }
        let recomputed_descriptor = descriptor_writer.finish()?;
        if &recomputed_descriptor != self.canonical_stream_summary.stream_descriptor() {
            return Err(RefusalReason::WrongHashOrRoot);
        }
        Ok(())
    }
}

/// Incremental verifier for the headerless suite-owned component grammar.
///
/// At most one compact residue is retained. Payload chunks remain owned by the
/// worker's authenticated external-memory transaction; this verifier only
/// authenticates and validates the borrowed chunk before it is committed.
pub(crate) struct VerifiedKeySwitchComponentMaterialStream {
    topology: KeySwitchComponentMaterialTopology,
    ownership_binding: ComponentMaterialOwnershipBinding,
    canonical_stream: Option<CanonicalStreamVerifier>,
    block_index: usize,
    limb_index: usize,
    coefficient_index: usize,
    pending_residue_bytes: [u8; size_of::<u64>()],
    pending_residue_byte_length: usize,
    observed_byte_length: u64,
    refusal_reason: Option<RefusalReason>,
}

impl VerifiedKeySwitchComponentMaterialStream {
    pub(crate) fn begin(
        topology: KeySwitchComponentMaterialTopology,
        ownership_binding: ComponentMaterialOwnershipBinding,
        descriptor: StreamDescriptor,
    ) -> Result<Self, RefusalReason> {
        if descriptor.total_byte_length != topology.expected_byte_length() {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let canonical_stream =
            CanonicalStreamVerifier::new(CanonicalStreamDomain::EvaluatorKeyStore, descriptor)?;
        Ok(Self {
            topology,
            ownership_binding,
            canonical_stream: Some(canonical_stream),
            block_index: 0,
            limb_index: 0,
            coefficient_index: 0,
            pending_residue_bytes: [0; size_of::<u64>()],
            pending_residue_byte_length: 0,
            observed_byte_length: 0,
            refusal_reason: None,
        })
    }

    pub(crate) fn absorb_chunk(
        &mut self,
        chunk_index: usize,
        chunk_bytes: &[u8],
    ) -> VerificationResult<()> {
        if let Some(refusal_reason) = self.refusal_reason {
            return VerificationResult::refused(refusal_reason);
        }
        let result = self.absorb_chunk_inner(chunk_index, chunk_bytes);
        match result {
            Ok(()) => VerificationResult::valid(()),
            Err(refusal_reason) => {
                self.refusal_reason = Some(refusal_reason);
                VerificationResult::refused(refusal_reason)
            }
        }
    }

    pub(crate) fn cancel(&mut self) {
        self.canonical_stream = None;
        self.pending_residue_bytes.fill(0);
        self.pending_residue_byte_length = 0;
        self.refusal_reason = Some(RefusalReason::ConsumedState);
    }

    pub(crate) fn finish(mut self) -> VerificationResult<VerifiedKeySwitchComponentMaterial> {
        let result = self.finish_inner();
        self.pending_residue_bytes.fill(0);
        match result {
            Ok(verified_material) => VerificationResult::valid(verified_material),
            Err(refusal_reason) => VerificationResult::refused(refusal_reason),
        }
    }

    fn absorb_chunk_inner(
        &mut self,
        chunk_index: usize,
        chunk_bytes: &[u8],
    ) -> Result<(), RefusalReason> {
        self.canonical_stream
            .as_mut()
            .ok_or(RefusalReason::ConsumedState)?
            .absorb_chunk(chunk_index, chunk_bytes)
            .into_result()?;
        self.observed_byte_length = self
            .observed_byte_length
            .checked_add(
                u64::try_from(chunk_bytes.len())
                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            )
            .ok_or(RefusalReason::OutsideSupportedProfile)?;

        let mut unread_bytes = chunk_bytes;
        while !unread_bytes.is_empty() {
            let residue_byte_length = self.topology.residue_byte_length(self.limb_index)?;
            let remaining_residue_byte_length = residue_byte_length
                .checked_sub(self.pending_residue_byte_length)
                .ok_or(RefusalReason::WrongTypeOrLength)?;
            let copied_byte_length = remaining_residue_byte_length.min(unread_bytes.len());
            let destination_start = self.pending_residue_byte_length;
            let destination_end = destination_start
                .checked_add(copied_byte_length)
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
            self.pending_residue_bytes[destination_start..destination_end]
                .copy_from_slice(&unread_bytes[..copied_byte_length]);
            self.pending_residue_byte_length = destination_end;
            unread_bytes = &unread_bytes[copied_byte_length..];

            if self.pending_residue_byte_length == residue_byte_length {
                self.finish_residue()?;
            }
        }
        Ok(())
    }

    fn finish_residue(&mut self) -> Result<(), RefusalReason> {
        let residue = u64::from_le_bytes(self.pending_residue_bytes);
        let modulus = self.topology.modulus(self.limb_index)?;
        self.pending_residue_bytes.fill(0);
        self.pending_residue_byte_length = 0;
        if residue >= modulus {
            return Err(RefusalReason::MalformedEncoding);
        }

        self.coefficient_index += 1;
        if self.coefficient_index == self.topology.polynomial_degree() {
            self.coefficient_index = 0;
            self.limb_index += 1;
            if self.limb_index == self.topology.extended_limb_count() {
                self.limb_index = 0;
                self.block_index += 1;
            }
        }
        if self.block_index > self.topology.data_block_count() {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        Ok(())
    }

    fn finish_inner(&mut self) -> Result<VerifiedKeySwitchComponentMaterial, RefusalReason> {
        if let Some(refusal_reason) = self.refusal_reason {
            return Err(refusal_reason);
        }
        if self.observed_byte_length != self.topology.expected_byte_length()
            || self.block_index != self.topology.data_block_count()
            || self.limb_index != 0
            || self.coefficient_index != 0
            || self.pending_residue_byte_length != 0
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let canonical_summary = self
            .canonical_stream
            .take()
            .ok_or(RefusalReason::ConsumedState)?
            .finish_with_summary()
            .into_result()?;
        derive_verified_component_material(
            canonical_summary,
            self.ownership_binding,
            self.topology.clone(),
        )
    }

    #[cfg(test)]
    const fn retained_payload_byte_length(&self) -> usize {
        self.pending_residue_byte_length
    }
}

fn derive_verified_component_material(
    canonical_summary: VerifiedCanonicalStreamSummary,
    ownership_binding: ComponentMaterialOwnershipBinding,
    topology: KeySwitchComponentMaterialTopology,
) -> Result<VerifiedKeySwitchComponentMaterial, RefusalReason> {
    if canonical_summary.stream_domain() != CanonicalStreamDomain::EvaluatorKeyStore {
        return Err(RefusalReason::WrongContext);
    }
    let full_object_digest = canonical_summary.full_object_digest();
    let total_byte_length = canonical_summary.total_byte_length();
    let material_root =
        derive_component_material_root(ownership_binding, total_byte_length, full_object_digest)?;
    Ok(VerifiedKeySwitchComponentMaterial {
        material_root,
        topology,
        canonical_stream_summary: canonical_summary,
    })
}

fn derive_component_material_root(
    ownership_binding: ComponentMaterialOwnershipBinding,
    total_byte_length: u64,
    full_object_digest: Hash512,
) -> Result<Hash512, RefusalReason> {
    hash_foundation_tuple_512(
        COMPONENT_MATERIAL_ROOT_DOMAIN,
        &[
            CanonicalItem::hash512(ownership_binding.suite_identifier.into_bytes()),
            CanonicalItem::hash512(ownership_binding.action_context_hash.into_bytes()),
            CanonicalItem::hash512(ownership_binding.application_context_hash.into_bytes()),
            CanonicalItem::unsigned64(total_byte_length),
            CanonicalItem::hash512(full_object_digest.into_bytes()),
        ],
    )
    .map_err(|_| RefusalReason::OutsideSupportedProfile)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::{FOUNDATION_PROFILE, derive_canonical_stream_descriptor};

    const TEST_DATA_MODULI: [u64; 3] = [257, 65_537, 16_777_213];
    const TEST_SPECIAL_MODULI: [u64; 2] = [769, 4_294_967_291];

    fn test_topology() -> KeySwitchComponentMaterialTopology {
        KeySwitchComponentMaterialTopology::for_test_suite(
            &TEST_DATA_MODULI,
            &TEST_SPECIAL_MODULI,
            2,
            8,
        )
        .expect("test topology")
    }

    fn test_binding(application_byte: u8) -> ComponentMaterialOwnershipBinding {
        ComponentMaterialOwnershipBinding::from_verified_application(
            [0x11; Hash512::BYTE_LENGTH],
            [0x22; Hash512::BYTE_LENGTH],
            [application_byte; Hash512::BYTE_LENGTH],
        )
    }

    fn encoded_material(topology: &KeySwitchComponentMaterialTopology) -> Vec<u8> {
        let expected_length = usize::try_from(topology.expected_byte_length())
            .expect("test material length fits usize");
        let mut bytes = Vec::with_capacity(expected_length);
        for block_index in 0..topology.data_block_count() {
            for limb_index in 0..topology.extended_limb_count() {
                let modulus = topology.modulus(limb_index).expect("test modulus");
                let residue_byte_length = topology
                    .residue_byte_length(limb_index)
                    .expect("test residue width");
                for coefficient_index in 0..topology.polynomial_degree() {
                    let residue = (u64::try_from(block_index).expect("block index") * 37
                        + u64::try_from(limb_index).expect("limb index") * 11
                        + u64::try_from(coefficient_index).expect("coefficient index"))
                        % modulus;
                    bytes.extend_from_slice(&residue.to_le_bytes()[..residue_byte_length]);
                }
            }
        }
        assert_eq!(bytes.len(), expected_length);
        bytes
    }

    fn verify_material(
        topology: KeySwitchComponentMaterialTopology,
        binding: ComponentMaterialOwnershipBinding,
        bytes: &[u8],
    ) -> VerificationResult<VerifiedKeySwitchComponentMaterial> {
        let descriptor =
            derive_canonical_stream_descriptor(CanonicalStreamDomain::EvaluatorKeyStore, bytes)
                .expect("test stream descriptor");
        let mut stream =
            VerifiedKeySwitchComponentMaterialStream::begin(topology, binding, descriptor)
                .expect("stream begins");
        for (chunk_index, chunk) in bytes
            .chunks(FOUNDATION_PROFILE.stream_chunk_byte_length)
            .enumerate()
        {
            stream
                .absorb_chunk(chunk_index, chunk)
                .into_result()
                .expect("chunk verifies");
            assert!(stream.retained_payload_byte_length() < size_of::<u64>());
        }
        stream.finish()
    }

    #[test]
    fn topology_is_generic_over_larger_blocks_multiple_special_primes_and_compact_widths() {
        let topology = test_topology();

        assert_eq!(topology.data_block_count(), 2);
        assert_eq!(topology.extended_limb_count(), 5);
        assert_eq!(topology.polynomial_degree(), 8);
        assert_eq!(topology.residue_byte_lengths.as_ref(), &[2, 3, 3, 2, 4]);
        assert_eq!(topology.expected_byte_length(), 224);

        assert_eq!(
            KeySwitchComponentMaterialTopology::for_test_suite(&[257, 769], &[12289], 1, 8)
                .expect("alpha one topology")
                .data_block_count(),
            2
        );
        for invalid_topology in [
            KeySwitchComponentMaterialTopology::for_test_suite(&[], &[769], 1, 8),
            KeySwitchComponentMaterialTopology::for_test_suite(&[257], &[], 1, 8),
            KeySwitchComponentMaterialTopology::for_test_suite(&[257], &[257], 1, 8),
            KeySwitchComponentMaterialTopology::for_test_suite(&[257], &[769], 0, 8),
            KeySwitchComponentMaterialTopology::for_test_suite(&[257], &[769], 2, 8),
            KeySwitchComponentMaterialTopology::for_test_suite(&[257], &[769], 1, 7),
        ] {
            assert_eq!(
                invalid_topology,
                Err(RefusalReason::UnsupportedVersionOrSuite)
            );
        }
    }

    #[test]
    fn trace_columns_map_exactly_to_low_and_high_authenticated_stream_ranges() {
        let topology = test_topology();
        let bytes = encoded_material(&topology);

        assert_eq!(topology.trace_column_count(), Ok(20));
        let expected_columns = [
            (0, 0, 0, KeySwitchComponentTraceHalf::Low, 0, 4, 0, 8),
            (1, 0, 0, KeySwitchComponentTraceHalf::High, 4, 4, 8, 8),
            (2, 0, 1, KeySwitchComponentTraceHalf::Low, 0, 4, 16, 12),
            (9, 0, 4, KeySwitchComponentTraceHalf::High, 4, 4, 96, 16),
            (10, 1, 0, KeySwitchComponentTraceHalf::Low, 0, 4, 112, 8),
            (19, 1, 4, KeySwitchComponentTraceHalf::High, 4, 4, 208, 16),
        ];
        for (
            column_ordinal,
            expected_block,
            expected_limb,
            expected_half,
            expected_coefficient_start,
            expected_coefficient_count,
            expected_byte_offset,
            expected_byte_length,
        ) in expected_columns
        {
            let column = topology
                .trace_column(column_ordinal)
                .expect("trace column coordinates");
            assert_eq!(column.column_ordinal(), column_ordinal);
            assert_eq!(column.block_index(), expected_block);
            assert_eq!(column.limb_index(), expected_limb);
            assert_eq!(column.half(), expected_half);
            assert_eq!(column.coefficient_start(), expected_coefficient_start);
            assert_eq!(column.coefficient_count(), expected_coefficient_count);
            assert_eq!(column.byte_offset(), expected_byte_offset);
            assert_eq!(column.byte_length(), expected_byte_length);
            assert_eq!(column.modulus(), topology.modulus(expected_limb).unwrap());
            assert_eq!(
                column.residue_byte_length(),
                topology.residue_byte_length(expected_limb).unwrap()
            );

            let start = usize::try_from(column.byte_offset()).unwrap();
            let end = start + usize::try_from(column.byte_length()).unwrap();
            let decoded = column
                .decode_authenticated_bytes(&bytes[start..end])
                .expect("canonical trace column decodes");
            let expected = (expected_coefficient_start
                ..expected_coefficient_start + expected_coefficient_count)
                .map(|coefficient_index| {
                    let residue = (u64::try_from(expected_block).unwrap() * 37
                        + u64::try_from(expected_limb).unwrap() * 11
                        + u64::try_from(coefficient_index).unwrap())
                        % topology.modulus(expected_limb).unwrap();
                    ProofBaseFieldElement::from_canonical(residue).unwrap()
                })
                .collect::<Vec<_>>();
            assert_eq!(decoded, expected);
        }

        assert_eq!(
            topology.trace_column(20),
            Err(RefusalReason::WrongTypeOrLength)
        );
        let first_column = topology.trace_column(0).unwrap();
        assert_eq!(
            first_column.decode_authenticated_bytes(&bytes[..7]),
            Err(RefusalReason::WrongTypeOrLength)
        );
        let mut noncanonical = bytes[..8].to_vec();
        noncanonical[..2].copy_from_slice(&TEST_DATA_MODULI[0].to_le_bytes()[..2]);
        assert_eq!(
            first_column.decode_authenticated_bytes(&noncanonical),
            Err(RefusalReason::MalformedEncoding)
        );
    }

    #[test]
    fn authenticated_headerless_stream_mints_a_context_bound_root_without_retaining_payload() {
        let topology = test_topology();
        let bytes = encoded_material(&topology);
        let verified = verify_material(topology.clone(), test_binding(0x33), &bytes)
            .into_result()
            .expect("canonical material verifies");
        let repeated = verify_material(topology.clone(), test_binding(0x33), &bytes)
            .into_result()
            .expect("same material verifies deterministically");
        let different_application = verify_material(topology, test_binding(0x34), &bytes)
            .into_result()
            .expect("same material in another application verifies");

        assert_eq!(verified.material_root(), repeated.material_root());
        assert_eq!(verified.full_object_digest(), repeated.full_object_digest());
        assert!(verified.binds_ownership(test_binding(0x33)));
        assert!(!verified.binds_ownership(test_binding(0x34)));
        assert_eq!(verified.total_byte_length(), bytes.len() as u64);
        assert_eq!(verified.topology(), &test_topology());
        assert_eq!(
            verified.stream_descriptor().full_object_digest,
            verified.full_object_digest()
        );
        let mut readback = verified
            .begin_authenticated_readback()
            .expect("verified material begins authenticated replay");
        assert_eq!(readback.authenticate_chunk(0, &bytes), Ok(()));
        assert_eq!(
            readback
                .finish()
                .into_result()
                .expect("complete replay retains stream authority")
                .full_object_digest(),
            verified.full_object_digest()
        );

        let mut substituted_readback = repeated
            .begin_authenticated_readback()
            .expect("repeated material begins authenticated replay");
        let mut substituted_bytes = bytes.clone();
        substituted_bytes[0] ^= 1;
        assert_eq!(
            substituted_readback.authenticate_chunk(0, &substituted_bytes),
            Err(RefusalReason::WrongHashOrRoot)
        );
        assert_ne!(
            verified.material_root(),
            different_application.material_root()
        );
        assert_eq!(
            verified.full_object_digest(),
            different_application.full_object_digest()
        );
    }

    #[test]
    fn stream_refuses_truncation_trailing_bytes_wrong_chunk_hash_and_noncanonical_residues() {
        let topology = test_topology();
        let bytes = encoded_material(&topology);

        for wrong_length in [bytes.len() - 1, bytes.len() + 1] {
            let wrong_bytes = vec![0_u8; wrong_length];
            let descriptor = derive_canonical_stream_descriptor(
                CanonicalStreamDomain::EvaluatorKeyStore,
                &wrong_bytes,
            )
            .expect("wrong-length descriptor is internally canonical");
            assert_eq!(
                VerifiedKeySwitchComponentMaterialStream::begin(
                    topology.clone(),
                    test_binding(0x33),
                    descriptor,
                )
                .err(),
                Some(RefusalReason::WrongTypeOrLength)
            );
        }

        let descriptor =
            derive_canonical_stream_descriptor(CanonicalStreamDomain::EvaluatorKeyStore, &bytes)
                .expect("descriptor");
        let mut wrong_hash = VerifiedKeySwitchComponentMaterialStream::begin(
            topology.clone(),
            test_binding(0x33),
            descriptor,
        )
        .expect("stream begins");
        let mut changed_bytes = bytes.clone();
        let changed_byte_index = changed_bytes.len() / 2;
        changed_bytes[changed_byte_index] ^= 1;
        assert_eq!(
            wrong_hash.absorb_chunk(0, &changed_bytes),
            VerificationResult::refused(RefusalReason::WrongHashOrRoot)
        );
        assert_eq!(
            wrong_hash.finish(),
            VerificationResult::refused(RefusalReason::WrongHashOrRoot)
        );

        let mut noncanonical_bytes = bytes;
        noncanonical_bytes[..2].copy_from_slice(&TEST_DATA_MODULI[0].to_le_bytes()[..2]);
        let descriptor = derive_canonical_stream_descriptor(
            CanonicalStreamDomain::EvaluatorKeyStore,
            &noncanonical_bytes,
        )
        .expect("noncanonical payload still has a transport descriptor");
        let mut noncanonical = VerifiedKeySwitchComponentMaterialStream::begin(
            topology,
            test_binding(0x33),
            descriptor,
        )
        .expect("stream begins");
        assert_eq!(
            noncanonical.absorb_chunk(0, &noncanonical_bytes),
            VerificationResult::refused(RefusalReason::MalformedEncoding)
        );
        assert_eq!(
            noncanonical.finish(),
            VerificationResult::refused(RefusalReason::MalformedEncoding)
        );
    }

    #[test]
    fn cancellation_is_terminal_and_does_not_mint_material() {
        let topology = test_topology();
        let bytes = encoded_material(&topology);
        let descriptor =
            derive_canonical_stream_descriptor(CanonicalStreamDomain::EvaluatorKeyStore, &bytes)
                .expect("descriptor");
        let mut stream = VerifiedKeySwitchComponentMaterialStream::begin(
            topology,
            test_binding(0x33),
            descriptor,
        )
        .expect("stream begins");

        stream.cancel();
        assert_eq!(
            stream.absorb_chunk(0, &bytes),
            VerificationResult::refused(RefusalReason::ConsumedState)
        );
        assert_eq!(
            stream.finish(),
            VerificationResult::refused(RefusalReason::ConsumedState)
        );
    }

    #[test]
    fn multi_megabyte_stream_keeps_only_one_partial_residue_in_rust() {
        let topology = KeySwitchComponentMaterialTopology::for_test_suite(
            &[281_474_976_710_677],
            &[281_474_976_710_693],
            1,
            131_072,
        )
        .expect("large compact-width topology");
        assert_eq!(topology.residue_byte_lengths.as_ref(), &[7, 7]);
        let bytes = encoded_material(&topology);
        assert!(bytes.len() > FOUNDATION_PROFILE.stream_chunk_byte_length);
        let descriptor =
            derive_canonical_stream_descriptor(CanonicalStreamDomain::EvaluatorKeyStore, &bytes)
                .expect("large descriptor");
        let mut stream = VerifiedKeySwitchComponentMaterialStream::begin(
            topology,
            test_binding(0x33),
            descriptor,
        )
        .expect("large stream begins");

        let mut observed_split_residue = false;
        for (chunk_index, chunk) in bytes
            .chunks(FOUNDATION_PROFILE.stream_chunk_byte_length)
            .enumerate()
        {
            stream
                .absorb_chunk(chunk_index, chunk)
                .into_result()
                .expect("large chunk verifies");
            let retained = stream.retained_payload_byte_length();
            assert!(retained < size_of::<u64>());
            observed_split_residue |= retained != 0;
        }
        assert!(observed_split_residue);
        assert!(stream.finish().is_valid());
    }
}
