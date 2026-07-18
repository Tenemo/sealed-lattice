//! Authenticated component-stream reconstruction for setup public-polynomial trees.
//!
//! Browser workers retain component payloads outside Wasm. This adapter keeps
//! only one partial trace-column byte range while it authenticates the exact
//! canonical component stream and reconstructs the coefficient columns needed
//! by the common-proof verifier. A detached descriptor or root cannot create
//! either output capability.

use crate::foundation::{
    CanonicalStreamDomain, CanonicalStreamVerifier, RefusalReason, StreamDescriptor,
    VerifiedCanonicalStreamSummary,
};

use super::selected_profile::SELECTED_EVALUATION_DOMAIN_SIZE;
use super::{
    ComponentMaterialOwnershipBinding, KeySwitchComponentMaterialTopology, ProofBaseFieldElement,
    SetupPublicPolynomialContext, SetupPublicPolynomialError, SetupPublicPolynomialTree,
    SetupPublicPolynomialTreeInput, VerifiedKeySwitchComponentMaterial,
    VerifiedKeySwitchComponentMaterialStream,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ComponentPublicPolynomialRuntimeError {
    Refusal(RefusalReason),
    PublicPolynomial(SetupPublicPolynomialError),
}

impl From<RefusalReason> for ComponentPublicPolynomialRuntimeError {
    fn from(error: RefusalReason) -> Self {
        Self::Refusal(error)
    }
}

impl From<SetupPublicPolynomialError> for ComponentPublicPolynomialRuntimeError {
    fn from(error: SetupPublicPolynomialError) -> Self {
        Self::PublicPolynomial(error)
    }
}

/// Verifier-owned pairing of one authenticated component material capability
/// and the public-polynomial tree reconstructed from those exact bytes.
pub(crate) struct RecomputedKeySwitchComponentTree {
    material: VerifiedKeySwitchComponentMaterial,
    tree: SetupPublicPolynomialTree,
}

impl RecomputedKeySwitchComponentTree {
    pub(crate) const fn material(&self) -> &VerifiedKeySwitchComponentMaterial {
        &self.material
    }

    pub(crate) const fn tree(&self) -> &SetupPublicPolynomialTree {
        &self.tree
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        VerifiedKeySwitchComponentMaterial,
        SetupPublicPolynomialTree,
    ) {
        (self.material, self.tree)
    }
}

/// One descriptor-authenticated tree reconstruction that deliberately does
/// not mint component-material ownership. The evaluator lifecycle uses this
/// before the circular application-statement hash exists, then performs a
/// separate ownership-bound material pass after the statement is fixed.
pub(crate) struct DescriptorAuthenticatedKeySwitchComponentTree {
    canonical_stream_summary: VerifiedCanonicalStreamSummary,
    tree: SetupPublicPolynomialTree,
}

impl DescriptorAuthenticatedKeySwitchComponentTree {
    pub(crate) const fn canonical_stream_summary(&self) -> &VerifiedCanonicalStreamSummary {
        &self.canonical_stream_summary
    }

    pub(crate) const fn tree(&self) -> &SetupPublicPolynomialTree {
        &self.tree
    }

    pub(crate) fn into_tree(self) -> SetupPublicPolynomialTree {
        self.tree
    }
}

/// Authenticates one exact component descriptor while reconstructing its
/// setup-polynomial tree. It accepts no material root and cannot produce a
/// `VerifiedKeySwitchComponentMaterial`; that authority belongs exclusively
/// to the later application-owned pass.
pub(crate) struct DescriptorAuthenticatedKeySwitchComponentPublicPolynomialStream {
    topology: KeySwitchComponentMaterialTopology,
    canonical_stream: Option<CanonicalStreamVerifier>,
    ordered_trace_columns: Vec<Vec<ProofBaseFieldElement>>,
    pending_trace_column_bytes: Vec<u8>,
    next_trace_column_ordinal: usize,
    observed_byte_length: u64,
    refused: bool,
}

impl DescriptorAuthenticatedKeySwitchComponentPublicPolynomialStream {
    pub(crate) fn begin(
        topology: KeySwitchComponentMaterialTopology,
        stream_descriptor: StreamDescriptor,
    ) -> Result<Self, ComponentPublicPolynomialRuntimeError> {
        if stream_descriptor.total_byte_length != topology.expected_byte_length() {
            return Err(RefusalReason::WrongTypeOrLength.into());
        }
        let trace_column_count = topology.trace_column_count()?;
        let mut ordered_trace_columns = Vec::new();
        ordered_trace_columns
            .try_reserve_exact(trace_column_count)
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        Ok(Self {
            topology,
            canonical_stream: Some(CanonicalStreamVerifier::new(
                CanonicalStreamDomain::EvaluatorKeyStore,
                stream_descriptor,
            )?),
            ordered_trace_columns,
            pending_trace_column_bytes: Vec::new(),
            next_trace_column_ordinal: 0,
            observed_byte_length: 0,
            refused: false,
        })
    }

    pub(crate) fn absorb_chunk(
        &mut self,
        chunk_index: usize,
        chunk_bytes: &[u8],
    ) -> Result<(), ComponentPublicPolynomialRuntimeError> {
        if self.refused {
            return Err(RefusalReason::ConsumedState.into());
        }
        let result = self.absorb_chunk_inner(chunk_index, chunk_bytes);
        if result.is_err() {
            self.cancel();
        }
        result
    }

    fn absorb_chunk_inner(
        &mut self,
        chunk_index: usize,
        chunk_bytes: &[u8],
    ) -> Result<(), ComponentPublicPolynomialRuntimeError> {
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
            let trace_column = self.topology.trace_column(self.next_trace_column_ordinal)?;
            let expected_column_byte_length = usize::try_from(trace_column.byte_length())
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
            let remaining_column_byte_length = expected_column_byte_length
                .checked_sub(self.pending_trace_column_bytes.len())
                .ok_or(RefusalReason::WrongTypeOrLength)?;
            let copied_byte_length = remaining_column_byte_length.min(unread_bytes.len());
            self.pending_trace_column_bytes
                .extend_from_slice(&unread_bytes[..copied_byte_length]);
            unread_bytes = &unread_bytes[copied_byte_length..];
            if self.pending_trace_column_bytes.len() == expected_column_byte_length {
                let coefficients =
                    trace_column.decode_authenticated_bytes(&self.pending_trace_column_bytes)?;
                self.ordered_trace_columns.push(coefficients);
                self.pending_trace_column_bytes.clear();
                self.next_trace_column_ordinal = self
                    .next_trace_column_ordinal
                    .checked_add(1)
                    .ok_or(RefusalReason::OutsideSupportedProfile)?;
            }
        }
        Ok(())
    }

    pub(crate) fn finish(
        mut self,
        context: SetupPublicPolynomialContext,
    ) -> Result<DescriptorAuthenticatedKeySwitchComponentTree, ComponentPublicPolynomialRuntimeError>
    {
        let expected_trace_column_count = self.topology.trace_column_count()?;
        if self.refused
            || !self.pending_trace_column_bytes.is_empty()
            || self.next_trace_column_ordinal != expected_trace_column_count
            || self.ordered_trace_columns.len() != expected_trace_column_count
            || self.observed_byte_length != self.topology.expected_byte_length()
        {
            self.cancel();
            return Err(RefusalReason::WrongTypeOrLength.into());
        }
        let canonical_stream_summary = self
            .canonical_stream
            .take()
            .ok_or(RefusalReason::ConsumedState)?
            .finish_with_summary()
            .into_result()?;
        let evaluation_domain_size = usize::try_from(SELECTED_EVALUATION_DOMAIN_SIZE)
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let tree = SetupPublicPolynomialTree::construct(SetupPublicPolynomialTreeInput {
            context: &context,
            evaluation_domain_size,
            source_polynomial_degree_bound_exclusive: self
                .topology
                .quarter_polynomial_degree_bound_exclusive()?,
            ordered_coefficient_columns: &self.ordered_trace_columns,
        })?;
        Ok(DescriptorAuthenticatedKeySwitchComponentTree {
            canonical_stream_summary,
            tree,
        })
    }

    pub(crate) fn cancel(&mut self) {
        self.canonical_stream = None;
        self.pending_trace_column_bytes.fill(0);
        self.pending_trace_column_bytes.clear();
        for column in &mut self.ordered_trace_columns {
            column.fill(ProofBaseFieldElement::ZERO);
        }
        self.ordered_trace_columns.clear();
        self.refused = true;
    }
}

/// One-pass authenticated reconstruction of a headerless key-switch component.
///
/// The topology comes from the selected-suite capability and the ownership
/// binding comes from the live proof application. Chunks must arrive in exact
/// canonical stream order. The finished tree is fixed to the selected proof
/// evaluation domain rather than accepting a host-provided size.
pub(crate) struct KeySwitchComponentPublicPolynomialStream {
    topology: KeySwitchComponentMaterialTopology,
    material_stream: Option<VerifiedKeySwitchComponentMaterialStream>,
    ordered_trace_columns: Vec<Vec<ProofBaseFieldElement>>,
    pending_trace_column_bytes: Vec<u8>,
    next_trace_column_ordinal: usize,
    observed_byte_length: u64,
    refused: bool,
}

impl KeySwitchComponentPublicPolynomialStream {
    pub(crate) fn begin(
        topology: KeySwitchComponentMaterialTopology,
        ownership_binding: ComponentMaterialOwnershipBinding,
        stream_descriptor: StreamDescriptor,
    ) -> Result<Self, ComponentPublicPolynomialRuntimeError> {
        let trace_column_count = topology.trace_column_count()?;
        let material_stream = VerifiedKeySwitchComponentMaterialStream::begin(
            topology.clone(),
            ownership_binding,
            stream_descriptor,
        )?;
        let mut ordered_trace_columns = Vec::new();
        ordered_trace_columns
            .try_reserve_exact(trace_column_count)
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        Ok(Self {
            topology,
            material_stream: Some(material_stream),
            ordered_trace_columns,
            pending_trace_column_bytes: Vec::new(),
            next_trace_column_ordinal: 0,
            observed_byte_length: 0,
            refused: false,
        })
    }

    pub(crate) fn absorb_chunk(
        &mut self,
        chunk_index: usize,
        chunk_bytes: &[u8],
    ) -> Result<(), ComponentPublicPolynomialRuntimeError> {
        if self.refused {
            return Err(RefusalReason::ConsumedState.into());
        }
        let result = self.absorb_chunk_inner(chunk_index, chunk_bytes);
        if result.is_err() {
            self.cancel();
        }
        result
    }

    fn absorb_chunk_inner(
        &mut self,
        chunk_index: usize,
        chunk_bytes: &[u8],
    ) -> Result<(), ComponentPublicPolynomialRuntimeError> {
        self.material_stream
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
            let trace_column = self.topology.trace_column(self.next_trace_column_ordinal)?;
            let expected_column_byte_length = usize::try_from(trace_column.byte_length())
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
            let remaining_column_byte_length = expected_column_byte_length
                .checked_sub(self.pending_trace_column_bytes.len())
                .ok_or(RefusalReason::WrongTypeOrLength)?;
            let copied_byte_length = remaining_column_byte_length.min(unread_bytes.len());
            self.pending_trace_column_bytes
                .extend_from_slice(&unread_bytes[..copied_byte_length]);
            unread_bytes = &unread_bytes[copied_byte_length..];

            if self.pending_trace_column_bytes.len() == expected_column_byte_length {
                let coefficients =
                    trace_column.decode_authenticated_bytes(&self.pending_trace_column_bytes)?;
                self.ordered_trace_columns.push(coefficients);
                self.pending_trace_column_bytes.clear();
                self.next_trace_column_ordinal = self
                    .next_trace_column_ordinal
                    .checked_add(1)
                    .ok_or(RefusalReason::OutsideSupportedProfile)?;
            }
        }
        Ok(())
    }

    pub(crate) fn finish(
        mut self,
        context: SetupPublicPolynomialContext,
    ) -> Result<RecomputedKeySwitchComponentTree, ComponentPublicPolynomialRuntimeError> {
        let expected_trace_column_count = self.topology.trace_column_count()?;
        if self.refused
            || !self.pending_trace_column_bytes.is_empty()
            || self.next_trace_column_ordinal != expected_trace_column_count
            || self.ordered_trace_columns.len() != expected_trace_column_count
            || self.observed_byte_length != self.topology.expected_byte_length()
        {
            self.cancel();
            return Err(RefusalReason::WrongTypeOrLength.into());
        }
        let material = self
            .material_stream
            .take()
            .ok_or(RefusalReason::ConsumedState)?
            .finish()
            .into_result()?;
        let evaluation_domain_size = usize::try_from(SELECTED_EVALUATION_DOMAIN_SIZE)
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let tree = SetupPublicPolynomialTree::construct(SetupPublicPolynomialTreeInput {
            context: &context,
            evaluation_domain_size,
            source_polynomial_degree_bound_exclusive: self
                .topology
                .quarter_polynomial_degree_bound_exclusive()?,
            ordered_coefficient_columns: &self.ordered_trace_columns,
        })?;
        material.authenticate_setup_tree_trace_columns(tree.ordered_coefficient_columns())?;
        Ok(RecomputedKeySwitchComponentTree { material, tree })
    }

    pub(crate) fn cancel(&mut self) {
        if let Some(material_stream) = self.material_stream.as_mut() {
            material_stream.cancel();
        }
        self.material_stream = None;
        self.pending_trace_column_bytes.fill(0);
        self.pending_trace_column_bytes.clear();
        for column in &mut self.ordered_trace_columns {
            column.fill(ProofBaseFieldElement::ZERO);
        }
        self.ordered_trace_columns.clear();
        self.refused = true;
    }
}
