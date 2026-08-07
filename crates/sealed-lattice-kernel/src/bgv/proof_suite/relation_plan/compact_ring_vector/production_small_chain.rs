use std::collections::BTreeMap;

use p3_field::PrimeCharacteristicRing;
use zeroize::Zeroizing;

use super::super::authenticated_assignment::{
    CompactAuthenticatedAssignmentCatalog, CompactAuthenticatedAssignmentCursor,
    CompactAuthenticatedAssignmentPoll, CompactLookupInverseMaterializationPoll,
};
use super::super::{
    derive_compact_public_key_relation_catalog, selected_input_and_context,
    CompactPublicKeyRelationCatalog, CompactRingVectorReference, CompactStructuredLinearTerm,
};
use super::*;
use crate::bgv::proof_suite::prover::{
    CommonProofAuthenticatedSourceReadRequest, CommonProofProverError, CommonProofSourcePolynomial,
    CommonProofSourcePolynomialProvider, CommonProofSourcePolynomialProviderPoll,
    CommonProofSourcePolynomialReplayIdentity, CommonProofSourcePolynomialRequest,
    CommonProofSourcePolynomialRequestContext, CommonProofSourceProviderMemoryAccounting,
    ProvidedCommonProofSourcePolynomial,
};
use crate::bgv::proof_suite::relation_plan::{
    compile_public_key_share_relation_with_source_layout, RelationPlanVariant,
};
use crate::bgv::proof_suite::{
    compact_cfw::{
        compact_challenge_from_production, compact_challenge_to_production,
        verify_compact_cfw_transcript, CompactCfwError, CompactCfwGeometry, CompactCfwMaskMaterial,
        CompactCfwMatrixRole, CompactCfwR1csMatrices, CompactCfwTranscript, CompactChallengeField,
        PreparedCompactCfwProver, COMPACT_CFW_MATRIX_COUNT,
    },
    compact_cfw_external_prover::{CompactCfwExternalProverState, CompactCfwExternalRowSource},
    compact_proof_wire::{
        decode_compact_proof_wire, decode_compact_public_input, encode_compact_proof_wire,
        encode_compact_public_input, CompactProofResponseWireGeometry,
        CompactProofResponseWireInput, CompactProofWireGeometry, CompactProofWireInput,
        CompactPublicInputBindings, CompactPublicInputWireGeometry,
        COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH, PROOF_FIXED_HEADER_BYTE_LENGTH,
    },
    compact_response_merkle::{
        verify_decoded_compact_response_opening, CompactResponseComponentGeometry,
        CompactResponseLeafValue, CompactResponseLeafValueKind, CompactResponseMerkleGeometry,
        CompactResponsePostorderMerkleWriter, CompactResponseQuerySelection,
    },
    compact_transcript::{derive_compact_fiat_shamir_verifier_message, CompactProverTranscript},
    external_memory::tests::TestStorage,
    fixed_uniform_verifier_message::{
        DecodedFixedUniformVerifierMessage, FixedUniformVerifierMessageGeometry,
    },
    ProofBaseFieldElement, ProofChallengeExtensionElement,
    COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH, PROOF_BASE_FIELD_MODULUS,
};
use crate::foundation::{Hash512, ProofApplicationSlotCeilings};

const SMALL_CHAIN_RING_DEGREE: u64 = 2_048;

enum OwnedResponseLeaf {
    Base(Vec<ProofBaseFieldElement>),
    Extension(Vec<ProofChallengeExtensionElement>),
}

impl OwnedResponseLeaf {
    fn value_kind(&self) -> CompactResponseLeafValueKind {
        match self {
            Self::Base(_) => CompactResponseLeafValueKind::BaseField,
            Self::Extension(_) => CompactResponseLeafValueKind::ExtensionField,
        }
    }

    fn field_element_count(&self) -> u64 {
        match self {
            Self::Base(values) => u64::try_from(values.len()).expect("base leaf length fits u64"),
            Self::Extension(values) => {
                u64::try_from(values.len()).expect("extension leaf length fits u64")
            }
        }
    }

    fn borrowed(&self) -> CompactResponseLeafValue<'_> {
        match self {
            Self::Base(values) => CompactResponseLeafValue::BaseField(values),
            Self::Extension(values) => CompactResponseLeafValue::ExtensionField(values),
        }
    }
}

struct BuiltResponse {
    root: [u8; Hash512::BYTE_LENGTH],
    fiat_shamir_round_salt: [u8; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH],
    wire_input: CompactProofResponseWireInput,
    merkle_geometry: CompactResponseMerkleGeometry,
    query_leaf_ordinals: Vec<u64>,
    retained_tree_bytes: Vec<u8>,
}

fn response_wire_geometry(
    response_ordinal: u32,
    base_field_element_count: u64,
    extension_field_element_count: u64,
    leaf_count: u64,
    verifier_message_geometry: FixedUniformVerifierMessageGeometry,
) -> CompactProofResponseWireGeometry {
    CompactProofResponseWireGeometry::new(
        response_ordinal,
        base_field_element_count,
        extension_field_element_count,
        leaf_count,
        0,
        verifier_message_geometry,
    )
    .expect("small-chain response wire geometry is valid")
}

fn build_response(response_ordinal: u32, leaves: Vec<OwnedResponseLeaf>) -> BuiltResponse {
    assert!(!leaves.is_empty());
    assert!(leaves.len().is_power_of_two());
    let components = leaves
        .iter()
        .enumerate()
        .map(|(leaf_ordinal, leaf)| {
            CompactResponseComponentGeometry::new(
                u64::try_from(leaf_ordinal).expect("leaf ordinal fits u64"),
                1,
                1,
                CompactResponseQuerySelection::EveryLeaf,
                leaf.value_kind(),
                leaf.field_element_count(),
            )
        })
        .collect::<Vec<_>>();
    let merkle_geometry = CompactResponseMerkleGeometry::new(response_ordinal, components)
        .expect("small-chain response Merkle geometry is valid");
    let leaf_salts = (0..leaves.len())
        .map(|leaf_ordinal| small_chain_leaf_salt(response_ordinal, leaf_ordinal))
        .collect::<Vec<_>>();
    let mut writer = CompactResponsePostorderMerkleWriter::new(&merkle_geometry)
        .expect("small-chain retained tree writer starts");
    let mut retained_tree_bytes = Vec::new();
    for (leaf, leaf_salt) in leaves.iter().zip(&leaf_salts) {
        writer
            .absorb_leaf(leaf.borrowed(), leaf_salt)
            .expect("small-chain retained tree accepts a canonical leaf");
        while let Some(output_chunk) = writer.output_chunk().map(<[u8]>::to_vec) {
            retained_tree_bytes.extend_from_slice(&output_chunk);
            writer
                .acknowledge_output_chunk()
                .expect("small-chain retained tree chunk is acknowledged");
        }
    }
    let root = writer
        .finish()
        .expect("small-chain retained response tree finishes");
    assert_eq!(retained_tree_bytes.last_chunk::<64>(), Some(&root));
    let mut base_field_values = Vec::new();
    let mut extension_field_values = Vec::new();
    for leaf in leaves {
        match leaf {
            OwnedResponseLeaf::Base(values) => base_field_values.extend(values),
            OwnedResponseLeaf::Extension(values) => extension_field_values.extend(values),
        }
    }
    let fiat_shamir_round_salt = small_chain_round_salt(response_ordinal);
    let query_leaf_ordinals = (0..leaf_salts.len())
        .map(|ordinal| u64::try_from(ordinal).expect("query ordinal fits u64"))
        .collect();
    let wire_input = CompactProofResponseWireInput::new(
        root,
        fiat_shamir_round_salt,
        base_field_values,
        extension_field_values,
        leaf_salts,
        Vec::new(),
    );
    BuiltResponse {
        root,
        fiat_shamir_round_salt,
        wire_input,
        merkle_geometry,
        query_leaf_ordinals,
        retained_tree_bytes,
    }
}

fn small_chain_leaf_salt(
    response_ordinal: u32,
    leaf_ordinal: usize,
) -> [u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH] {
    let mut salt = [0xa5_u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH];
    salt[..4].copy_from_slice(&response_ordinal.to_le_bytes());
    salt[4..12].copy_from_slice(
        &u64::try_from(leaf_ordinal)
            .expect("leaf ordinal fits u64")
            .to_le_bytes(),
    );
    salt
}

fn small_chain_round_salt(
    response_ordinal: u32,
) -> [u8; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH] {
    let mut salt = [0x5a_u8; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH];
    salt[..4].copy_from_slice(&response_ordinal.to_le_bytes());
    salt
}

fn digest_base_field_elements(digest: [u8; Hash512::BYTE_LENGTH]) -> Vec<ProofBaseFieldElement> {
    digest
        .chunks_exact(4)
        .map(|chunk| {
            ProofBaseFieldElement::from_canonical(u64::from(u32::from_le_bytes(
                chunk.try_into().expect("digest chunk has four bytes"),
            )))
            .expect("32-bit digest limb is a canonical base-field element")
        })
        .collect()
}

fn compact_challenges(message: &DecodedFixedUniformVerifierMessage) -> Vec<CompactChallengeField> {
    message
        .extension_elements()
        .iter()
        .copied()
        .map(compact_challenge_from_production)
        .collect()
}

fn small_chain_proof_wire_geometry(cfw_geometry: CompactCfwGeometry) -> CompactProofWireGeometry {
    let mut responses = Vec::new();
    responses.push(response_wire_geometry(
        0,
        16,
        0,
        1,
        FixedUniformVerifierMessageGeometry::new(1, PROOF_BASE_FIELD_MODULUS, 0, Vec::new())
            .expect("lookup challenge message geometry"),
    ));
    let committed_mask_element_count = 1_u64
        + u64::try_from(cfw_geometry.inner_mask_count() * 4)
            .expect("inner mask element count fits u64")
        + u64::try_from(cfw_geometry.outer_mask_count() * 8)
            .expect("outer mask element count fits u64");
    responses.push(response_wire_geometry(
        1,
        16,
        committed_mask_element_count,
        2,
        FixedUniformVerifierMessageGeometry::new(
            u64::try_from(cfw_geometry.sumcheck_round_count() + 1)
                .expect("CFW initial challenge count fits u64"),
            0,
            0,
            Vec::new(),
        )
        .expect("CFW initial verifier message geometry"),
    ));
    for round_ordinal in 0..cfw_geometry.sumcheck_round_count() {
        let response_ordinal =
            u32::try_from(round_ordinal + 2).expect("CFW response ordinal fits u32");
        responses.push(response_wire_geometry(
            response_ordinal,
            0,
            8,
            1,
            FixedUniformVerifierMessageGeometry::new(1, 0, 0, Vec::new())
                .expect("CFW round verifier message geometry"),
        ));
    }
    let final_response_ordinal = u32::try_from(cfw_geometry.sumcheck_round_count() + 2)
        .expect("CFW final response ordinal fits u32");
    responses.push(response_wire_geometry(
        final_response_ordinal,
        0,
        u64::try_from(cfw_geometry.outer_mask_count() + COMPACT_CFW_MATRIX_COUNT)
            .expect("CFW final message count fits u64"),
        1,
        FixedUniformVerifierMessageGeometry::new(2, 0, 0, Vec::new())
            .expect("CFW final verifier message geometry"),
    ));
    CompactProofWireGeometry::new(1, responses).expect("small-chain proof wire geometry")
}

struct ProductionRowSourceResidentMatrices<'source, 'assignment> {
    row_source: &'source CompactStructuredR1csRowSource<'assignment, CompactPublicKeyAssignment>,
    public_ring_vectors_are_zero: bool,
}

impl<'source, 'assignment> ProductionRowSourceResidentMatrices<'source, 'assignment> {
    fn new(
        row_source: &'source CompactStructuredR1csRowSource<
            'assignment,
            CompactPublicKeyAssignment,
        >,
        public_input: &[CompactChallengeField],
    ) -> Result<Self, CompactCfwError> {
        if u64::try_from(public_input.len()).ok() != Some(row_source.witness_length())
            || public_input.first() != Some(&CompactChallengeField::ONE)
            || public_input[1..]
                .iter()
                .any(|value| *value != CompactChallengeField::ZERO)
        {
            return Err(CompactCfwError::InvalidMatrixSource);
        }
        Ok(Self {
            row_source,
            public_ring_vectors_are_zero: true,
        })
    }

    fn form_for_role<'row>(
        row: &'row CompactStructuredR1csRow,
        matrix_role: CompactCfwMatrixRole,
    ) -> &'row CompactStructuredLinearForm {
        match matrix_role {
            CompactCfwMatrixRole::LeftMultiplicand => &row.left,
            CompactCfwMatrixRole::RightMultiplicand => &row.right,
            CompactCfwMatrixRole::Product => &row.output,
        }
    }

    fn little_endian_boolean_weight(
        point: &[CompactChallengeField],
        boolean_ordinal: u64,
    ) -> CompactChallengeField {
        point
            .iter()
            .enumerate()
            .map(|(coordinate_ordinal, coordinate)| {
                if (boolean_ordinal >> coordinate_ordinal) & 1 == 0 {
                    CompactChallengeField::ONE - *coordinate
                } else {
                    *coordinate
                }
            })
            .product()
    }

    fn public_form_contribution(
        &self,
        form: &CompactStructuredLinearForm,
        public_input: &[CompactChallengeField],
    ) -> Result<CompactChallengeField, CompactCfwError> {
        let public_input_length = self.row_source.matrices.public_input_length;
        let lookup_challenge =
            compact_challenge_from_production(self.row_source.assignment.lookup_challenge());
        let mut contribution = CompactChallengeField::ZERO;
        for term in &form.ordered_terms {
            match *term {
                CompactStructuredMatrixTerm::StaticEntry {
                    column_ordinal,
                    integer_coefficient,
                } if column_ordinal < public_input_length => {
                    contribution += public_input[column_ordinal as usize]
                        * compact_challenge_from_production(
                            ProofChallengeExtensionElement::from_base(
                                base_element_from_signed_integer(integer_coefficient)
                                    .map_err(|_| CompactCfwError::InvalidMatrixSource)?,
                            ),
                        );
                }
                CompactStructuredMatrixTerm::LookupChallengeEntry { column_ordinal }
                    if column_ordinal < public_input_length =>
                {
                    contribution += public_input[column_ordinal as usize] * lookup_challenge;
                }
                CompactStructuredMatrixTerm::UniformStaticRange {
                    first_column_ordinal,
                    element_count,
                    integer_coefficient,
                } => {
                    let range_end = first_column_ordinal
                        .checked_add(element_count)
                        .ok_or(CompactCfwError::CountOverflow)?;
                    let public_range_end = range_end.min(public_input_length);
                    if first_column_ordinal < public_range_end {
                        let coefficient = compact_challenge_from_production(
                            ProofChallengeExtensionElement::from_base(
                                base_element_from_signed_integer(integer_coefficient)
                                    .map_err(|_| CompactCfwError::InvalidMatrixSource)?,
                            ),
                        );
                        for column_ordinal in first_column_ordinal..public_range_end {
                            contribution += public_input[column_ordinal as usize] * coefficient;
                        }
                    }
                }
                CompactStructuredMatrixTerm::NegatedLookupTableReciprocalRange {
                    first_column_ordinal,
                    ..
                } if first_column_ordinal < public_input_length => {
                    return Err(CompactCfwError::InvalidMatrixSource);
                }
                CompactStructuredMatrixTerm::PublicNegacyclicMatrixBand { .. } => {
                    if !self.public_ring_vectors_are_zero {
                        return Err(CompactCfwError::InvalidMatrixSource);
                    }
                }
                _ => {}
            }
        }
        Ok(contribution)
    }

    fn accumulate_witness_form(
        &self,
        form: &CompactStructuredLinearForm,
        row_weight: CompactChallengeField,
        matrix_role_weight: CompactChallengeField,
        destination: &mut [CompactChallengeField],
    ) -> Result<(), CompactCfwError> {
        let public_input_length = self.row_source.matrices.public_input_length;
        let matrix_dimension = self.row_source.matrices.matrix_dimension;
        let weighted_row = row_weight * matrix_role_weight;
        for term in &form.ordered_terms {
            match *term {
                CompactStructuredMatrixTerm::StaticEntry {
                    column_ordinal,
                    integer_coefficient,
                } if column_ordinal >= public_input_length => {
                    add_witness_covector_entry(
                        destination,
                        public_input_length,
                        matrix_dimension,
                        column_ordinal,
                        weighted_row
                            * compact_challenge_from_production(
                                ProofChallengeExtensionElement::from_base(
                                    base_element_from_signed_integer(integer_coefficient)
                                        .map_err(|_| CompactCfwError::InvalidMatrixSource)?,
                                ),
                            ),
                    )?;
                }
                CompactStructuredMatrixTerm::LookupChallengeEntry { column_ordinal }
                    if column_ordinal >= public_input_length =>
                {
                    add_witness_covector_entry(
                        destination,
                        public_input_length,
                        matrix_dimension,
                        column_ordinal,
                        weighted_row
                            * compact_challenge_from_production(
                                self.row_source.assignment.lookup_challenge(),
                            ),
                    )?;
                }
                CompactStructuredMatrixTerm::UniformStaticRange {
                    first_column_ordinal,
                    element_count,
                    integer_coefficient,
                } => {
                    let range_end = first_column_ordinal
                        .checked_add(element_count)
                        .ok_or(CompactCfwError::CountOverflow)?;
                    let first_witness_column = first_column_ordinal.max(public_input_length);
                    let coefficient = weighted_row
                        * compact_challenge_from_production(
                            ProofChallengeExtensionElement::from_base(
                                base_element_from_signed_integer(integer_coefficient)
                                    .map_err(|_| CompactCfwError::InvalidMatrixSource)?,
                            ),
                        );
                    for column_ordinal in first_witness_column..range_end {
                        add_witness_covector_entry(
                            destination,
                            public_input_length,
                            matrix_dimension,
                            column_ordinal,
                            coefficient,
                        )?;
                    }
                }
                CompactStructuredMatrixTerm::NegatedLookupTableReciprocalRange {
                    first_column_ordinal,
                    table_value_count,
                } => {
                    if first_column_ordinal < public_input_length {
                        return Err(CompactCfwError::InvalidMatrixSource);
                    }
                    for table_value in 0..table_value_count {
                        let denominator = self.row_source.assignment.lookup_challenge().add(
                            ProofChallengeExtensionElement::from_base(
                                ProofBaseFieldElement::from_canonical(table_value)
                                    .map_err(|_| CompactCfwError::InvalidMatrixSource)?,
                            ),
                        );
                        let reciprocal = denominator
                            .inverse()
                            .map_err(|_| CompactCfwError::InvalidMatrixSource)?
                            .negate();
                        add_witness_covector_entry(
                            destination,
                            public_input_length,
                            matrix_dimension,
                            first_column_ordinal
                                .checked_add(table_value)
                                .ok_or(CompactCfwError::CountOverflow)?,
                            weighted_row * compact_challenge_from_production(reciprocal),
                        )?;
                    }
                }
                CompactStructuredMatrixTerm::PublicNegacyclicMatrixBand { .. } => {
                    if !self.public_ring_vectors_are_zero {
                        return Err(CompactCfwError::InvalidMatrixSource);
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}

impl CompactCfwR1csMatrices for ProductionRowSourceResidentMatrices<'_, '_> {
    fn witness_length(&self) -> usize {
        usize::try_from(self.row_source.witness_length())
            .expect("small-chain witness length fits usize")
    }

    fn evaluate_assignment_rows(
        &self,
        matrix_role: CompactCfwMatrixRole,
        public_input: &[CompactChallengeField],
        witness: &[CompactChallengeField],
    ) -> Result<Vec<CompactChallengeField>, CompactCfwError> {
        if public_input.len() != self.witness_length() || witness.len() != self.witness_length() {
            return Err(CompactCfwError::InvalidMatrixSource);
        }
        let row_count = usize::try_from(self.row_source.row_count())
            .map_err(|_| CompactCfwError::CountOverflow)?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(row_count)
            .map_err(|_| CompactCfwError::AllocationLimitExceeded)?;
        for row_ordinal in 0..row_count {
            let evaluation = self
                .row_source
                .evaluate_row(
                    u64::try_from(row_ordinal).map_err(|_| CompactCfwError::CountOverflow)?,
                )
                .map_err(|_| CompactCfwError::InvalidMatrixSource)?;
            rows.push(compact_challenge_from_production(match matrix_role {
                CompactCfwMatrixRole::LeftMultiplicand => evaluation.left,
                CompactCfwMatrixRole::RightMultiplicand => evaluation.right,
                CompactCfwMatrixRole::Product => evaluation.output,
            }));
        }
        Ok(rows)
    }

    fn public_contribution_at_row_point(
        &self,
        matrix_role: CompactCfwMatrixRole,
        row_point: &[CompactChallengeField],
        public_input: &[CompactChallengeField],
    ) -> Result<CompactChallengeField, CompactCfwError> {
        if row_point.len() != self.row_source.row_count().ilog2() as usize
            || public_input.len() != self.witness_length()
        {
            return Err(CompactCfwError::InvalidMatrixSource);
        }
        let mut result = CompactChallengeField::ZERO;
        for row_ordinal in 0..self.row_source.row_count() {
            let row = self
                .row_source
                .matrices
                .row(self.row_source.relation, row_ordinal)
                .map_err(|_| CompactCfwError::InvalidMatrixSource)?;
            let row_weight = Self::little_endian_boolean_weight(row_point, row_ordinal);
            result += row_weight
                * self.public_form_contribution(
                    Self::form_for_role(&row, matrix_role),
                    public_input,
                )?;
        }
        Ok(result)
    }

    fn accumulate_weighted_witness_covector_at_row_point(
        &self,
        row_point: &[CompactChallengeField],
        matrix_role_weights: [CompactChallengeField; COMPACT_CFW_MATRIX_COUNT],
        destination: &mut [CompactChallengeField],
    ) -> Result<(), CompactCfwError> {
        if row_point.len() != self.row_source.row_count().ilog2() as usize
            || destination.len() != self.witness_length()
        {
            return Err(CompactCfwError::InvalidMatrixSource);
        }
        for row_ordinal in 0..self.row_source.row_count() {
            let row = self
                .row_source
                .matrices
                .row(self.row_source.relation, row_ordinal)
                .map_err(|_| CompactCfwError::InvalidMatrixSource)?;
            let row_weight = Self::little_endian_boolean_weight(row_point, row_ordinal);
            for matrix_role in CompactCfwMatrixRole::ALL {
                self.accumulate_witness_form(
                    Self::form_for_role(&row, matrix_role),
                    row_weight,
                    matrix_role_weights[matrix_role.ordinal()],
                    destination,
                )?;
            }
        }
        Ok(())
    }
}

fn add_witness_covector_entry(
    destination: &mut [CompactChallengeField],
    public_input_length: u64,
    matrix_dimension: u64,
    column_ordinal: u64,
    contribution: CompactChallengeField,
) -> Result<(), CompactCfwError> {
    if column_ordinal < public_input_length || column_ordinal >= matrix_dimension {
        return Err(CompactCfwError::InvalidMatrixSource);
    }
    let destination_ordinal = usize::try_from(column_ordinal - public_input_length)
        .map_err(|_| CompactCfwError::CountOverflow)?;
    *destination
        .get_mut(destination_ordinal)
        .ok_or(CompactCfwError::InvalidMatrixSource)? += contribution;
    Ok(())
}

struct AuthenticatedConstantSourceProvider {
    relation_plan_variant: RelationPlanVariant,
    request_context: CommonProofSourcePolynomialRequestContext,
    ordered_source_column_ordinals: Vec<u32>,
    canonical_values: BTreeMap<u32, u64>,
    next_source_index: usize,
    pending_authenticated_read: Option<CommonProofAuthenticatedSourceReadRequest>,
    first_authenticated_read_supplied: bool,
    finished: bool,
}

impl AuthenticatedConstantSourceProvider {
    fn new(
        relation: &CompactPublicKeyRelationCatalog,
        relation_plan_variant: RelationPlanVariant,
        request_context: CommonProofSourcePolynomialRequestContext,
    ) -> Result<Self, CommonProofProverError> {
        let assignment_catalog =
            CompactAuthenticatedAssignmentCatalog::derive(relation, &relation_plan_variant)?;
        let ordered_source_column_ordinals = assignment_catalog.source_column_ordinals();
        let mut canonical_values = BTreeMap::new();
        for vector in &relation.ordered_public_vectors {
            insert_vector_source_value(&mut canonical_values, *vector, 0)?;
        }
        for compact_relation in &relation.ordered_relations {
            for term in &compact_relation.ordered_terms {
                if let CompactStructuredLinearTerm::ModulusQuotient {
                    quotient_vector, ..
                } = term
                {
                    insert_vector_source_value(&mut canonical_values, *quotient_vector, 0)?;
                }
            }
        }
        for descriptor in &relation.ordered_private_small_vectors {
            insert_vector_source_value(
                &mut canonical_values,
                descriptor.vector,
                descriptor.centered_offset,
            )?;
        }
        if canonical_values.keys().copied().collect::<Vec<_>>() != ordered_source_column_ordinals {
            return Err(CommonProofProverError::InvalidColumn);
        }
        Ok(Self {
            relation_plan_variant,
            request_context,
            ordered_source_column_ordinals,
            canonical_values,
            next_source_index: 0,
            pending_authenticated_read: None,
            first_authenticated_read_supplied: false,
            finished: false,
        })
    }

    fn validate_request(
        &self,
        request: CommonProofSourcePolynomialRequest<'_>,
    ) -> Result<(u32, u64), CommonProofProverError> {
        let expected_column_ordinal = *self
            .ordered_source_column_ordinals
            .get(self.next_source_index)
            .ok_or(CommonProofProverError::InvalidColumn)?;
        if self.finished
            || request.request_context() != self.request_context
            || request.column_ordinal() != expected_column_ordinal
            || self.relation_plan_variant.ordered_columns().get(
                usize::try_from(expected_column_ordinal)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            ) != Some(request.descriptor())
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let canonical_value = *self
            .canonical_values
            .get(&expected_column_ordinal)
            .ok_or(CommonProofProverError::InvalidColumn)?;
        Ok((expected_column_ordinal, canonical_value))
    }
}

impl CommonProofSourcePolynomialProvider for AuthenticatedConstantSourceProvider {
    fn memory_accounting(
        &self,
    ) -> Result<CommonProofSourceProviderMemoryAccounting, CommonProofProverError> {
        Ok(CommonProofSourceProviderMemoryAccounting::new(1, 1, 8, 8))
    }

    fn poll_source_polynomial(
        &mut self,
        request: CommonProofSourcePolynomialRequest<'_>,
    ) -> Result<CommonProofSourcePolynomialProviderPoll, CommonProofProverError> {
        let (column_ordinal, canonical_value) = self.validate_request(request)?;
        if self.next_source_index == 0 && !self.first_authenticated_read_supplied {
            if self.pending_authenticated_read.is_none() {
                self.pending_authenticated_read = Some(
                    CommonProofAuthenticatedSourceReadRequest::from_authenticated_source(
                        request,
                        [11_u8; 64],
                        [12_u8; 64],
                        [13_u8; 64],
                        [14_u8; 64],
                        8,
                        0,
                        0,
                        8,
                        0,
                    )?,
                );
            }
            return Ok(CommonProofSourcePolynomialProviderPoll::AuthenticatedSourceReadRequired);
        }
        let replay_identity = CommonProofSourcePolynomialReplayIdentity::from_authenticated_source(
            crate::hashing::hash_framed_parts_512(
                "sealed-lattice/test/production-small-chain-source/v1",
                &[
                    &column_ordinal.to_le_bytes(),
                    &canonical_value.to_le_bytes(),
                ],
            ),
        )?;
        self.next_source_index = self
            .next_source_index
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        Ok(CommonProofSourcePolynomialProviderPoll::Ready(
            ProvidedCommonProofSourcePolynomial::new(
                CommonProofSourcePolynomial::from_base_coefficients(vec![
                    ProofBaseFieldElement::from_canonical(canonical_value)?,
                ]),
                replay_identity,
            ),
        ))
    }

    fn poll_replayed_source_polynomial(
        &mut self,
        _request: CommonProofSourcePolynomialRequest<'_>,
    ) -> Result<CommonProofSourcePolynomialProviderPoll, CommonProofProverError> {
        Err(CommonProofProverError::InvalidColumn)
    }

    fn pending_authenticated_source_read_request(
        &self,
    ) -> Result<Option<CommonProofAuthenticatedSourceReadRequest>, CommonProofProverError> {
        Ok(self.pending_authenticated_read)
    }

    fn supply_authenticated_source_range(
        &mut self,
        request: CommonProofAuthenticatedSourceReadRequest,
        authenticated_bytes: Zeroizing<Box<[u8]>>,
    ) -> Result<(), CommonProofProverError> {
        if self.pending_authenticated_read != Some(request)
            || authenticated_bytes.as_ref() != [0xa5_u8; 8]
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        self.pending_authenticated_read = None;
        self.first_authenticated_read_supplied = true;
        Ok(())
    }

    fn cancel_pending_authenticated_source_read(&mut self) {
        self.pending_authenticated_read = None;
    }

    fn finish(&mut self) -> Result<(), CommonProofProverError> {
        if self.finished
            || self.pending_authenticated_read.is_some()
            || self.next_source_index != self.ordered_source_column_ordinals.len()
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        self.finished = true;
        Ok(())
    }
}

fn insert_vector_source_value(
    values: &mut BTreeMap<u32, u64>,
    vector: CompactRingVectorReference,
    canonical_value: u64,
) -> Result<(), CommonProofProverError> {
    for column_ordinal in vector.column_ordinals {
        match values.insert(column_ordinal, canonical_value) {
            None => {}
            Some(previous_value) if previous_value == canonical_value => {}
            Some(_) => return Err(CommonProofProverError::InvalidColumn),
        }
    }
    Ok(())
}

fn reduced_relation() -> (
    CompactPublicKeyRelationCatalog,
    RelationPlanVariant,
    CompactAuthenticatedAssignmentCatalog,
) {
    let (mut input, context) = selected_input_and_context().expect("selected relation inputs");
    input.ring_degree = SMALL_CHAIN_RING_DEGREE;
    input.public_polynomial_column_degree_bound_exclusive = SMALL_CHAIN_RING_DEGREE / 2;
    let compiled = compile_public_key_share_relation_with_source_layout(&input, &context)
        .expect("reduced production-family relation compiles");
    compiled
        .relation_plan
        .check(&context)
        .expect("reduced relation plan checks");
    let relation_plan_variant = compiled
        .relation_plan
        .select_variant(None, None)
        .expect("reduced relation variant")
        .clone();
    let relation = derive_compact_public_key_relation_catalog(
        &input,
        &relation_plan_variant,
        &compiled.source_layout,
    )
    .expect("reduced compact relation derives");
    let assignment_catalog =
        CompactAuthenticatedAssignmentCatalog::derive(&relation, &relation_plan_variant)
            .expect("reduced authenticated assignment derives");
    (relation, relation_plan_variant, assignment_catalog)
}

fn request_context(
    relation: &CompactPublicKeyRelationCatalog,
) -> CommonProofSourcePolynomialRequestContext {
    CommonProofSourcePolynomialRequestContext::new(
        1,
        [2_u8; 64],
        ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        [3_u8; 64],
        [4_u8; 64],
        relation.relation_plan_hash(),
        None,
        None,
    )
}

#[test]
fn production_small_chain_reconciles_authenticated_cfw_transcript_and_structured_handoff() {
    let (relation, relation_plan_variant, assignment_catalog) = reduced_relation();
    assert_eq!(relation.ring_degree(), SMALL_CHAIN_RING_DEGREE);
    assert_eq!(relation.public_key_share_relation_count(), 23);
    assert_eq!(relation.ordinary_anchor_relation_count(), 3);
    assert_eq!(relation.final_anchor_relation_count(), 3);
    assert_eq!(relation.quotient_vector_count(), 29);
    assert_eq!(relation.public_input_ring_vector_count(), 61);
    assert_eq!(relation.quotient_lookup_table_ring_vector_count(), 64);
    assert_eq!(relation.witness_ring_vector_count(), 146);
    assert_eq!(relation.padded_witness_element_count(), 524_288);
    assert_eq!(relation.operative_constraint_count(), 167_937);
    assert_eq!(relation.padded_constraint_count(), 1_048_576);
    let cross_epoch_copy = relation
        .cross_epoch_copy_geometry()
        .expect("reduced two-epoch copy geometry");
    assert_eq!(cross_epoch_copy.copied_ring_vector_count(), 93);
    assert_eq!(cross_epoch_copy.copied_element_count(), 190_464);
    assert_eq!(
        cross_epoch_copy.pre_challenge_message_element_count(),
        262_144
    );
    assert_eq!(cross_epoch_copy.main_message_element_count(), 524_288);
    assert_eq!(cross_epoch_copy.point_coordinate_count(), 18);
    assert_eq!(assignment_catalog.source_column_ordinals().len(), 202);

    let request_context = request_context(&relation);
    let mut source_provider = AuthenticatedConstantSourceProvider::new(
        &relation,
        relation_plan_variant.clone(),
        request_context,
    )
    .expect("authenticated source provider derives from the reduced relation");
    let mut assignment_cursor = CompactAuthenticatedAssignmentCursor::new(
        &relation,
        &relation_plan_variant,
        request_context,
    )
    .expect("authenticated assignment loading starts");
    assert!(matches!(
        assignment_cursor
            .next_source(&relation, &relation_plan_variant, &mut source_provider,)
            .expect("first source requests authenticated bytes"),
        CompactAuthenticatedAssignmentPoll::AuthenticatedSourceReadRequired,
    ));
    let authenticated_read = source_provider
        .pending_authenticated_source_read_request()
        .expect("authenticated read state")
        .expect("authenticated read request");
    source_provider
        .supply_authenticated_source_range(
            authenticated_read,
            Zeroizing::new(vec![0xa5_u8; 8].into_boxed_slice()),
        )
        .expect("authenticated source bytes bind the first read");

    let mut loaded_source_count = 0_usize;
    loop {
        match assignment_cursor
            .next_source(&relation, &relation_plan_variant, &mut source_provider)
            .expect("authenticated source loading advances")
        {
            CompactAuthenticatedAssignmentPoll::AuthenticatedSourceReadRequired => {
                panic!("the authenticated source range was already supplied")
            }
            CompactAuthenticatedAssignmentPoll::SourceLoaded { .. } => {
                loaded_source_count += 1;
            }
            CompactAuthenticatedAssignmentPoll::Complete => break,
        }
    }
    assert_eq!(loaded_source_count, 202);
    let base_assignment = assignment_cursor
        .finish(&relation, &relation_plan_variant)
        .expect("authenticated assignment loading finishes");
    assert_ne!(base_assignment.source_replay_binding(), [0_u8; 64]);
    let source_replay_binding = base_assignment.source_replay_binding();
    let cfw_geometry = CompactCfwGeometry::derive(
        usize::try_from(relation.padded_witness_element_count())
            .expect("small-chain witness length fits usize"),
    )
    .expect("small-chain CFW geometry derives");
    assert_eq!(cfw_geometry.sumcheck_round_count(), 20);
    let proof_wire_geometry = small_chain_proof_wire_geometry(cfw_geometry);
    let public_input_wire_geometry = CompactPublicInputWireGeometry::new(
        1,
        relation.public_input_ring_vector_count(),
        relation.ring_degree(),
    )
    .expect("small-chain public-input wire geometry");
    let public_input_field_elements =
        (0..u64::from(public_input_wire_geometry.field_element_count()))
            .map(|element_ordinal| {
                base_assignment
                    .public_input_base_value(element_ordinal + 1)
                    .expect("small-chain public ring-vector coefficient")
            })
            .collect::<Vec<_>>();
    let public_input_bindings = CompactPublicInputBindings::new(
        Hash512::from_bytes([0x21_u8; 64]),
        Hash512::from_bytes([0x22_u8; 64]),
        Hash512::from_bytes([0x23_u8; 64]),
        Hash512::from_bytes(relation.relation_plan_hash()),
    );
    let canonical_public_input_bytes = encode_compact_public_input(
        public_input_wire_geometry,
        public_input_bindings,
        &public_input_field_elements,
    )
    .expect("small-chain public input encodes canonically");
    let decoded_public_input = decode_compact_public_input(
        public_input_wire_geometry,
        public_input_bindings,
        &canonical_public_input_bytes,
    )
    .expect("fresh small-chain public-input decoder accepts transported bytes");
    let mut prover_transcript = CompactProverTranscript::new(
        &proof_wire_geometry,
        &decoded_public_input,
        &canonical_public_input_bytes,
    )
    .expect("small-chain compact transcript starts");
    let mut built_responses = Vec::with_capacity(proof_wire_geometry.responses().len());
    let mut prover_verifier_messages = Vec::with_capacity(proof_wire_geometry.responses().len());
    let source_response = build_response(
        0,
        vec![OwnedResponseLeaf::Base(digest_base_field_elements(
            source_replay_binding,
        ))],
    );
    prover_transcript
        .record_response_commitment(source_response.root, source_response.fiat_shamir_round_salt)
        .expect("authenticated source response enters the transcript");
    let lookup_message = prover_transcript
        .derive_verifier_message()
        .expect("lookup challenge derives from the committed source response");
    let [lookup_challenge] = lookup_message.extension_elements() else {
        panic!("lookup transcript move must contain one extension challenge")
    };
    assert!(lookup_challenge.canonical_coordinates()[1..]
        .iter()
        .any(|coordinate| *coordinate != 0));
    let lookup_challenge = *lookup_challenge;
    prover_verifier_messages.push(lookup_message);
    built_responses.push(source_response);
    let mut lookup_materializer = base_assignment
        .begin_lookup_inverse_materialization(lookup_challenge)
        .expect("lookup inverse materialization starts");
    loop {
        match lookup_materializer
            .advance(8_192)
            .expect("lookup inverse materialization advances")
        {
            CompactLookupInverseMaterializationPoll::ArithmeticStepCompleted {
                processed_element_count,
            } => assert!((1..=8_192).contains(&processed_element_count)),
            CompactLookupInverseMaterializationPoll::Complete => break,
        }
    }
    let assignment = lookup_materializer
        .finish()
        .expect("lookup inverse materialization finishes");
    assert_eq!(
        assignment.memory_geometry().padded_witness_element_count(),
        524_288
    );

    let mut preparation = CompactStructuredR1csRowSourcePreparation::new(&relation, &assignment)
        .expect("structured row-source preparation starts");
    let row_source = loop {
        match preparation
            .advance(8_192)
            .expect("structured row-source preparation advances")
        {
            CompactStructuredR1csRowSourcePreparationPoll::StepCompleted {
                completed_work_unit_count,
                ..
            } => assert!(completed_work_unit_count > 0),
            CompactStructuredR1csRowSourcePreparationPoll::Complete(row_source) => {
                break row_source;
            }
        }
    };
    assert_eq!(row_source.witness_length(), 524_288);
    assert_eq!(row_source.row_count(), 1_048_576);
    for row_ordinal in [
        0,
        relation.operative_constraint_count() - 1,
        relation.operative_constraint_count(),
        relation.padded_constraint_count() - 1,
    ] {
        let evaluation = row_source
            .evaluate_row(row_ordinal)
            .expect("production-family row evaluates");
        assert_eq!(
            evaluation.left.multiply(evaluation.right),
            evaluation.output
        );
    }
    assert_eq!(
        CompactCfwExternalRowSource::witness_length(&row_source)
            .expect("row source exposes CFW witness geometry"),
        524_288
    );

    let witness_length = usize::try_from(row_source.witness_length())
        .expect("small-chain witness length fits usize");
    let public_input = (0..witness_length)
        .map(|element_ordinal| {
            assignment
                .public_input_value(
                    u64::try_from(element_ordinal).expect("public ordinal fits u64"),
                )
                .map(compact_challenge_from_production)
                .expect("small-chain public input value")
        })
        .collect::<Vec<_>>();
    let witness = (0..witness_length)
        .map(|element_ordinal| {
            assignment
                .witness_value(u64::try_from(element_ordinal).expect("witness ordinal fits u64"))
                .map(compact_challenge_from_production)
                .expect("small-chain witness value")
        })
        .collect::<Vec<_>>();
    let resident_matrices = ProductionRowSourceResidentMatrices::new(&row_source, &public_input)
        .expect("resident matrix view binds the structured row source");
    let mut mask_seed = 10_000_u64;
    let mask_material = CompactCfwMaskMaterial::sample(cfw_geometry, || {
        mask_seed += 29;
        compact_test_challenge(mask_seed)
    })
    .expect("small-chain CFW masks derive");
    let prepared_resident = PreparedCompactCfwProver::prepare(
        &resident_matrices,
        &public_input,
        &witness,
        mask_material.clone(),
    )
    .expect("resident CFW prepares from production-family rows");
    let auxiliary_target = prepared_resident.auxiliary_target();
    let mut lookup_challenge_bytes = Vec::with_capacity(40);
    for coordinate in lookup_challenge.canonical_coordinates() {
        lookup_challenge_bytes.extend_from_slice(&coordinate.to_le_bytes());
    }
    let assignment_commitment = crate::hashing::hash_framed_parts_512(
        "sealed-lattice/test/production-small-chain-assignment/v1",
        &[
            &source_replay_binding,
            &relation.relation_plan_hash(),
            &lookup_challenge_bytes,
        ],
    );
    let mut committed_mask_values = Vec::new();
    committed_mask_values.push(
        compact_challenge_to_production(auxiliary_target)
            .expect("auxiliary target uses production field coordinates"),
    );
    for mask in mask_material.inner_masks() {
        for value in mask {
            committed_mask_values.push(
                compact_challenge_to_production(*value)
                    .expect("inner mask uses production field coordinates"),
            );
        }
    }
    for mask in mask_material.outer_masks() {
        for value in mask {
            committed_mask_values.push(
                compact_challenge_to_production(*value)
                    .expect("outer mask uses production field coordinates"),
            );
        }
    }
    let mask_response = build_response(
        1,
        vec![
            OwnedResponseLeaf::Base(digest_base_field_elements(assignment_commitment)),
            OwnedResponseLeaf::Extension(committed_mask_values),
        ],
    );
    prover_transcript
        .record_response_commitment(mask_response.root, mask_response.fiat_shamir_round_salt)
        .expect("assignment and masks enter the transcript before CFW challenges");
    let initial_cfw_message = prover_transcript
        .derive_verifier_message()
        .expect("initial CFW challenges derive from the assignment and mask commitment");
    let initial_cfw_challenges = compact_challenges(&initial_cfw_message);
    let constraint_combining_challenge = *initial_cfw_challenges
        .first()
        .expect("initial CFW message includes the combining challenge");
    let equality_point = initial_cfw_challenges[1..].to_vec();
    assert_eq!(equality_point.len(), cfw_geometry.sumcheck_round_count());
    prover_verifier_messages.push(initial_cfw_message);
    built_responses.push(mask_response);
    let mut resident_prover = prepared_resident
        .begin(constraint_combining_challenge, equality_point.clone())
        .expect("resident CFW begins");
    let mut external_prover = CompactCfwExternalProverState::prepare(
        &row_source,
        mask_material,
        constraint_combining_challenge,
        equality_point.clone(),
    )
    .expect("external CFW prepares from the same production-family rows");
    assert_eq!(external_prover.auxiliary_target(), auxiliary_target);
    let mut storage = TestStorage::default();
    let mut resident_round_polynomials = Vec::with_capacity(cfw_geometry.sumcheck_round_count());
    let mut external_round_polynomials = Vec::with_capacity(cfw_geometry.sumcheck_round_count());
    let mut round_challenges = Vec::with_capacity(cfw_geometry.sumcheck_round_count());
    for round_ordinal in 0..cfw_geometry.sumcheck_round_count() {
        let resident_round_polynomial = resident_prover
            .next_round_polynomial()
            .expect("resident CFW round polynomial");
        let external_round_polynomial = loop {
            if let Some(round_polynomial) = external_prover
                .advance_round_polynomial(&row_source, &mut storage)
                .expect("external CFW round derivation advances")
            {
                break round_polynomial;
            }
        };
        assert_eq!(external_round_polynomial, resident_round_polynomial);
        resident_round_polynomials.push(resident_round_polynomial);
        external_round_polynomials.push(external_round_polynomial);
        let round_response_ordinal =
            u32::try_from(round_ordinal + 2).expect("CFW round response ordinal fits u32");
        let round_response = build_response(
            round_response_ordinal,
            vec![OwnedResponseLeaf::Extension(
                resident_round_polynomial
                    .into_iter()
                    .map(|value| {
                        compact_challenge_to_production(value)
                            .expect("CFW round polynomial uses production field coordinates")
                    })
                    .collect(),
            )],
        );
        let external_round_response = build_response(
            round_response_ordinal,
            vec![OwnedResponseLeaf::Extension(
                external_round_polynomial
                    .into_iter()
                    .map(|value| {
                        compact_challenge_to_production(value)
                            .expect("external CFW round uses production field coordinates")
                    })
                    .collect(),
            )],
        );
        assert_eq!(external_round_response.root, round_response.root);
        assert_eq!(
            external_round_response.retained_tree_bytes,
            round_response.retained_tree_bytes
        );
        assert_eq!(
            external_round_response.wire_input,
            round_response.wire_input
        );
        prover_transcript
            .record_response_commitment(round_response.root, round_response.fiat_shamir_round_salt)
            .expect("CFW round polynomial enters the transcript");
        let round_message = prover_transcript
            .derive_verifier_message()
            .expect("CFW round challenge derives from the round commitment");
        let round_message_challenges = compact_challenges(&round_message);
        let [round_challenge] = round_message_challenges.as_slice() else {
            panic!("CFW round message must contain one challenge")
        };
        let round_challenge = *round_challenge;
        round_challenges.push(round_challenge);
        prover_verifier_messages.push(round_message);
        built_responses.push(round_response);
        resident_prover
            .bind_round_challenge(round_challenge)
            .expect("resident CFW round challenge binds");
        external_prover
            .bind_round_challenge(round_challenge)
            .expect("external CFW round challenge binds");
        while !external_prover
            .advance_bound_round(&row_source, &mut storage)
            .expect("external CFW bound round advances")
        {}
    }
    let resident_finish = resident_prover.finish().expect("resident CFW finishes");
    let external_output = external_prover.finish().expect("external CFW finishes");
    assert_eq!(external_round_polynomials, resident_round_polynomials);
    assert_eq!(
        external_output.finish().outer_evaluations(),
        resident_finish.outer_evaluations()
    );
    assert_eq!(
        external_output.finish().final_values(),
        resident_finish.final_values()
    );
    assert!(external_output.usage().total_written_byte_length() > 0);
    assert!(external_output.usage().total_read_byte_length() > 0);

    let final_response_values = resident_finish
        .outer_evaluations()
        .iter()
        .copied()
        .chain(resident_finish.final_values())
        .map(|value| {
            compact_challenge_to_production(value)
                .expect("CFW final response uses production field coordinates")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        final_response_values.len(),
        cfw_geometry.outer_mask_count() + COMPACT_CFW_MATRIX_COUNT
    );
    let final_response_ordinal =
        u32::try_from(cfw_geometry.sumcheck_round_count() + 2).expect("final ordinal fits u32");
    let final_response = build_response(
        final_response_ordinal,
        vec![OwnedResponseLeaf::Extension(final_response_values.clone())],
    );
    let external_final_response_values = external_output
        .finish()
        .outer_evaluations()
        .iter()
        .copied()
        .chain(external_output.finish().final_values())
        .map(|value| {
            compact_challenge_to_production(value)
                .expect("external CFW final response uses production field coordinates")
        })
        .collect::<Vec<_>>();
    assert_eq!(external_final_response_values, final_response_values);
    let external_final_response = build_response(
        final_response_ordinal,
        vec![OwnedResponseLeaf::Extension(external_final_response_values)],
    );
    assert_eq!(external_final_response.root, final_response.root);
    assert_eq!(
        external_final_response.retained_tree_bytes,
        final_response.retained_tree_bytes
    );
    assert_eq!(
        external_final_response.wire_input,
        final_response.wire_input
    );
    prover_transcript
        .record_response_commitment(final_response.root, final_response.fiat_shamir_round_salt)
        .expect("CFW final values enter the transcript");
    let final_verifier_message = prover_transcript
        .derive_verifier_message()
        .expect("post-CFW challenges derive from the final response");
    let final_challenges = compact_challenges(&final_verifier_message);
    let [joint_constraint_challenge, batching_challenge] = final_challenges.as_slice() else {
        panic!("post-CFW message must contain two challenges")
    };
    let joint_constraint_challenge = *joint_constraint_challenge;
    let batching_challenge = *batching_challenge;
    prover_verifier_messages.push(final_verifier_message);
    built_responses.push(final_response);
    prover_transcript
        .finish()
        .expect("small-chain compact transcript consumes every response");
    assert_eq!(built_responses.len(), proof_wire_geometry.responses().len());
    assert_eq!(
        prover_verifier_messages.len(),
        proof_wire_geometry.responses().len()
    );

    let canonical_proof_bytes = encode_compact_proof_wire(
        &proof_wire_geometry,
        &CompactProofWireInput::new(
            built_responses
                .iter()
                .map(|response| response.wire_input.clone())
                .collect(),
        ),
    )
    .expect("small-chain proof responses encode canonically");
    let decoded_proof = decode_compact_proof_wire(
        &proof_wire_geometry,
        &canonical_proof_bytes,
        canonical_proof_bytes.len(),
    )
    .expect("fresh small-chain proof decoder accepts transported bytes");
    for (response_ordinal, ((built_response, wire_geometry), decoded_response)) in built_responses
        .iter()
        .zip(proof_wire_geometry.responses())
        .zip(decoded_proof.responses())
        .enumerate()
    {
        verify_decoded_compact_response_opening(
            &built_response.merkle_geometry,
            wire_geometry,
            decoded_response,
            &canonical_proof_bytes,
            &built_response.query_leaf_ordinals,
        )
        .unwrap_or_else(|error| {
            panic!("fresh response {response_ordinal} opening verification failed: {error:?}")
        });
        let verifier_message = derive_compact_fiat_shamir_verifier_message(
            &proof_wire_geometry,
            &decoded_proof,
            &canonical_proof_bytes,
            &decoded_public_input,
            &canonical_public_input_bytes,
            u32::try_from(response_ordinal).expect("response ordinal fits u32"),
        )
        .expect("fresh verifier derives the exact response message");
        assert_eq!(
            verifier_message, prover_verifier_messages[response_ordinal],
            "transcript message mismatch at response {response_ordinal}"
        );
    }

    let mut fresh_public_input = Vec::with_capacity(witness_length);
    fresh_public_input.push(CompactChallengeField::ONE);
    for element_ordinal in 0..decoded_public_input.field_element_count() {
        fresh_public_input.push(compact_challenge_from_production(
            ProofChallengeExtensionElement::from_base(
                decoded_public_input
                    .field_element(&canonical_public_input_bytes, element_ordinal)
                    .expect("fresh public-input coefficient decodes"),
            ),
        ));
    }
    fresh_public_input.resize(witness_length, CompactChallengeField::ZERO);
    assert_eq!(fresh_public_input, public_input);

    let decoded_mask_response = &decoded_proof.responses()[1];
    let decoded_auxiliary_target = compact_challenge_from_production(
        decoded_mask_response
            .extension_field_value(&canonical_proof_bytes, 0)
            .expect("transported auxiliary target decodes"),
    );
    assert_eq!(decoded_auxiliary_target, auxiliary_target);
    let mut decoded_round_polynomials = Vec::with_capacity(cfw_geometry.sumcheck_round_count());
    for round_ordinal in 0..cfw_geometry.sumcheck_round_count() {
        let decoded_response = &decoded_proof.responses()[round_ordinal + 2];
        let mut polynomial = [CompactChallengeField::ZERO; 8];
        for (coefficient_ordinal, coefficient) in polynomial.iter_mut().enumerate() {
            *coefficient = compact_challenge_from_production(
                decoded_response
                    .extension_field_value(&canonical_proof_bytes, coefficient_ordinal)
                    .expect("transported CFW round coefficient decodes"),
            );
        }
        decoded_round_polynomials.push(polynomial);
    }
    assert_eq!(decoded_round_polynomials, resident_round_polynomials);
    let decoded_final_response = decoded_proof
        .responses()
        .last()
        .expect("transported CFW final response exists");
    let decoded_outer_evaluations = (0..cfw_geometry.outer_mask_count())
        .map(|evaluation_ordinal| {
            compact_challenge_from_production(
                decoded_final_response
                    .extension_field_value(&canonical_proof_bytes, evaluation_ordinal)
                    .expect("transported outer evaluation decodes"),
            )
        })
        .collect::<Vec<_>>();
    let decoded_final_values = core::array::from_fn(|matrix_ordinal| {
        compact_challenge_from_production(
            decoded_final_response
                .extension_field_value(
                    &canonical_proof_bytes,
                    cfw_geometry.outer_mask_count() + matrix_ordinal,
                )
                .expect("transported final matrix value decodes"),
        )
    });
    let fresh_cfw_transcript = CompactCfwTranscript::new(
        decoded_auxiliary_target,
        decoded_round_polynomials.clone(),
        decoded_outer_evaluations,
        decoded_final_values,
    );
    let verified_claim_batch = verify_compact_cfw_transcript(
        &resident_matrices,
        &fresh_public_input,
        &fresh_cfw_transcript,
        constraint_combining_challenge,
        &equality_point,
        &round_challenges,
        joint_constraint_challenge,
    )
    .expect("fresh verifier accepts the transported CFW transcript");

    let direct_combined_relation = verified_claim_batch
        .clone()
        .combine_with_preceding_opening_claims(&resident_matrices, &[], batching_challenge)
        .expect("independent direct transpose combines the verified CFW claims");
    let production_combination = verified_claim_batch
        .begin_combining_with_preceding_opening_claims(&[], batching_challenge)
        .expect("production structured transpose begins from verified CFW claims");
    let mut production_handoff =
        CompactStructuredWitnessCovectorHandoff::from_production_row_source(
            &row_source,
            production_combination,
        )
        .expect("production structured transpose connects to the row source");
    let production_combined_relation = loop {
        match production_handoff
            .advance(8_192)
            .expect("production structured transpose advances")
        {
            CompactStructuredWitnessCovectorHandoffPoll::StepCompleted { .. } => {}
            CompactStructuredWitnessCovectorHandoffPoll::Complete(combined_relation) => {
                break combined_relation;
            }
        }
    };
    assert_eq!(production_combined_relation, direct_combined_relation);

    decoded_round_polynomials[0][0] += CompactChallengeField::ONE;
    let mutated_cfw_transcript = CompactCfwTranscript::new(
        decoded_auxiliary_target,
        decoded_round_polynomials,
        resident_finish.outer_evaluations().to_vec(),
        resident_finish.final_values(),
    );
    assert!(verify_compact_cfw_transcript(
        &resident_matrices,
        &fresh_public_input,
        &mutated_cfw_transcript,
        constraint_combining_challenge,
        &equality_point,
        &round_challenges,
        joint_constraint_challenge,
    )
    .is_err());

    let mut wrong_root_bytes = canonical_proof_bytes.clone();
    wrong_root_bytes[PROOF_FIXED_HEADER_BYTE_LENGTH + size_of::<u32>()] ^= 1;
    let wrong_root_proof = decode_compact_proof_wire(
        &proof_wire_geometry,
        &wrong_root_bytes,
        wrong_root_bytes.len(),
    )
    .expect("a canonical root mutation remains structurally decodable");
    assert!(verify_decoded_compact_response_opening(
        &built_responses[0].merkle_geometry,
        &proof_wire_geometry.responses()[0],
        &wrong_root_proof.responses()[0],
        &wrong_root_bytes,
        &built_responses[0].query_leaf_ordinals,
    )
    .is_err());
    assert!(decode_compact_proof_wire(
        &proof_wire_geometry,
        &canonical_proof_bytes[..canonical_proof_bytes.len() - 1],
        canonical_proof_bytes.len() - 1,
    )
    .is_err());
    let mut trailing_proof_bytes = canonical_proof_bytes.clone();
    trailing_proof_bytes.push(0);
    assert!(decode_compact_proof_wire(
        &proof_wire_geometry,
        &trailing_proof_bytes,
        trailing_proof_bytes.len(),
    )
    .is_err());
    let mut wrong_public_input_binding = canonical_public_input_bytes.clone();
    wrong_public_input_binding[10] ^= 1;
    assert!(decode_compact_public_input(
        public_input_wire_geometry,
        public_input_bindings,
        &wrong_public_input_binding,
    )
    .is_err());
}

fn compact_test_challenge(seed: u64) -> CompactChallengeField {
    compact_challenge_from_production(
        ProofChallengeExtensionElement::from_canonical_coordinates([
            seed,
            seed + 1,
            seed + 2,
            seed + 3,
            seed + 4,
        ])
        .expect("small-chain challenge coordinates are canonical"),
    )
}
