use super::super::*;
use super::*;

type CompactVssMessageEncodingLayout =
    crate::bgv::setup::compact_vss_commitment::CompactVssMessageEncodingLayout;
type CompactVssMessageRangeEvidence =
    crate::bgv::setup::compact_vss_commitment::CompactVssMessageRangeEvidence;

fn compact_vss_message_encoding_layouts_for_bounds(
    message_bounds: Vec<u64>,
    range_evidence: CompactVssMessageRangeEvidence,
) -> CanonicalResult<Vec<CompactVssMessageEncodingLayout>> {
    message_bounds
        .into_iter()
        .map(|message_bound| {
            let layout =
                crate::bgv::setup::compact_vss_commitment::compact_vss_message_encoding_layout(
                    message_bound,
                )?;
            Ok(match range_evidence {
                CompactVssMessageRangeEvidence::DigitAndTritColumns => layout,
                CompactVssMessageRangeEvidence::DigitColumnsOnly => {
                    layout.with_digit_columns_only()
                }
            })
        })
        .collect()
}

fn compact_vss_message_encoding_offsets_for_layouts(
    layouts: &[CompactVssMessageEncodingLayout],
) -> CanonicalResult<Vec<usize>> {
    let mut offsets = Vec::with_capacity(layouts.len() + 1);
    let mut offset = 0_usize;
    offsets.push(offset);
    for layout in layouts {
        offset = offset
            .checked_add(layout.encoding_column_count())
            .ok_or_else(|| invalid_succinct_setup_proof("compact VSS column layout overflowed"))?;
        offsets.push(offset);
    }

    Ok(offsets)
}

fn compact_vss_message_encoding_total(offsets: &[usize]) -> usize {
    offsets.last().copied().unwrap_or(0)
}

fn compact_vss_message_position_for_encoding_column(
    offsets: &[usize],
    vector_index: usize,
) -> Option<(usize, usize)> {
    offsets
        .windows(2)
        .enumerate()
        .find(|(_, window)| vector_index >= window[0] && vector_index < window[1])
        .map(|(message_position, window)| (message_position, vector_index - window[0]))
}

// Per-limb physical column layout. Every logical length-N vector occupies
// TRACE_SPLIT physical columns of length N / TRACE_SPLIT, in half order. The
// layout is: secret halves, then per active key per digit the error halves,
// then the matching error-square halves, then the claim-mask digit halves.
pub(crate) struct LimbColumnLayout {
    pub(crate) limb_index: usize,
    pub(crate) base_ring_degree: usize,
    pub(crate) ring_degree: usize,
    pub(crate) trace_size: usize,
    pub(crate) family_shape: SuccinctSetupProofFamilyShape,
    pub(crate) consistency_repetitions: usize,
    // (key index, digit count) per active key, in key order.
    pub(crate) active_keys: Vec<(usize, usize)>,
    pub(crate) total_error_columns: usize,
    pub(crate) private_vss_coefficient_columns: usize,
    pub(crate) compact_vss_coefficient_columns: usize,
    pub(crate) compact_vss_coefficient_relation_columns: usize,
    pub(crate) compact_vss_item_columns: usize,
    pub(crate) target_decryption_message_columns: usize,
    pub(crate) target_decryption_relation_count: usize,
    compact_vss_message_encoding_layouts: Vec<CompactVssMessageEncodingLayout>,
    compact_vss_message_encoding_offsets: Vec<usize>,
    compact_same_secret_bridge_message_encoding_layouts: Vec<CompactVssMessageEncodingLayout>,
    compact_same_secret_bridge_message_encoding_offsets: Vec<usize>,
    target_decryption_message_encoding_layouts: Vec<CompactVssMessageEncodingLayout>,
    target_decryption_message_encoding_offsets: Vec<usize>,
    // Linkage logical columns active in this limb: the binary negative
    // indicator plus the per-commitment opening-randomness columns, or zero
    // outside the commitment fields.
    pub(crate) linkage_randomness_columns: usize,
    pub(crate) private_vss_randomness_columns: usize,
    pub(crate) compact_vss_randomness_columns: usize,
    pub(crate) target_decryption_randomness_columns: usize,
    claim_mask_digit_counts: Vec<usize>,
    claim_mask_slot_offsets: Vec<usize>,
    pub(crate) mask_column_count: usize,
}

impl LimbColumnLayout {
    pub(crate) fn new(
        statement: &TrusteeEvaluationKeyStatement,
        limb_index: usize,
    ) -> CanonicalResult<Self> {
        let family_shape = statement.family_shape()?;
        let active_keys = statement
            .active_key_indices(limb_index)
            .into_iter()
            .map(|key_index| (key_index, statement.keys[key_index].digit_count()))
            .collect::<Vec<_>>();
        let private_vss_coefficient_columns = statement
            .private_vss_share
            .as_ref()
            .filter(|_| limb_index < SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len())
            .map(|statement| statement.coefficient_commitments.len())
            .unwrap_or(0);
        let compact_vss_coefficient_columns = statement.compact_vss_coefficient_count(limb_index);
        let compact_vss_coefficient_relation_columns =
            statement.compact_vss_coefficient_relation_count(limb_index);
        let compact_vss_item_columns = statement.compact_vss_item_count(limb_index);
        let compact_vss_item_lane_count =
            if family_shape == SuccinctSetupProofFamilyShape::CompactVssShareLinkage {
                statement
                    .compact_vss_share_linkage
                    .as_ref()
                    .map(|share_linkage| share_linkage.packed_item_lane_count())
                    .unwrap_or(1)
            } else {
                1
            };
        let target_decryption_message_columns =
            statement.target_decryption_message_count(limb_index);
        let target_decryption_relation_count =
            statement.target_decryption_relation_count(limb_index);
        let compact_vss_range_evidence = CompactVssMessageRangeEvidence::DigitColumnsOnly;
        let compact_vss_message_bounds = statement.compact_vss_message_bounds(limb_index);
        let compact_vss_message_encoding_layouts = compact_vss_message_bounds
            .into_iter()
            .map(|message_bound| {
                compact_vss_message_encoding_layouts_for_bounds(
                    vec![message_bound],
                    compact_vss_range_evidence,
                )
                .and_then(|mut layouts| {
                    layouts.pop().ok_or_else(|| {
                        invalid_succinct_setup_proof(
                            "compact VSS message layout construction returned no layout",
                        )
                    })
                })
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        if compact_vss_message_encoding_layouts.len()
            != compact_vss_coefficient_columns + usize::from(compact_vss_item_columns > 0)
        {
            return Err(invalid_succinct_setup_proof(
                "compact VSS statement bounds do not match the active message columns",
            ));
        }
        let compact_vss_message_encoding_offsets =
            compact_vss_message_encoding_offsets_for_layouts(
                &compact_vss_message_encoding_layouts,
            )?;
        let compact_same_secret_bridge_message_encoding_layouts =
            compact_vss_message_encoding_layouts_for_bounds(
                statement.compact_same_secret_bridge_message_bounds(limb_index),
                CompactVssMessageRangeEvidence::DigitColumnsOnly,
            )?;
        let compact_same_secret_bridge_message_encoding_offsets =
            compact_vss_message_encoding_offsets_for_layouts(
                &compact_same_secret_bridge_message_encoding_layouts,
            )?;
        let target_decryption_message_encoding_layouts =
            compact_vss_message_encoding_layouts_for_bounds(
                statement.target_decryption_message_bounds(limb_index),
                CompactVssMessageRangeEvidence::DigitAndTritColumns,
            )?;
        if target_decryption_message_encoding_layouts.len() != target_decryption_message_columns {
            return Err(invalid_succinct_setup_proof(
                "target-decryption statement bounds do not match the active message columns",
            ));
        }
        let target_decryption_message_encoding_offsets =
            compact_vss_message_encoding_offsets_for_layouts(
                &target_decryption_message_encoding_layouts,
            )?;
        if active_keys.is_empty()
            && statement.linkage_randomness_count(limb_index) == 0
            && private_vss_coefficient_columns == 0
            && compact_vss_coefficient_columns == 0
            && target_decryption_message_columns == 0
        {
            return Err(invalid_succinct_setup_proof(
                "limb layout requires an active key or active linkage relations",
            ));
        }
        let total_error_columns = active_keys.iter().map(|(_, digits)| *digits).sum::<usize>();
        let linkage_randomness_columns = statement.linkage_randomness_count(limb_index);
        let private_vss_randomness_columns = statement.private_vss_randomness_count(limb_index);
        let compact_vss_randomness_columns = statement.compact_vss_randomness_count(limb_index);
        let target_decryption_randomness_columns =
            statement.target_decryption_randomness_count(limb_index);
        let base_ring_degree = statement.ring_degree;
        let ring_degree = if family_shape == SuccinctSetupProofFamilyShape::CompactVssShareLinkage {
            base_ring_degree
                .checked_mul(compact_vss_item_lane_count)
                .ok_or_else(|| {
                    invalid_succinct_setup_proof("compact VSS packed ring degree overflowed")
                })?
        } else {
            base_ring_degree
        };
        // The mask columns are sized from the number of published consistency
        // claims, so this must mirror consistency_vector_count() exactly. For
        // private VSS the message (Shamir coefficient) columns carry no
        // consistency claim (their cross-field consistency is argued globally,
        // not by a per-claim mask; see consistency_vector_count), so the count is
        // the carry plus the opening-randomness columns, not the full logical
        // column count. Compact VSS share-linkage claims the per-item carries
        // plus every compact message digit; the digit claims bind the digit
        // witnesses across commitment fields without carrying separate trit
        // decoder columns in this relation.
        let consistency_vector_count = match family_shape {
            SuccinctSetupProofFamilyShape::PrivateVssShare => 1 + private_vss_randomness_columns,
            SuccinctSetupProofFamilyShape::CompactVssShareLinkage => {
                usize::from(compact_vss_item_columns > 0)
                    + (compact_vss_coefficient_columns + usize::from(compact_vss_item_columns > 0))
                        * crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_MESSAGE_DIGIT_COUNT
            }
            SuccinctSetupProofFamilyShape::CompactSameSecretBridge => {
                2 + compact_same_secret_bridge_message_encoding_layouts.len()
                    * crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_MESSAGE_DIGIT_COUNT
                    + linkage_randomness_columns
            }
            SuccinctSetupProofFamilyShape::TargetDecryptionShare => {
                target_decryption_message_columns
                    * crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_MESSAGE_DIGIT_COUNT
                    + target_decryption_randomness_columns
            }
            _ => {
                1 + total_error_columns
                    + if linkage_randomness_columns > 0 {
                        1 + linkage_randomness_columns
                    } else {
                        0
                    }
            }
        };
        let consistency_repetitions = family_shape.consistency_repetitions();
        let claim_count = consistency_vector_count * consistency_repetitions;
        let claim_mask_digit_counts = (0..claim_count)
            .map(|claim_index| {
                if family_shape == SuccinctSetupProofFamilyShape::TargetDecryptionShare {
                    let vector_index = claim_index / consistency_repetitions;
                    let target_decryption_message_digit_vectors =
                        target_decryption_message_columns
                            * crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_MESSAGE_DIGIT_COUNT;
                    if vector_index < target_decryption_message_digit_vectors {
                        let local_message_index = vector_index
                            / crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_MESSAGE_DIGIT_COUNT;
                        let global_message_index = statement
                            .target_decryption_message_global_index(limb_index, local_message_index)
                            .expect("target-decryption message column is in the layout");
                        match statement
                            .target_decryption_message_claim_kind(global_message_index)
                            .expect("target-decryption message column has a claim kind")
                        {
                            TargetDecryptionMessageClaimKind::AggregateOpening => {
                                TARGET_DECRYPTION_AGGREGATE_MESSAGE_CLAIM_MASK_DIGIT_COUNT
                            }
                            TargetDecryptionMessageClaimKind::SmudgingOpening => {
                                TARGET_DECRYPTION_SMUDGING_MESSAGE_CLAIM_MASK_DIGIT_COUNT
                            }
                        }
                    } else {
                        TARGET_DECRYPTION_RANDOMNESS_CLAIM_MASK_DIGIT_COUNT
                    }
                } else if family_shape == SuccinctSetupProofFamilyShape::CompactVssShareLinkage {
                    let vector_index = claim_index / consistency_repetitions;
                    if vector_index == 0 {
                        COMPACT_VSS_CARRY_CLAIM_MASK_DIGIT_COUNT
                    } else {
                        COMPACT_VSS_DIGIT_CLAIM_MASK_DIGIT_COUNT
                    }
                } else if family_shape == SuccinctSetupProofFamilyShape::CompactSameSecretBridge {
                    let vector_index = claim_index / consistency_repetitions;
                    let bridge_digit_vector_count =
                        compact_same_secret_bridge_message_encoding_layouts.len()
                            * crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_MESSAGE_DIGIT_COUNT;
                    if (2..2 + bridge_digit_vector_count).contains(&vector_index) {
                        COMPACT_VSS_DIGIT_CLAIM_MASK_DIGIT_COUNT
                    } else {
                        family_shape.claim_mask_digit_count()
                    }
                } else {
                    family_shape.claim_mask_digit_count()
                }
            })
            .collect::<Vec<_>>();
        let mut claim_mask_slot_offsets = Vec::with_capacity(claim_count + 1);
        let mut mask_slot_count = 0_usize;
        claim_mask_slot_offsets.push(mask_slot_count);
        for digit_count in &claim_mask_digit_counts {
            mask_slot_count = mask_slot_count.checked_add(*digit_count).ok_or_else(|| {
                invalid_succinct_setup_proof("claim mask column count overflowed")
            })?;
            claim_mask_slot_offsets.push(mask_slot_count);
        }
        let mask_column_count = mask_slot_count.div_ceil(ring_degree);

        Ok(Self {
            limb_index,
            base_ring_degree,
            ring_degree,
            trace_size: ring_degree / TRACE_SPLIT,
            family_shape,
            consistency_repetitions,
            active_keys,
            total_error_columns,
            private_vss_coefficient_columns,
            compact_vss_coefficient_columns,
            compact_vss_coefficient_relation_columns,
            compact_vss_item_columns,
            target_decryption_message_columns,
            target_decryption_relation_count,
            compact_vss_message_encoding_layouts,
            compact_vss_message_encoding_offsets,
            compact_same_secret_bridge_message_encoding_layouts,
            compact_same_secret_bridge_message_encoding_offsets,
            target_decryption_message_encoding_layouts,
            target_decryption_message_encoding_offsets,
            linkage_randomness_columns,
            private_vss_randomness_columns,
            compact_vss_randomness_columns,
            target_decryption_randomness_columns,
            claim_mask_digit_counts,
            claim_mask_slot_offsets,
            mask_column_count,
        })
    }

    pub(crate) fn linkage_active(&self) -> bool {
        self.linkage_randomness_columns > 0
    }

    // Logical linkage columns: the negative indicator plus the randomness.
    fn linkage_logical_columns(&self) -> usize {
        if self.linkage_active() {
            1 + self.linkage_randomness_columns
        } else {
            0
        }
    }

    pub(crate) fn private_vss_active(&self) -> bool {
        self.family_shape == SuccinctSetupProofFamilyShape::PrivateVssShare
    }

    pub(crate) fn compact_vss_active(&self) -> bool {
        self.family_shape == SuccinctSetupProofFamilyShape::CompactVssShareLinkage
    }

    pub(crate) fn compact_same_secret_bridge_active(&self) -> bool {
        self.family_shape == SuccinctSetupProofFamilyShape::CompactSameSecretBridge
    }

    pub(crate) fn target_decryption_active(&self) -> bool {
        self.family_shape == SuccinctSetupProofFamilyShape::TargetDecryptionShare
    }

    // Every private-VSS logical witness column committed in the trace: the
    // message (Shamir coefficient) columns, the carry column, and the
    // opening-randomness columns. This is the trace width and the length of the
    // opening lincheck (`publics.linkage`). It deliberately exceeds
    // consistency_vector_count(), which claims only the carry and randomness
    // columns; the message columns remain witnesses for the opening and share
    // linchecks (their cross-field consistency is argued globally rather than by
    // a per-claim consistency mask; see consistency_vector_count).
    pub(crate) fn private_vss_logical_columns(&self) -> usize {
        if self.private_vss_active() {
            self.private_vss_coefficient_columns + 1 + self.private_vss_randomness_columns
        } else {
            0
        }
    }

    pub(crate) fn compact_vss_logical_columns(&self) -> usize {
        if self.compact_vss_active() {
            self.compact_vss_message_encoding_columns() + 1 + self.compact_vss_randomness_columns
        } else {
            0
        }
    }

    pub(crate) fn target_decryption_logical_columns(&self) -> usize {
        if self.target_decryption_active() {
            self.target_decryption_message_encoding_columns()
                + self.target_decryption_randomness_columns
        } else {
            0
        }
    }

    pub(crate) fn private_vss_relation_count(&self) -> usize {
        if self.private_vss_active() {
            self.private_vss_coefficient_columns * SETUP_COMMITMENT_ROW_COUNT + 1
        } else {
            0
        }
    }

    pub(crate) fn compact_vss_relation_count(&self) -> usize {
        if self.compact_vss_active() {
            let decoder_relation_count = (self.compact_vss_coefficient_relation_columns
                * self.compact_vss_coefficient_decoder_digit_count()
                + self.compact_vss_item_columns * self.compact_vss_recipient_decoder_digit_count())
                * LINCHECK_REPETITIONS;
            self.compact_vss_coefficient_relation_columns
                * crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_OUTPUT_COORDINATE_COUNT
                + self.compact_vss_item_columns
                    * (crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_OUTPUT_COORDINATE_COUNT
                        + LINCHECK_REPETITIONS)
                + decoder_relation_count
        } else {
            0
        }
    }

    // Logical witness vectors carrying cross-limb consistency claims: the
    // shared secret first, then every active key's error vectors in order,
    // then the linkage negative indicator and opening-randomness vectors. Family
    // shapes with their own lifted relations override this shape below.
    pub(crate) fn consistency_vector_count(&self) -> usize {
        if self.private_vss_active() {
            // The message (Shamir coefficient) columns carry no cross-field
            // consistency claim; only the carry and the opening-randomness
            // columns do. This is NOT because the commitment opening rows pin the
            // message across fields: the published commitment's message row is
            // free per commitment field (only the binding rows t1 = A1*r are
            // forced consistent, via the kept randomness consistency r*), so
            // m_msg^(c) = (t_msg^(c) - A2*r*) is free per field and a single
            // recipient's check does not bind the message coefficients across the
            // RNS commitment fields. The sharing is pinned GLOBALLY instead: the
            // kept carry consistency claim plus the public, range-checked share
            // pin the evaluation sum_k alpha_j^k F_k at each recipient point
            // alpha_j to one bounded integer across the commitment fields (carry
            // pinned + bounded => the evaluation is the bounded centered lift),
            // and >= t honest recipients at distinct points force the degree
            // (t-1) sharing polynomial to be consistent. This requires
            // q_setup_complete - c_priv >= t honest verifying recipients
            // (7 >= 4 in the first profile). Dropping the carry from this set, or
            // weakening the carry/share range checks, breaks the argument.
            // private_vss_logical_columns() still counts the message columns
            // because they remain witnesses for the opening and share linchecks.
            1 + self.private_vss_randomness_columns
        } else if self.compact_vss_active() {
            // Compact share-linkage packs every recipient/source-limb item into
            // one longer trace. It claims one packed lifted-carry vector and
            // every packed compact message digit. Opening and share-relation
            // linchecks keep consuming the digits in each field, while these
            // claims bind the digits to lifted integer vectors across the
            // carried fields.
            // Opening randomness remains committed and ternary row-checked in
            // each proof limb, but it is not consumed downstream and does not
            // need a separate cross-field integer claim.
            1 + self.compact_vss_message_vector_count()
                * crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_MESSAGE_DIGIT_COUNT
        } else if self.compact_same_secret_bridge_active() {
            // Compact same-secret bridge claims the signed secret, the binary
            // negative indicator, every target-message digit, and the compact
            // opening randomness. The digit claims bind the target messages
            // across commitment fields, so this relation does not carry trit
            // decoder columns.
            2 + self.compact_same_secret_bridge_target_count()
                * crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_MESSAGE_DIGIT_COUNT
                + self.linkage_randomness_columns
        } else if self.target_decryption_active() {
            // Target-decryption claims every compact message digit directly,
            // then every compact-opening randomness column. Decoder rows bind
            // the digit columns to local ternary decomposition columns.
            self.target_decryption_message_columns
                * crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_MESSAGE_DIGIT_COUNT
                + self.target_decryption_randomness_columns
        } else {
            1 + self.total_error_columns + self.linkage_logical_columns()
        }
    }

    pub(crate) fn claim_count(&self) -> usize {
        self.consistency_vector_count() * self.consistency_repetitions
    }

    pub(crate) fn compact_vss_message_vector_count(&self) -> usize {
        self.compact_vss_coefficient_columns + 1
    }

    fn compact_vss_decoder_digit_count_for_layout(
        layout: CompactVssMessageEncodingLayout,
    ) -> usize {
        (0..crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_MESSAGE_DIGIT_COUNT)
            .filter(|digit_index| layout.digit_trit_count(*digit_index).unwrap_or(0) > 0)
            .count()
    }

    pub(crate) fn compact_vss_coefficient_decoder_digit_count(&self) -> usize {
        self.compact_vss_message_encoding_layouts
            .first()
            .copied()
            .map(Self::compact_vss_decoder_digit_count_for_layout)
            .unwrap_or(0)
    }

    pub(crate) fn compact_vss_recipient_decoder_digit_count(&self) -> usize {
        self.compact_vss_message_encoding_layouts
            .get(self.compact_vss_coefficient_columns)
            .copied()
            .map(Self::compact_vss_decoder_digit_count_for_layout)
            .unwrap_or(0)
    }

    pub(crate) fn compact_vss_coefficient_message_range_evidence(
        &self,
    ) -> CompactVssMessageRangeEvidence {
        self.compact_vss_message_encoding_layouts
            .first()
            .copied()
            .map(|layout| {
                if layout.has_digit_decoder_relations() {
                    CompactVssMessageRangeEvidence::DigitAndTritColumns
                } else {
                    CompactVssMessageRangeEvidence::DigitColumnsOnly
                }
            })
            .unwrap_or(CompactVssMessageRangeEvidence::DigitColumnsOnly)
    }

    pub(crate) fn compact_vss_recipient_message_range_evidence(
        &self,
    ) -> CompactVssMessageRangeEvidence {
        self.compact_vss_message_encoding_layouts
            .get(self.compact_vss_coefficient_columns)
            .copied()
            .map(|layout| {
                if layout.has_digit_decoder_relations() {
                    CompactVssMessageRangeEvidence::DigitAndTritColumns
                } else {
                    CompactVssMessageRangeEvidence::DigitColumnsOnly
                }
            })
            .unwrap_or(CompactVssMessageRangeEvidence::DigitColumnsOnly)
    }

    pub(crate) fn compact_vss_message_encoding_layout(
        &self,
        message_position: usize,
    ) -> CompactVssMessageEncodingLayout {
        self.compact_vss_message_encoding_layouts[message_position]
    }

    pub(crate) fn compact_vss_message_encoding_columns(&self) -> usize {
        compact_vss_message_encoding_total(&self.compact_vss_message_encoding_offsets)
    }

    pub(crate) fn compact_vss_message_encoding_column_count(
        &self,
        message_position: usize,
    ) -> usize {
        self.compact_vss_message_encoding_offsets[message_position + 1]
            - self.compact_vss_message_encoding_offsets[message_position]
    }

    pub(crate) fn compact_vss_message_trit_count(
        &self,
        message_position: usize,
        digit_index: usize,
    ) -> usize {
        self.compact_vss_message_encoding_layouts[message_position]
            .digit_trit_count(digit_index)
            .expect("compact VSS digit is in the layout")
    }

    pub(crate) fn compact_vss_message_position_for_encoding_column(
        &self,
        vector_index: usize,
    ) -> Option<(usize, usize)> {
        compact_vss_message_position_for_encoding_column(
            &self.compact_vss_message_encoding_offsets,
            vector_index,
        )
    }

    pub(crate) fn compact_same_secret_bridge_target_count(&self) -> usize {
        if self.compact_same_secret_bridge_active() {
            self.linkage_randomness_columns
                / crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_RANDOMNESS_COLUMN_COUNT
        } else {
            0
        }
    }

    pub(crate) fn compact_same_secret_bridge_message_encoding_columns(&self) -> usize {
        compact_vss_message_encoding_total(
            &self.compact_same_secret_bridge_message_encoding_offsets,
        )
    }

    pub(crate) fn compact_same_secret_bridge_decoder_digit_count(&self) -> usize {
        self.compact_same_secret_bridge_message_encoding_layouts
            .iter()
            .copied()
            .map(Self::compact_vss_decoder_digit_count_for_layout)
            .sum()
    }

    pub(crate) fn compact_same_secret_bridge_relation_count(&self) -> usize {
        if self.compact_same_secret_bridge_active() {
            self.compact_same_secret_bridge_target_count()
                * (crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_OUTPUT_COORDINATE_COUNT
                    + LINCHECK_REPETITIONS)
                + self.compact_same_secret_bridge_decoder_digit_count() * LINCHECK_REPETITIONS
        } else {
            0
        }
    }

    pub(crate) fn compact_same_secret_bridge_message_trit_count(
        &self,
        target_index: usize,
        digit_index: usize,
    ) -> usize {
        self.compact_same_secret_bridge_message_encoding_layouts[target_index]
            .digit_trit_count(digit_index)
            .expect("compact same-secret bridge digit is in the layout")
    }

    pub(crate) fn compact_same_secret_bridge_message_position_for_encoding_column(
        &self,
        vector_index: usize,
    ) -> Option<(usize, usize)> {
        compact_vss_message_position_for_encoding_column(
            &self.compact_same_secret_bridge_message_encoding_offsets,
            vector_index,
        )
    }

    pub(crate) fn compact_same_secret_bridge_logical_columns(&self) -> usize {
        if self.compact_same_secret_bridge_active() {
            2 + self.compact_same_secret_bridge_message_encoding_columns()
                + self.linkage_randomness_columns
        } else {
            0
        }
    }

    pub(crate) fn target_decryption_message_encoding_columns(&self) -> usize {
        compact_vss_message_encoding_total(&self.target_decryption_message_encoding_offsets)
    }

    pub(crate) fn target_decryption_message_position_for_encoding_column(
        &self,
        vector_index: usize,
    ) -> Option<(usize, usize)> {
        compact_vss_message_position_for_encoding_column(
            &self.target_decryption_message_encoding_offsets,
            vector_index,
        )
    }

    pub(crate) fn target_decryption_message_trit_count(
        &self,
        message_position: usize,
        digit_index: usize,
    ) -> usize {
        self.target_decryption_message_encoding_layouts[message_position]
            .digit_trit_count(digit_index)
            .expect("target-decryption digit is in the layout")
    }

    pub(crate) fn physical_secret(&self, half: usize) -> usize {
        debug_assert!(!self.private_vss_active());
        half
    }

    // error_position counts error vectors across active keys in layout order.
    pub(crate) fn physical_error(&self, error_position: usize, half: usize) -> usize {
        debug_assert!(!self.private_vss_active());
        TRACE_SPLIT * (1 + error_position) + half
    }

    pub(crate) fn physical_error_square(&self, error_position: usize, half: usize) -> usize {
        debug_assert!(!self.private_vss_active());
        TRACE_SPLIT * (1 + self.total_error_columns + error_position) + half
    }

    pub(crate) fn physical_negative_indicator(&self, half: usize) -> usize {
        debug_assert!(self.linkage_active());
        debug_assert!(!self.private_vss_active());
        TRACE_SPLIT * (1 + 2 * self.total_error_columns) + half
    }

    pub(crate) fn physical_linkage_randomness(
        &self,
        randomness_position: usize,
        half: usize,
    ) -> usize {
        debug_assert!(self.linkage_active());
        debug_assert!(!self.private_vss_active());
        if self.compact_same_secret_bridge_active() {
            return TRACE_SPLIT
                * (2 + self.compact_same_secret_bridge_message_encoding_columns()
                    + randomness_position)
                + half;
        }
        TRACE_SPLIT * (1 + 2 * self.total_error_columns + 1 + randomness_position) + half
    }

    pub(crate) fn physical_private_vss_message(
        &self,
        coefficient_index: usize,
        half: usize,
    ) -> usize {
        debug_assert!(self.private_vss_active());
        TRACE_SPLIT * coefficient_index + half
    }

    pub(crate) fn physical_compact_vss_message(
        &self,
        message_position: usize,
        encoding_column: usize,
        half: usize,
    ) -> usize {
        debug_assert!(self.compact_vss_active());
        debug_assert!(message_position < self.compact_vss_message_vector_count());
        debug_assert!(
            encoding_column < self.compact_vss_message_encoding_column_count(message_position)
        );
        TRACE_SPLIT
            * (self.compact_vss_message_encoding_offsets[message_position] + encoding_column)
            + half
    }

    pub(crate) fn physical_compact_vss_message_trit(
        &self,
        message_position: usize,
        digit_index: usize,
        trit_index: usize,
        half: usize,
    ) -> usize {
        let encoding_column = self.compact_vss_message_encoding_layouts[message_position]
            .trit_encoding_column(digit_index, trit_index)
            .expect("compact VSS message trit is in the layout");
        self.physical_compact_vss_message(message_position, encoding_column, half)
    }

    pub(crate) fn physical_compact_vss_message_digit(
        &self,
        message_position: usize,
        digit_index: usize,
        half: usize,
    ) -> usize {
        let encoding_column = self.compact_vss_message_encoding_layouts[message_position]
            .digit_encoding_column(digit_index)
            .expect("compact VSS message digit is in the layout");
        self.physical_compact_vss_message(message_position, encoding_column, half)
    }

    pub(crate) fn physical_compact_vss_recipient_message_at(
        &self,
        _item_index: usize,
        encoding_column: usize,
        half: usize,
    ) -> usize {
        debug_assert!(self.compact_vss_active());
        self.physical_compact_vss_message(
            self.compact_vss_coefficient_columns,
            encoding_column,
            half,
        )
    }

    pub(crate) fn physical_compact_vss_carry_at(&self, item_index: usize, half: usize) -> usize {
        debug_assert!(self.compact_vss_active());
        debug_assert!(item_index < self.compact_vss_item_columns);
        TRACE_SPLIT * self.compact_vss_message_encoding_columns() + half
    }

    pub(crate) fn physical_compact_vss_randomness(
        &self,
        randomness_position: usize,
        half: usize,
    ) -> usize {
        debug_assert!(self.compact_vss_active());
        TRACE_SPLIT * (self.compact_vss_message_encoding_columns() + 1 + randomness_position) + half
    }

    pub(crate) fn physical_compact_same_secret_bridge_message(
        &self,
        target_index: usize,
        encoding_column: usize,
        half: usize,
    ) -> usize {
        debug_assert!(self.compact_same_secret_bridge_active());
        debug_assert!(target_index < self.compact_same_secret_bridge_target_count());
        debug_assert!(
            encoding_column
                < self.compact_same_secret_bridge_message_encoding_layouts[target_index]
                    .encoding_column_count()
        );
        TRACE_SPLIT
            * (2 + self.compact_same_secret_bridge_message_encoding_offsets[target_index]
                + encoding_column)
            + half
    }

    pub(crate) fn physical_compact_same_secret_bridge_message_trit(
        &self,
        target_index: usize,
        digit_index: usize,
        trit_index: usize,
        half: usize,
    ) -> usize {
        let encoding_column = self.compact_same_secret_bridge_message_encoding_layouts
            [target_index]
            .trit_encoding_column(digit_index, trit_index)
            .expect("compact same-secret bridge message trit is in the layout");
        self.physical_compact_same_secret_bridge_message(target_index, encoding_column, half)
    }

    pub(crate) fn physical_compact_same_secret_bridge_message_digit(
        &self,
        target_index: usize,
        digit_index: usize,
        half: usize,
    ) -> usize {
        let encoding_column = self.compact_same_secret_bridge_message_encoding_layouts
            [target_index]
            .digit_encoding_column(digit_index)
            .expect("compact same-secret bridge message digit is in the layout");
        self.physical_compact_same_secret_bridge_message(target_index, encoding_column, half)
    }

    pub(crate) fn physical_target_decryption_message_encoding(
        &self,
        message_position: usize,
        encoding_column: usize,
        half: usize,
    ) -> usize {
        debug_assert!(self.target_decryption_active());
        debug_assert!(message_position < self.target_decryption_message_columns);
        debug_assert!(
            encoding_column
                < self.target_decryption_message_encoding_layouts[message_position]
                    .encoding_column_count()
        );
        TRACE_SPLIT
            * (self.target_decryption_message_encoding_offsets[message_position] + encoding_column)
            + half
    }

    pub(crate) fn physical_target_decryption_message_digit(
        &self,
        message_position: usize,
        digit_index: usize,
        half: usize,
    ) -> usize {
        let encoding_column = self.target_decryption_message_encoding_layouts[message_position]
            .digit_encoding_column(digit_index)
            .expect("target-decryption message digit is in the layout");
        self.physical_target_decryption_message_encoding(message_position, encoding_column, half)
    }

    pub(crate) fn physical_target_decryption_message_trit(
        &self,
        message_position: usize,
        digit_index: usize,
        trit_index: usize,
        half: usize,
    ) -> usize {
        let encoding_column = self.target_decryption_message_encoding_layouts[message_position]
            .trit_encoding_column(digit_index, trit_index)
            .expect("target-decryption message trit is in the layout");
        self.physical_target_decryption_message_encoding(message_position, encoding_column, half)
    }

    pub(crate) fn physical_target_decryption_randomness(
        &self,
        randomness_position: usize,
        half: usize,
    ) -> usize {
        debug_assert!(self.target_decryption_active());
        TRACE_SPLIT * (self.target_decryption_message_encoding_columns() + randomness_position)
            + half
    }

    pub(crate) fn physical_private_vss_carry(&self, half: usize) -> usize {
        debug_assert!(self.private_vss_active());
        TRACE_SPLIT * self.private_vss_coefficient_columns + half
    }

    pub(crate) fn physical_private_vss_randomness(
        &self,
        randomness_position: usize,
        half: usize,
    ) -> usize {
        debug_assert!(self.private_vss_active());
        TRACE_SPLIT * (self.private_vss_coefficient_columns + 1 + randomness_position) + half
    }

    pub(crate) fn physical_mask(&self, mask_column: usize, half: usize) -> usize {
        let logical_prefix = if self.private_vss_active() {
            self.private_vss_logical_columns()
        } else if self.compact_vss_active() {
            self.compact_vss_logical_columns()
        } else if self.compact_same_secret_bridge_active() {
            self.compact_same_secret_bridge_logical_columns()
        } else if self.target_decryption_active() {
            self.target_decryption_logical_columns()
        } else {
            1 + 2 * self.total_error_columns + self.linkage_logical_columns()
        };
        TRACE_SPLIT * (logical_prefix + mask_column) + half
    }

    pub(crate) fn phase_one_physical_count(&self) -> usize {
        let logical_prefix = if self.private_vss_active() {
            self.private_vss_logical_columns()
        } else if self.compact_vss_active() {
            self.compact_vss_logical_columns()
        } else if self.compact_same_secret_bridge_active() {
            self.compact_same_secret_bridge_logical_columns()
        } else if self.target_decryption_active() {
            self.target_decryption_logical_columns()
        } else {
            1 + 2 * self.total_error_columns + self.linkage_logical_columns()
        };
        TRACE_SPLIT * (logical_prefix + self.mask_column_count)
    }

    // Row-check constraints are present for restricted witness columns and
    // mask digits. Private VSS message and carry columns are unrestricted field
    // columns. The private VSS carry's integer lift is pinned by its masked
    // consistency claim; private VSS message columns carry no consistency claim,
    // so sharing relies on the global argument in consistency_vector_count
    // instead. Compact VSS share-linkage, bridge, and target-decryption message
    // digits are pinned by masked consistency claims, while any trit decoder
    // columns are locally range-checked here.
    pub(crate) fn row_check_constraint_count(&self) -> usize {
        if self.private_vss_active() {
            TRACE_SPLIT * (self.private_vss_randomness_columns + self.mask_column_count)
        } else if self.compact_vss_active() {
            let compact_vss_message_trit_columns = self
                .compact_vss_message_encoding_layouts
                .iter()
                .map(|layout| layout.total_trit_count())
                .sum::<usize>();
            TRACE_SPLIT
                * (compact_vss_message_trit_columns
                    + self.compact_vss_randomness_columns
                    + self.mask_column_count)
        } else if self.compact_same_secret_bridge_active() {
            let compact_same_secret_bridge_message_trit_columns = self
                .compact_same_secret_bridge_message_encoding_layouts
                .iter()
                .map(|layout| layout.total_trit_count())
                .sum::<usize>();
            TRACE_SPLIT
                * (1 + 1
                    + compact_same_secret_bridge_message_trit_columns
                    + self.linkage_randomness_columns
                    + self.mask_column_count)
        } else if self.target_decryption_active() {
            let target_decryption_message_trit_columns = self
                .target_decryption_message_encoding_layouts
                .iter()
                .map(|layout| layout.total_trit_count())
                .sum::<usize>();
            TRACE_SPLIT
                * (target_decryption_message_trit_columns
                    + self.target_decryption_randomness_columns
                    + self.mask_column_count)
        } else {
            self.phase_one_physical_count()
        }
    }

    pub(crate) fn claim_mask_digit_count(&self, claim_index: usize) -> usize {
        self.claim_mask_digit_counts[claim_index]
    }

    // Mask slot of one claim digit: claims are laid out consecutively with the
    // selected digit count for that claim.
    pub(crate) fn mask_slot(
        &self,
        claim_index: usize,
        digit_index: usize,
    ) -> (usize, usize, usize) {
        debug_assert!(claim_index < self.claim_mask_digit_counts.len());
        debug_assert!(digit_index < self.claim_mask_digit_count(claim_index));
        let slot = self.claim_mask_slot_offsets[claim_index] + digit_index;
        let logical_column = slot / self.ring_degree;
        let position = slot % self.ring_degree;
        let half = position / self.trace_size;
        let half_position = position % self.trace_size;

        (logical_column, half, half_position)
    }
}

pub(crate) const PHASE_TWO_COLUMN_COUNT: usize = 4;
pub(crate) const QUOTIENT_COLUMN_ROW_CHECK_LOW: usize = 0;
pub(crate) const QUOTIENT_COLUMN_ROW_CHECK_HIGH: usize = 1;
pub(crate) const QUOTIENT_COLUMN_SUMCHECK_VANISHING: usize = 2;
pub(crate) const QUOTIENT_COLUMN_SUMCHECK_RESIDUAL: usize = 3;
