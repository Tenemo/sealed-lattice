use super::super::*;
use super::*;

// Per-limb physical column layout. Every logical length-N vector occupies
// TRACE_SPLIT physical columns of length N / TRACE_SPLIT, in half order. The
// layout is: secret halves, then per active key per digit the error halves,
// then the matching error-square halves, then the claim-mask digit halves.
pub(crate) struct LimbColumnLayout {
    pub(crate) ring_degree: usize,
    pub(crate) trace_size: usize,
    pub(crate) family_shape: SuccinctSetupProofFamilyShape,
    // (key index, digit count) per active key, in key order.
    pub(crate) active_keys: Vec<(usize, usize)>,
    pub(crate) total_error_columns: usize,
    pub(crate) private_vss_coefficient_columns: usize,
    pub(crate) compact_vss_coefficient_columns: usize,
    pub(crate) target_decryption_message_columns: usize,
    pub(crate) target_decryption_relation_count: usize,
    // Linkage logical columns active in this limb: the binary negative
    // indicator plus the per-commitment opening-randomness columns, or zero
    // outside the commitment fields.
    pub(crate) linkage_randomness_columns: usize,
    pub(crate) private_vss_randomness_columns: usize,
    pub(crate) compact_vss_randomness_columns: usize,
    pub(crate) target_decryption_randomness_columns: usize,
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
        let target_decryption_message_columns = statement.target_decryption_message_count();
        let target_decryption_relation_count =
            statement.target_decryption_relation_count(limb_index);
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
        let target_decryption_randomness_columns = statement.target_decryption_randomness_count();
        let ring_degree = statement.ring_degree;
        // The mask columns are sized from the number of published consistency
        // claims, so this must mirror consistency_vector_count() exactly. For
        // private VSS the message (Shamir coefficient) columns carry no
        // consistency claim (their cross-field consistency is argued globally,
        // not by a per-claim mask; see consistency_vector_count), so the count is
        // the carry plus the opening-randomness columns, not the full logical
        // column count. Sizing the masks from the logical column count instead
        // would commit unused mask columns for claims that are never published.
        let consistency_vector_count = match family_shape {
            SuccinctSetupProofFamilyShape::PrivateVssShare => 1 + private_vss_randomness_columns,
            SuccinctSetupProofFamilyShape::CompactVssShareLinkage => {
                1 + compact_vss_randomness_columns
            }
            SuccinctSetupProofFamilyShape::TargetDecryptionShare => {
                target_decryption_message_columns + target_decryption_randomness_columns
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
        let claim_count = consistency_vector_count * CONSISTENCY_REPETITIONS;
        let mask_slot_count = claim_count * CLAIM_MASK_DIGIT_COUNT;
        let mask_column_count = mask_slot_count.div_ceil(ring_degree);

        Ok(Self {
            ring_degree,
            trace_size: ring_degree / TRACE_SPLIT,
            family_shape,
            active_keys,
            total_error_columns,
            private_vss_coefficient_columns,
            compact_vss_coefficient_columns,
            target_decryption_message_columns,
            target_decryption_relation_count,
            linkage_randomness_columns,
            private_vss_randomness_columns,
            compact_vss_randomness_columns,
            target_decryption_randomness_columns,
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
            self.compact_vss_coefficient_columns + 2 + self.compact_vss_randomness_columns
        } else {
            0
        }
    }

    pub(crate) fn target_decryption_logical_columns(&self) -> usize {
        if self.target_decryption_active() {
            self.target_decryption_message_columns + self.target_decryption_randomness_columns
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
            (self.compact_vss_coefficient_columns + 1)
                * crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_OUTPUT_COORDINATE_COUNT
                + 1
        } else {
            0
        }
    }

    // Logical witness vectors carrying cross-limb consistency claims: the
    // shared secret first, then every active key's error vectors in order,
    // then the linkage negative indicator and opening-randomness vectors.
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
            1 + self.compact_vss_randomness_columns
        } else if self.target_decryption_active() {
            self.target_decryption_logical_columns()
        } else {
            1 + self.total_error_columns + self.linkage_logical_columns()
        }
    }

    pub(crate) fn claim_count(&self) -> usize {
        self.consistency_vector_count() * CONSISTENCY_REPETITIONS
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
        coefficient_index: usize,
        half: usize,
    ) -> usize {
        debug_assert!(self.compact_vss_active());
        TRACE_SPLIT * coefficient_index + half
    }

    pub(crate) fn physical_compact_vss_recipient_message(&self, half: usize) -> usize {
        debug_assert!(self.compact_vss_active());
        TRACE_SPLIT * self.compact_vss_coefficient_columns + half
    }

    pub(crate) fn physical_compact_vss_carry(&self, half: usize) -> usize {
        debug_assert!(self.compact_vss_active());
        TRACE_SPLIT * (self.compact_vss_coefficient_columns + 1) + half
    }

    pub(crate) fn physical_compact_vss_randomness(
        &self,
        randomness_position: usize,
        half: usize,
    ) -> usize {
        debug_assert!(self.compact_vss_active());
        TRACE_SPLIT * (self.compact_vss_coefficient_columns + 2 + randomness_position) + half
    }

    pub(crate) fn physical_target_decryption_message(
        &self,
        message_position: usize,
        half: usize,
    ) -> usize {
        debug_assert!(self.target_decryption_active());
        TRACE_SPLIT * message_position + half
    }

    pub(crate) fn physical_target_decryption_randomness(
        &self,
        randomness_position: usize,
        half: usize,
    ) -> usize {
        debug_assert!(self.target_decryption_active());
        TRACE_SPLIT * (self.target_decryption_message_columns + randomness_position) + half
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
        } else if self.target_decryption_active() {
            self.target_decryption_logical_columns()
        } else {
            1 + 2 * self.total_error_columns + self.linkage_logical_columns()
        };
        TRACE_SPLIT * (logical_prefix + self.mask_column_count)
    }

    // Row-check constraints are present for restricted witness columns and
    // mask digits. Private VSS message and carry columns are unrestricted field
    // columns. The carry's integer lift is pinned by its masked consistency
    // claim; the message columns carry no consistency claim, so they are not
    // pinned by masked consistency and the sharing relies on the global argument
    // in consistency_vector_count instead.
    pub(crate) fn row_check_constraint_count(&self) -> usize {
        if self.private_vss_active() {
            TRACE_SPLIT * (self.private_vss_randomness_columns + self.mask_column_count)
        } else if self.compact_vss_active() {
            TRACE_SPLIT * (self.compact_vss_randomness_columns + self.mask_column_count)
        } else if self.target_decryption_active() {
            TRACE_SPLIT * (self.target_decryption_randomness_columns + self.mask_column_count)
        } else {
            self.phase_one_physical_count()
        }
    }

    // Mask slot of one claim digit: claims are laid out consecutively with
    // CLAIM_MASK_DIGIT_COUNT binary digits each.
    pub(crate) fn mask_slot(
        &self,
        claim_index: usize,
        digit_index: usize,
    ) -> (usize, usize, usize) {
        let slot = claim_index * CLAIM_MASK_DIGIT_COUNT + digit_index;
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
