use super::super::*;
use super::*;

// The seed label of the accepted BGV common reference polynomial; the
// public-key share descriptor pins it as its sample domain so the family
// cannot prove against an arbitrary reference polynomial.
pub(crate) const PUBLIC_KEY_SHARE_COMMON_REFERENCE_LABEL: &str = "accepted-bgv-public-a";

// Which key family the diagonal source term encodes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum EvaluationKeyShareKind {
    // source = s (the shared trustee secret): relinearization round one.
    RelinearizationRoundOne,
    // source = s (*) A, where A is the public round-one aggregate:
    // relinearization round two.
    RelinearizationRoundTwo,
    // source = phi_g(s), the Galois automorphism s(X) -> s(X^g) applied to
    // the shared trustee secret: rotation key for the odd element g.
    GaloisRotation { galois_element: usize },
    // No diagonal source: the public-key share relation b_l + a_l (*) s -
    // p * e = 0 over every Q_share limb, with one error vector and the
    // seed-derived common reference polynomial as the public sample.
    PublicKeyShare,
}

impl EvaluationKeyShareKind {
    pub(crate) fn tag_bytes(self) -> [u8; 9] {
        let mut bytes = [0_u8; 9];
        match self {
            Self::RelinearizationRoundOne => bytes[0] = 1,
            Self::RelinearizationRoundTwo => bytes[0] = 2,
            Self::GaloisRotation { galois_element } => {
                bytes[0] = 3;
                bytes[1..].copy_from_slice(&(galois_element as u64).to_le_bytes());
            }
            Self::PublicKeyShare => bytes[0] = 4,
        }

        bytes
    }

    // Whether the relation carries the [l == j] diagonal source term.
    pub(crate) fn has_diagonal_source(self) -> bool {
        !matches!(self, Self::PublicKeyShare)
    }
}

// One evaluation-key share inside a trustee proof: for every digit j and limb
// l of this key's level, b_{j,l} + a_{j,l} * s - p * e_j - [l == j] * source_j
// = 0 in R_{q_l}, with a_{j,l} the deterministic public key-switch sample and
// the diagonal source chosen by the kind.
pub(crate) struct EvaluationKeyShareDescriptor {
    pub(crate) kind: EvaluationKeyShareKind,
    pub(crate) level: usize,
    pub(crate) key_switch_domain: String,
    pub(crate) key_switch_seed_hex: String,
    // component_b_by_digit[digit][limb] is one coefficient vector mod q_limb.
    pub(crate) component_b_by_digit: Vec<Vec<Vec<u64>>>,
    // Round two only: the digit-j round-one aggregate reduced mod q_j.
    pub(crate) round_one_aggregate_diagonal: Vec<Vec<u64>>,
}

// The accepted BDLOP same-secret constant commitments, opened inside the
// argument so every key relation provably uses the committed trustee secret:
// for every Q_share limb l and commitment field q_c (the first three data
// primes), each commitment row satisfies
//   t_{l,k} = sum_w A_{l,k,w} (*) r_{l,w} + [k == message row] * (s + neg * q_l)
// over Z_{q_c}, with r ternary, neg binary, and s the shared key-relation
// secret. Holding over all three commitment fields gives the equation over
// the commitment modulus product by CRT, and binding makes the opened message
// the committed one.
#[derive(Clone)]
pub(crate) struct SameSecretLinkageStatement {
    pub(crate) public_matrix_seed_hash: String,
    // One constant commitment per Q_share limb, in limb order.
    pub(crate) commitments: Vec<SetupCommitmentValue>,
}

// Recipient-private VSS opening statement. The proof opens the source
// trustee's committed Shamir coefficient polynomials to hidden coefficient
// vectors and proves the recipient share vector is their lifted evaluation at
// the recipient trustee point, with a hidden carry vector:
//   sum_k alpha_j^k F_k - q_l * carry = share_j
// over the integers. The linear relation is checked over the setup commitment
// fields; bounded cross-field consistency gives the integer lift.
pub(crate) struct PrivateVssShareStatement {
    pub(crate) public_matrix_seed_hash: String,
    pub(crate) private_envelope_aad_hash: String,
    pub(crate) source_trustee_identity: String,
    pub(crate) source_trustee_roster_position: u64,
    pub(crate) recipient_identity: String,
    pub(crate) recipient_roster_position: u64,
    pub(crate) source_trustee_commitment_root: String,
    pub(crate) source_rns_limb_index: usize,
    pub(crate) source_message_modulus: u64,
    pub(crate) share_values_hash: String,
    pub(crate) share_values: Vec<u64>,
    pub(crate) coefficient_commitment_roots: Vec<String>,
    pub(crate) coefficient_commitments: Vec<SetupCommitmentValue>,
}

pub(crate) struct VssShareLinkageStatement {
    pub(crate) public_matrix_seed_hash: String,
    pub(crate) source_trustee_identity: String,
    pub(crate) source_trustee_roster_position: u64,
    pub(crate) recipient_identity: String,
    pub(crate) recipient_roster_position: u64,
    pub(crate) source_coefficient_commitment_root: String,
    pub(crate) source_recipient_share_commitment_root: String,
    pub(crate) source_rns_limb_index: usize,
    pub(crate) source_message_modulus: u64,
    pub(crate) coefficient_commitment_roots: Vec<String>,
    pub(crate) coefficient_opening_roots: Vec<String>,
    pub(crate) coefficient_commitments: Vec<VssShareLinkageCommitment>,
    pub(crate) recipient_share_commitment_root: String,
    pub(crate) recipient_share_opening_root: String,
    pub(crate) recipient_share_commitment: VssShareLinkageCommitment,
    pub(crate) additional_linkage_items: Vec<VssShareLinkageItem>,
    // The threshold-aggregate mode reuses this same share-linkage relation with
    // a unit evaluation point: proving each recipient's threshold share
    // T_{j,l} = sum_i sigma_{i->j,l} mod q_l is exactly the lincheck
    // `sum_k point^k F_k - share - q * carry = 0` with `point = 1`, the summed
    // sources standing in for the coefficient messages, T for the recipient
    // share, and the mod-q wrap for the carry. When set, the coefficient
    // commitments open recipient-share committed material and the recipient
    // commitment opens aggregate-threshold-share committed material.
    pub(crate) is_threshold_aggregate: bool,
}

#[derive(Clone)]
pub(crate) struct VssShareLinkageItem {
    pub(crate) source_trustee_identity: String,
    pub(crate) source_trustee_roster_position: u64,
    pub(crate) source_coefficient_commitment_root: String,
    pub(crate) source_recipient_share_commitment_root: String,
    pub(crate) recipient_identity: String,
    pub(crate) recipient_roster_position: u64,
    pub(crate) source_rns_limb_index: usize,
    pub(crate) source_message_modulus: u64,
    pub(crate) coefficient_commitment_roots: Vec<String>,
    pub(crate) coefficient_opening_roots: Vec<String>,
    pub(crate) coefficient_commitments: Vec<VssShareLinkageCommitment>,
    pub(crate) recipient_share_commitment_root: String,
    pub(crate) recipient_share_opening_root: String,
    pub(crate) recipient_share_commitment: VssShareLinkageCommitment,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct VssPublicCoefficientWitnessSlot {
    pub(crate) source_trustee_roster_position: u64,
    pub(crate) source_rns_limb_index: usize,
    pub(crate) source_message_modulus: u64,
    pub(crate) shamir_coefficient_index: usize,
    pub(crate) commitment_root: String,
    pub(crate) opening_root: String,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SameSecretBridgeStatement {
    pub(crate) public_matrix_seed_hash: String,
    pub(crate) source_trustee_identity: String,
    pub(crate) source_trustee_roster_position: u64,
    pub(crate) target_basis_hash: String,
    pub(crate) target_rns_primes: Vec<u64>,
    pub(crate) target_constant_commitment_roots: Vec<String>,
    pub(crate) target_constant_commitments: Vec<VssShareLinkageCommitment>,
}

pub(crate) struct TargetDecryptionShareRoleStatement {
    pub(crate) target_role: String,
    pub(crate) target_ciphertext_component_one: Vec<u64>,
    pub(crate) released_partial_decryption: Vec<u64>,
    pub(crate) smudging_commitment_roots: Vec<String>,
    pub(crate) smudging_commitments: Vec<VssShareLinkageCommitment>,
}

pub(crate) struct TargetDecryptionShareLimbStatement {
    pub(crate) target_rns_limb_index: usize,
    pub(crate) target_rns_prime: u64,
    pub(crate) aggregate_commitment_root: String,
    pub(crate) aggregate_opening_root: String,
    pub(crate) aggregate_commitment: VssShareLinkageCommitment,
    pub(crate) role_statements: Vec<TargetDecryptionShareRoleStatement>,
}

pub(crate) struct TargetDecryptionShareStatement {
    pub(crate) public_matrix_seed_hash: String,
    pub(crate) target_basis_hash: String,
    pub(crate) trustee_identity: String,
    pub(crate) trustee_roster_position: u64,
    pub(crate) active_credential_binding_root: String,
    pub(crate) interpolation_point: u64,
    pub(crate) aggregate_message_coefficient_bound: u64,
    pub(crate) smudging_commitment_set_root: String,
    pub(crate) limb_statements: Vec<TargetDecryptionShareLimbStatement>,
    pub(crate) smudging_polynomial_degree: usize,
    pub(crate) smudging_coefficient_bound: i64,
    pub(crate) smudging_signed_coefficient_offset: i64,
    pub(crate) smudging_message_coefficient_bound: u64,
    pub(crate) plaintext_multiple: u64,
}

// Ceremony context the proof is bound to: the shared base fields, the proof
// family label, and the family's ordered labeled binding roots. Every field
// enters the statement hash, so a proof transplanted to another ceremony,
// roster position, epoch, family, or binding object fails the transcript
// rebinding. The binding label list is fixed per family: the standalone bridge
// carries no contextual binding roots because its canonical source and target
// commitments enter the statement directly, while the key-bearing
// evaluation-key family binds the frozen schedule and bridge proof record.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SuccinctSetupProofContext {
    pub(crate) proof_family: String,
    pub(crate) ceremony_id: String,
    pub(crate) manifest_hash: String,
    pub(crate) roster_hash: String,
    pub(crate) trustee_identity: String,
    pub(crate) trustee_roster_position: u64,
    pub(crate) setup_epoch: String,
    pub(crate) binding_roots: Vec<(String, String)>,
}

// A trustee's batched statement: every listed key share is proven against the
// same committed secret, with one trace commitment and one batched FRI
// instance per active limb field covering all listed keys.
pub(crate) struct TrusteeEvaluationKeyStatement {
    pub(crate) context: SuccinctSetupProofContext,
    pub(crate) ring_degree: usize,
    pub(crate) keys: Vec<EvaluationKeyShareDescriptor>,
    pub(crate) same_secret_linkage: Option<SameSecretLinkageStatement>,
    pub(crate) private_vss_share: Option<PrivateVssShareStatement>,
    pub(crate) vss_share_linkage: Option<VssShareLinkageStatement>,
    pub(crate) same_secret_bridge: Option<SameSecretBridgeStatement>,
    pub(crate) target_decryption_share: Option<TargetDecryptionShareStatement>,
}

pub(crate) struct TrusteeEvaluationKeyWitness {
    pub(crate) secret_coefficients: Vec<i64>,
    // error_coefficients_by_key[key][digit] follows each key's digit count.
    pub(crate) error_coefficients_by_key: Vec<Vec<Vec<i64>>>,
    // Linkage witnesses, present exactly when the statement carries the
    // same-secret linkage or same-secret bridge: the binary
    // negative-indicator vector and the ternary opening randomness per bound
    // commitment and column.
    pub(crate) negative_indicator_coefficients: Vec<i64>,
    pub(crate) opening_randomness_by_limb: Vec<Vec<Vec<i64>>>,
    // Private VSS witnesses, present exactly for the recipient-private VSS
    // family. Coefficient messages are canonical non-negative residues stored
    // as signed integers for shared residue conversion.
    pub(crate) private_vss_coefficient_messages_by_shamir_index: Vec<Vec<i64>>,
    pub(crate) private_vss_opening_randomness_by_shamir_index: Vec<Vec<Vec<i64>>>,
    pub(crate) private_vss_carry_witnesses: Vec<i64>,
    pub(crate) vss_public_coefficient_messages_by_shamir_index: Vec<Vec<i64>>,
    pub(crate) vss_public_recipient_share_messages: Vec<i64>,
    pub(crate) vss_public_coefficient_opening_randomness_by_shamir_index: Vec<Vec<Vec<i64>>>,
    pub(crate) vss_public_recipient_share_opening_randomness: Vec<Vec<i64>>,
    pub(crate) vss_public_carry_witnesses: Vec<i64>,
    pub(crate) vss_public_recipient_share_messages_by_item: Vec<Vec<i64>>,
    pub(crate) vss_public_recipient_share_opening_randomness_by_item: Vec<Vec<Vec<i64>>>,
    pub(crate) vss_public_carry_witnesses_by_item: Vec<Vec<i64>>,
    pub(crate) target_decryption_message_vectors: Vec<Vec<i64>>,
    pub(crate) target_decryption_opening_randomness_by_commitment: Vec<Vec<Vec<i64>>>,
    // Committed-material regeneration inputs, one per bound message in the
    // statement's bound-commitment order: the holder's private deterministic
    // seed and the commitment-context hash. The prover regenerates the trees
    // from these and refuses if any regenerated root differs from the
    // statement's roots; it never commits fresh trees inside a proof.
    pub(crate) vss_committed_material_seeds_by_bound_message: Vec<String>,
    pub(crate) vss_committed_material_context_hashes_by_bound_message: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TargetDecryptionMessageClaimKind {
    AggregateOpening,
    SmudgingOpening,
}

impl EvaluationKeyShareDescriptor {
    // Error vectors carried by this key: one per gadget digit for key-switch
    // kinds, one in total for the public-key share relation.
    pub(crate) fn digit_count(&self) -> usize {
        match self.kind {
            EvaluationKeyShareKind::PublicKeyShare => 1,
            _ => self.level + 1,
        }
    }

    // Limb width of every component_b_by_digit row: the key's active limbs.
    fn limb_width(&self) -> usize {
        self.level + 1
    }

    pub(crate) fn validate_shape(&self, ring_degree: usize) -> CanonicalResult<()> {
        validate_context_token("keySwitchDomain", &self.key_switch_domain)?;
        validate_context_token("keySwitchSeedHex", &self.key_switch_seed_hex)?;
        if self.level + 1 > DATA_PRIMES.len() {
            return Err(invalid_succinct_setup_proof(
                "key level is outside the selected data basis",
            ));
        }
        if self.component_b_by_digit.len() != self.digit_count()
            || self.component_b_by_digit.iter().any(|by_limb| {
                by_limb.len() != self.limb_width()
                    || by_limb
                        .iter()
                        .any(|component| component.len() != ring_degree)
            })
        {
            return Err(invalid_succinct_setup_proof(
                "key component material shape does not match its level and ring degree",
            ));
        }
        for component_b_by_limb in &self.component_b_by_digit {
            for (rns_limb_index, component_b) in component_b_by_limb.iter().enumerate() {
                let modulus = DATA_PRIMES[rns_limb_index];
                if component_b
                    .iter()
                    .any(|coefficient| *coefficient >= modulus)
                {
                    return Err(invalid_succinct_setup_proof(
                        "key component material contains noncanonical Q_share residues",
                    ));
                }
            }
        }
        match self.kind {
            EvaluationKeyShareKind::RelinearizationRoundOne => {
                if !self.round_one_aggregate_diagonal.is_empty() {
                    return Err(invalid_succinct_setup_proof(
                        "round-one key must not carry a round-one aggregate diagonal",
                    ));
                }
            }
            EvaluationKeyShareKind::RelinearizationRoundTwo => {
                if self.round_one_aggregate_diagonal.len() != self.digit_count() {
                    return Err(invalid_succinct_setup_proof(
                        "round-two key requires one aggregate diagonal per digit",
                    ));
                }
                for (digit_index, aggregate) in self.round_one_aggregate_diagonal.iter().enumerate()
                {
                    if aggregate.len() != ring_degree
                        || aggregate
                            .iter()
                            .any(|value| *value >= DATA_PRIMES[digit_index])
                    {
                        return Err(invalid_succinct_setup_proof(
                            "round-two aggregate diagonal shape or residue is out of range",
                        ));
                    }
                }
            }
            EvaluationKeyShareKind::GaloisRotation { galois_element } => {
                if !self.round_one_aggregate_diagonal.is_empty() {
                    return Err(invalid_succinct_setup_proof(
                        "Galois key must not carry a round-one aggregate diagonal",
                    ));
                }
                // The statement binds the scheduled element as transported;
                // the automorphism acts through its residue modulo the ring
                // order, so frozen full-scale schedule elements stay valid
                // on reduced development rings.
                if galois_element.is_multiple_of(2) || galois_element <= 1 {
                    return Err(invalid_succinct_setup_proof(
                        "Galois element must be a nontrivial odd element",
                    ));
                }
            }
            EvaluationKeyShareKind::PublicKeyShare => {
                if !self.round_one_aggregate_diagonal.is_empty() {
                    return Err(invalid_succinct_setup_proof(
                        "public-key share must not carry a round-one aggregate diagonal",
                    ));
                }
                // The share spans the whole data basis and the sample domain
                // is pinned to the accepted common reference polynomial.
                if self.level + 1 != DATA_PRIMES.len() {
                    return Err(invalid_succinct_setup_proof(
                        "public-key share must span every Q_share limb",
                    ));
                }
                if self.key_switch_domain != PUBLIC_KEY_SHARE_COMMON_REFERENCE_LABEL {
                    return Err(invalid_succinct_setup_proof(
                        "public-key share sample domain must be the accepted common reference label",
                    ));
                }
            }
        }

        Ok(())
    }

    // The public sample a_{j,l} of one digit at one limb: the deterministic
    // key-switch sample for key-switch kinds, the seed-derived common
    // reference polynomial for the public-key share relation.
    pub(crate) fn public_sample(
        &self,
        digit_index: usize,
        modulus: u64,
        ring_degree: usize,
    ) -> Vec<u64> {
        match self.kind {
            EvaluationKeyShareKind::PublicKeyShare => dense_public_residues_with_degree(
                &self.key_switch_seed_hex,
                &self.key_switch_domain,
                modulus,
                ring_degree,
            ),
            _ => public_key_switch_sample(
                &self.key_switch_domain,
                &self.key_switch_seed_hex,
                digit_index,
                modulus,
                ring_degree,
            ),
        }
    }
}

impl VssShareLinkageStatement {
    pub(crate) fn item_count(&self) -> usize {
        1 + self.additional_linkage_items.len()
    }

    pub(crate) fn packed_ring_degree(&self, ring_degree: usize) -> CanonicalResult<usize> {
        Ok(ring_degree)
    }

    fn append_coefficient_witness_slots(
        slots: &mut Vec<VssPublicCoefficientWitnessSlot>,
        slot_indices_by_item: &mut Vec<Vec<usize>>,
        source_trustee_roster_position: u64,
        source_rns_limb_index: usize,
        source_message_modulus: u64,
        coefficient_commitment_roots: &[String],
        coefficient_opening_roots: &[String],
    ) {
        let mut item_slot_indices = Vec::with_capacity(coefficient_commitment_roots.len());
        for (shamir_coefficient_index, (commitment_root, opening_root)) in
            coefficient_commitment_roots
                .iter()
                .zip(coefficient_opening_roots.iter())
                .enumerate()
        {
            let slot = VssPublicCoefficientWitnessSlot {
                source_trustee_roster_position,
                source_rns_limb_index,
                source_message_modulus,
                shamir_coefficient_index,
                commitment_root: commitment_root.clone(),
                opening_root: opening_root.clone(),
            };
            let slot_index = if let Some(existing_index) = slots
                .iter()
                .position(|existing_slot| existing_slot == &slot)
            {
                existing_index
            } else {
                slots.push(slot);
                slots.len() - 1
            };
            item_slot_indices.push(slot_index);
        }
        slot_indices_by_item.push(item_slot_indices);
    }

    fn coefficient_witness_slot_layout(
        &self,
    ) -> (Vec<VssPublicCoefficientWitnessSlot>, Vec<Vec<usize>>) {
        let mut slots = Vec::new();
        let mut slot_indices_by_item = Vec::with_capacity(self.item_count());
        Self::append_coefficient_witness_slots(
            &mut slots,
            &mut slot_indices_by_item,
            self.source_trustee_roster_position,
            self.source_rns_limb_index,
            self.source_message_modulus,
            &self.coefficient_commitment_roots,
            &self.coefficient_opening_roots,
        );
        for item in &self.additional_linkage_items {
            Self::append_coefficient_witness_slots(
                &mut slots,
                &mut slot_indices_by_item,
                item.source_trustee_roster_position,
                item.source_rns_limb_index,
                item.source_message_modulus,
                &item.coefficient_commitment_roots,
                &item.coefficient_opening_roots,
            );
        }

        (slots, slot_indices_by_item)
    }

    pub(crate) fn coefficient_witness_slots(&self) -> Vec<VssPublicCoefficientWitnessSlot> {
        self.coefficient_witness_slot_layout().0
    }

    pub(crate) fn packed_message_bounds(&self) -> Vec<u64> {
        let (coefficient_slots, _) = self.coefficient_witness_slot_layout();
        let mut bounds = coefficient_slots
            .iter()
            .map(|slot| slot.source_message_modulus)
            .collect::<Vec<_>>();
        bounds.push(self.source_message_modulus);
        bounds.extend(
            self.additional_linkage_items
                .iter()
                .map(|item| item.source_message_modulus),
        );

        bounds
    }

    pub(crate) fn coefficient_witness_slot_indices_by_item(&self) -> Vec<Vec<usize>> {
        self.coefficient_witness_slot_layout().1
    }

    pub(crate) fn unique_coefficient_witness_slot_count(&self) -> usize {
        self.coefficient_witness_slot_layout().0.len()
    }

    pub(crate) fn total_coefficient_commitment_count(&self) -> usize {
        self.coefficient_commitments.len()
            + self
                .additional_linkage_items
                .iter()
                .map(|item| item.coefficient_commitments.len())
                .sum::<usize>()
    }
}

impl TrusteeEvaluationKeyStatement {
    // Ordered committed-material commitments the material-binding families
    // open, one per bound message, in the bound-message order the limb
    // layouts use: vss-public - unique coefficient slots (slot order) then
    // per-item recipient shares (item order); bridge - target constants in
    // target order; target-decryption - per limb statement the aggregate then
    // its smudging commitments. Every commitment-field limb proof opens its
    // own field's tree of each bound commitment.
    pub(crate) fn vss_committed_material_bound_commitments(
        &self,
    ) -> Vec<&VssShareLinkageCommitment> {
        if let Some(share_linkage) = &self.vss_share_linkage {
            let slot_indices_by_item = share_linkage.coefficient_witness_slot_indices_by_item();
            let slot_count = share_linkage.unique_coefficient_witness_slot_count();
            let mut commitment_by_slot: Vec<Option<&VssShareLinkageCommitment>> =
                vec![None; slot_count];
            let commitments_by_item: Vec<&[VssShareLinkageCommitment]> =
                std::iter::once(share_linkage.coefficient_commitments.as_slice())
                    .chain(
                        share_linkage
                            .additional_linkage_items
                            .iter()
                            .map(|item| item.coefficient_commitments.as_slice()),
                    )
                    .collect();
            for (item_index, slot_indices) in slot_indices_by_item.iter().enumerate() {
                for (coefficient_index, slot_index) in slot_indices.iter().enumerate() {
                    if commitment_by_slot[*slot_index].is_none() {
                        commitment_by_slot[*slot_index] =
                            Some(&commitments_by_item[item_index][coefficient_index]);
                    }
                }
            }
            let mut bound_commitments = commitment_by_slot
                .into_iter()
                .map(|commitment| {
                    commitment.expect("every coefficient witness slot originates from an item")
                })
                .collect::<Vec<_>>();
            bound_commitments.push(&share_linkage.recipient_share_commitment);
            for item in &share_linkage.additional_linkage_items {
                bound_commitments.push(&item.recipient_share_commitment);
            }

            bound_commitments
        } else if let Some(bridge) = &self.same_secret_bridge {
            bridge.target_constant_commitments.iter().collect()
        } else if let Some(target_decryption_share) = &self.target_decryption_share {
            target_decryption_share
                .limb_statements
                .iter()
                .flat_map(|limb_statement| {
                    std::iter::once(&limb_statement.aggregate_commitment).chain(
                        limb_statement
                            .role_statements
                            .iter()
                            .flat_map(|role_statement| role_statement.smudging_commitments.iter()),
                    )
                })
                .collect()
        } else {
            Vec::new()
        }
    }

    pub(crate) const TARGET_DECRYPTION_AGGREGATE_MESSAGE_MASKED_CLAIM_FIELD_COUNT: usize = 5;
    pub(crate) const TARGET_DECRYPTION_SMUDGING_MESSAGE_MASKED_CLAIM_FIELD_COUNT: usize = 4;

    // The number of active limb fields: one past the highest key level. A
    // standalone same-secret bridge statement is active on every source
    // commitment field, where its opening relations live.
    pub(crate) fn limb_count(&self) -> usize {
        if self.private_vss_share.is_some() || self.vss_share_linkage.is_some() {
            return SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len();
        }
        let key_limb_count = self.keys.iter().map(|key| key.level + 1).max();
        if self.same_secret_bridge.is_some() {
            return key_limb_count
                .into_iter()
                .chain(std::iter::once(SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len()))
                .max()
                .unwrap_or(SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len());
        }
        if let Some(target_decryption_share) = &self.target_decryption_share {
            return target_decryption_share
                .limb_statements
                .iter()
                .map(|statement| statement.target_rns_limb_index + 1)
                .chain(std::iter::once(SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len()))
                .max()
                .unwrap_or(SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len());
        }
        key_limb_count.unwrap_or(if self.same_secret_linkage.is_some() {
            SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len()
        } else {
            0
        })
    }

    pub(crate) fn proof_limb_indices(&self) -> Vec<usize> {
        if let Some(target_decryption_share) = &self.target_decryption_share {
            let mut limb_indices =
                (0..SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len()).collect::<Vec<_>>();
            for limb_statement in &target_decryption_share.limb_statements {
                if !limb_indices.contains(&limb_statement.target_rns_limb_index) {
                    limb_indices.push(limb_statement.target_rns_limb_index);
                }
            }
            return limb_indices;
        }

        (0..self.limb_count()).collect()
    }

    #[cfg(test)]
    pub(crate) fn limb_moduli(&self) -> Vec<u64> {
        self.proof_limb_indices()
            .into_iter()
            .map(|limb_index| DATA_PRIMES[limb_index])
            .collect()
    }

    pub(crate) fn proof_limb_count(&self) -> usize {
        self.proof_limb_indices().len()
    }

    // Indices of the keys whose level reaches the given limb.
    pub(crate) fn active_key_indices(&self, limb_index: usize) -> Vec<usize> {
        self.keys
            .iter()
            .enumerate()
            .filter(|(_, key)| key.level >= limb_index)
            .map(|(key_index, _)| key_index)
            .collect()
    }

    // Number of linkage opening-randomness logical columns active in a limb:
    // the linkage relations live only in the commitment fields (the first
    // three data primes). Only the BDLOP source linkage carries opening
    // randomness; the committed-material bridge targets hide
    // via their tree masks and salts and have no algebraic opening randomness.
    pub(crate) fn linkage_randomness_count(&self, limb_index: usize) -> usize {
        if limb_index >= SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() {
            return 0;
        }
        if let Some(linkage) = &self.same_secret_linkage {
            return linkage.commitments.len() * SETUP_COMMITMENT_RANDOMNESS_WIDTH;
        }

        0
    }

    pub(crate) fn private_vss_randomness_count(&self, limb_index: usize) -> usize {
        match &self.private_vss_share {
            Some(statement) if limb_index < SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() => {
                statement.coefficient_commitments.len() * SETUP_COMMITMENT_RANDOMNESS_WIDTH
            }
            _ => 0,
        }
    }

    pub(crate) fn vss_public_coefficient_count(&self, limb_index: usize) -> usize {
        match &self.vss_share_linkage {
            Some(statement) if limb_index < SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() => {
                statement.unique_coefficient_witness_slot_count()
            }
            _ => 0,
        }
    }

    pub(crate) fn vss_public_coefficient_relation_count(&self, limb_index: usize) -> usize {
        match &self.vss_share_linkage {
            Some(statement) if limb_index < SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() => {
                statement.total_coefficient_commitment_count()
            }
            _ => 0,
        }
    }

    pub(crate) fn vss_public_item_count(&self, limb_index: usize) -> usize {
        match &self.vss_share_linkage {
            Some(statement) if limb_index < SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() => {
                statement.item_count()
            }
            _ => 0,
        }
    }

    pub(crate) fn vss_public_message_bounds(&self, limb_index: usize) -> Vec<u64> {
        match &self.vss_share_linkage {
            Some(statement) if limb_index < SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() => {
                statement.packed_message_bounds()
            }
            _ => Vec::new(),
        }
    }

    pub(crate) fn same_secret_bridge_message_bounds(&self, limb_index: usize) -> Vec<u64> {
        match &self.same_secret_bridge {
            Some(statement) if limb_index < SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() => {
                statement.target_rns_primes.clone()
            }
            _ => Vec::new(),
        }
    }

    fn target_decryption_limb_message_count(
        limb_statement: &TargetDecryptionShareLimbStatement,
    ) -> usize {
        1 + limb_statement
            .role_statements
            .iter()
            .map(|role_statement| role_statement.smudging_commitments.len())
            .sum::<usize>()
    }

    pub(crate) fn target_decryption_total_message_count(&self) -> usize {
        self.target_decryption_share
            .as_ref()
            .map(|statement| {
                statement
                    .limb_statements
                    .iter()
                    .map(Self::target_decryption_limb_message_count)
                    .sum()
            })
            .unwrap_or(0)
    }

    pub(crate) fn target_decryption_total_message_digit_count(&self) -> usize {
        self.target_decryption_total_message_count()
            * crate::bgv::setup::vss_commitment::VSS_PUBLIC_MESSAGE_DIGIT_COUNT
    }

    fn target_decryption_limb_message_range(
        &self,
        target_rns_limb_index: usize,
    ) -> Option<std::ops::Range<usize>> {
        let statement = self.target_decryption_share.as_ref()?;
        let mut offset = 0_usize;
        for limb_statement in &statement.limb_statements {
            let message_count = Self::target_decryption_limb_message_count(limb_statement);
            if limb_statement.target_rns_limb_index == target_rns_limb_index {
                return Some(offset..offset + message_count);
            }
            offset += message_count;
        }

        None
    }

    pub(crate) fn target_decryption_message_claim_kind(
        &self,
        global_message_index: usize,
    ) -> Option<TargetDecryptionMessageClaimKind> {
        let statement = self.target_decryption_share.as_ref()?;
        let mut offset = 0_usize;
        for limb_statement in &statement.limb_statements {
            let limb_message_count = Self::target_decryption_limb_message_count(limb_statement);
            if global_message_index < offset + limb_message_count {
                return Some(if global_message_index == offset {
                    TargetDecryptionMessageClaimKind::AggregateOpening
                } else {
                    TargetDecryptionMessageClaimKind::SmudgingOpening
                });
            }
            offset += limb_message_count;
        }

        None
    }

    pub(crate) fn target_decryption_message_bound(
        &self,
        global_message_index: usize,
    ) -> Option<u64> {
        let statement = self.target_decryption_share.as_ref()?;
        match self.target_decryption_message_claim_kind(global_message_index)? {
            TargetDecryptionMessageClaimKind::AggregateOpening => {
                Some(statement.aggregate_message_coefficient_bound)
            }
            TargetDecryptionMessageClaimKind::SmudgingOpening => {
                Some(statement.smudging_message_coefficient_bound)
            }
        }
    }

    pub(crate) fn target_decryption_message_digit_bound(
        &self,
        global_message_index: usize,
        digit_index: usize,
    ) -> Option<u64> {
        crate::bgv::setup::vss_commitment::vss_public_message_digit_bound(
            self.target_decryption_message_bound(global_message_index)?,
            digit_index,
        )
        .ok()
    }

    pub(crate) fn target_decryption_smudging_message_global_index(&self) -> Option<usize> {
        let statement = self.target_decryption_share.as_ref()?;
        let mut offset = 0_usize;
        for limb_statement in &statement.limb_statements {
            let limb_message_count = Self::target_decryption_limb_message_count(limb_statement);
            if limb_message_count > 1 {
                return Some(offset + 1);
            }
            offset += limb_message_count;
        }

        None
    }

    fn target_decryption_message_target_limb_index(
        &self,
        global_message_index: usize,
    ) -> Option<usize> {
        let statement = self.target_decryption_share.as_ref()?;
        let mut offset = 0_usize;
        for limb_statement in &statement.limb_statements {
            let limb_message_count = Self::target_decryption_limb_message_count(limb_statement);
            if global_message_index < offset + limb_message_count {
                return Some(limb_statement.target_rns_limb_index);
            }
            offset += limb_message_count;
        }

        None
    }

    pub(crate) fn target_decryption_message_decoder_limb_index(
        &self,
        global_message_index: usize,
    ) -> Option<usize> {
        self.target_decryption_message_target_limb_index(global_message_index)
    }

    pub(crate) fn target_decryption_message_claim_limb_indices(
        &self,
        global_message_index: usize,
    ) -> Vec<usize> {
        let Some(target_rns_limb_index) =
            self.target_decryption_message_target_limb_index(global_message_index)
        else {
            return Vec::new();
        };
        let field_count = match self.target_decryption_message_claim_kind(global_message_index) {
            Some(TargetDecryptionMessageClaimKind::AggregateOpening) => {
                Self::TARGET_DECRYPTION_AGGREGATE_MESSAGE_MASKED_CLAIM_FIELD_COUNT
            }
            Some(TargetDecryptionMessageClaimKind::SmudgingOpening) => {
                Self::TARGET_DECRYPTION_SMUDGING_MESSAGE_MASKED_CLAIM_FIELD_COUNT
            }
            None => return Vec::new(),
        };
        let proof_limb_indices = self.proof_limb_indices();
        let mut selected = proof_limb_indices
            .iter()
            .copied()
            .filter(|limb_index| *limb_index < SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len())
            .collect::<Vec<_>>();
        if !selected.contains(&target_rns_limb_index)
            && proof_limb_indices.contains(&target_rns_limb_index)
        {
            selected.push(target_rns_limb_index);
        }
        for candidate in proof_limb_indices {
            if selected.len() >= field_count {
                break;
            }
            if !selected.contains(&candidate) {
                selected.push(candidate);
            }
        }

        selected
    }

    fn target_decryption_message_indices(&self, proof_limb_index: usize) -> Vec<usize> {
        let Some(statement) = self.target_decryption_share.as_ref() else {
            return Vec::new();
        };
        let mut indices = Vec::new();
        for limb_statement in &statement.limb_statements {
            if let Some(range) =
                self.target_decryption_limb_message_range(limb_statement.target_rns_limb_index)
            {
                indices.extend(range.filter(|global_message_index| {
                    self.target_decryption_message_claim_limb_indices(*global_message_index)
                        .contains(&proof_limb_index)
                }));
            }
        }

        indices
    }

    pub(crate) fn target_decryption_local_message_offset(
        &self,
        proof_limb_index: usize,
        target_rns_limb_index: usize,
    ) -> Option<usize> {
        let target_range = self.target_decryption_limb_message_range(target_rns_limb_index)?;
        self.target_decryption_message_indices(proof_limb_index)
            .into_iter()
            .position(|global_message_index| global_message_index == target_range.start)
    }

    pub(crate) fn target_decryption_message_global_index(
        &self,
        proof_limb_index: usize,
        local_message_index: usize,
    ) -> Option<usize> {
        self.target_decryption_message_indices(proof_limb_index)
            .get(local_message_index)
            .copied()
    }

    pub(crate) fn target_decryption_message_count(&self, limb_index: usize) -> usize {
        self.target_decryption_message_indices(limb_index).len()
    }

    pub(crate) fn target_decryption_message_encoding_layout(
        &self,
        proof_limb_index: usize,
        global_message_index: usize,
    ) -> CanonicalResult<crate::bgv::setup::vss_commitment::VssPublicMessageEncodingLayout> {
        let message_bound = self
            .target_decryption_message_bound(global_message_index)
            .ok_or_else(|| {
                invalid_succinct_setup_proof(
                    "target-decryption message bound is missing from the statement layout",
                )
            })?;
        let decoder_limb_index = self
            .target_decryption_message_decoder_limb_index(global_message_index)
            .ok_or_else(|| {
                invalid_succinct_setup_proof(
                    "target-decryption message decoder limb is missing from the statement layout",
                )
            })?;
        crate::bgv::setup::vss_commitment::vss_public_cross_limb_message_encoding_layout(
            message_bound,
            proof_limb_index,
            decoder_limb_index,
        )
    }

    pub(crate) fn target_decryption_message_encoding_layouts(
        &self,
        limb_index: usize,
    ) -> CanonicalResult<Vec<crate::bgv::setup::vss_commitment::VssPublicMessageEncodingLayout>>
    {
        self.target_decryption_message_indices(limb_index)
            .into_iter()
            .map(|global_message_index| {
                self.target_decryption_message_encoding_layout(limb_index, global_message_index)
            })
            .collect()
    }

    fn target_decryption_decoder_digit_count_for_layout(
        layout: crate::bgv::setup::vss_commitment::VssPublicMessageEncodingLayout,
    ) -> usize {
        (0..crate::bgv::setup::vss_commitment::VSS_PUBLIC_MESSAGE_DIGIT_COUNT)
            .filter(|digit_index| layout.digit_trit_count(*digit_index).unwrap_or(0) > 0)
            .count()
    }

    // Target-decryption relation challenges: the per-role target-share lincheck
    // rows plus the digit decoder rows. The aggregate and smudging commitments
    // are bound by the material openings and Z_H binding rows, not by
    // projection relation challenges, so no per-coordinate blocks remain.
    pub(crate) fn target_decryption_relation_count(&self, limb_index: usize) -> usize {
        match &self.target_decryption_share {
            Some(statement) => {
                let target_relation_count = statement
                    .limb_statements
                    .iter()
                    .find(|limb_statement| limb_statement.target_rns_limb_index == limb_index)
                    .map(|limb_statement| {
                        limb_statement.role_statements.len() * LINCHECK_REPETITIONS
                    })
                    .unwrap_or(0);
                let decoder_relation_count = self
                    .target_decryption_message_encoding_layouts(limb_index)
                    .unwrap_or_default()
                    .into_iter()
                    .map(Self::target_decryption_decoder_digit_count_for_layout)
                    .sum::<usize>()
                    * LINCHECK_REPETITIONS;
                target_relation_count + decoder_relation_count
            }
            None => 0,
        }
    }
}
