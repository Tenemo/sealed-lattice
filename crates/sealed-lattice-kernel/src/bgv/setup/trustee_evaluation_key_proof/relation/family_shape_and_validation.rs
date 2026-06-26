use super::super::*;
use super::*;

const STATEMENT_HASH_DOMAIN: &str = "sealed-lattice/setup/trustee-evaluation-key/statement-v2";
const PROTOCOL_HASH_HEX_LENGTH: usize = 128;
const MAX_CONTEXT_TOKEN_BYTES: usize = 512;

pub(crate) const SAME_SECRET_LINKAGE_ANCHOR_BINDING_LABELS: [&str; 1] =
    ["vssCoefficientCommitmentMaterialRoot"];
pub(crate) const PUBLIC_KEY_SHARE_SUCCINCT_BINDING_LABELS: [&str; 2] =
    ["sameSecretStatementRoot", "sameSecretProofRoot"];
pub(crate) const PRIVATE_VSS_SHARE_BINDING_LABELS: [&str; 3] = [
    "sourceTrusteeCommitmentRoot",
    "privateEnvelopeAadHash",
    "shareValuesHash",
];
pub(crate) const COMPACT_VSS_SHARE_LINKAGE_BINDING_LABELS: [&str; 2] = [
    "sourceCoefficientCommitmentRoot",
    "sourceRecipientShareCommitmentRoot",
];
pub(crate) const COMPACT_SAME_SECRET_BRIDGE_BINDING_LABELS: [&str; 4] = [
    "compactSameSecretBridgeStatementRoot",
    "sameSecretStatementRoot",
    "sameSecretProofRoot",
    "sameSecretProofFamilyBindingRoot",
];
pub(crate) const TARGET_DECRYPTION_SHARE_BINDING_LABELS: [&str; 3] = [
    "targetShareProofStatementRoot",
    "aggregateCommitmentRoot",
    "smudgingCommitmentSetRoot",
];
pub(crate) const TRUSTEE_EVALUATION_KEY_BINDING_LABELS: [&str; 5] = [
    "requiredGaloisSetHash",
    "evaluatorKeyScheduleRoot",
    "keySwitchDecompositionHash",
    "sameSecretStatementRoot",
    "sameSecretProofRoot",
];

// The statement family shape, decided by the key list: keyless statements are
// the same-secret linkage anchor, a single public-key share descriptor is the
// public-key share family, and key-switch descriptors are the trustee
// evaluation-key family. A public-key share descriptor mixed with key-switch
// descriptors is refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum SuccinctSetupProofFamilyShape {
    SameSecretLinkageAnchor,
    PublicKeyShare,
    PrivateVssShare,
    CompactVssShareLinkage,
    CompactSameSecretBridge,
    TargetDecryptionShare,
    TrusteeEvaluationKey,
}

impl SuccinctSetupProofFamilyShape {
    pub(crate) fn from_key_kinds(kinds: &[EvaluationKeyShareKind]) -> CanonicalResult<Self> {
        if kinds.is_empty() {
            return Ok(Self::SameSecretLinkageAnchor);
        }
        let public_key_share_count = kinds
            .iter()
            .filter(|kind| matches!(kind, EvaluationKeyShareKind::PublicKeyShare))
            .count();
        if public_key_share_count == 0 {
            return Ok(Self::TrusteeEvaluationKey);
        }
        if kinds.len() == 1 {
            return Ok(Self::PublicKeyShare);
        }

        Err(invalid_succinct_setup_proof(
            "the public-key share descriptor must be the only statement key",
        ))
    }

    pub(crate) fn proof_family(self) -> &'static str {
        match self {
            Self::SameSecretLinkageAnchor => super::SAME_SECRET_LINKAGE_ANCHOR_PROOF_FAMILY,
            Self::PublicKeyShare => super::PUBLIC_KEY_SHARE_PROOF_FAMILY,
            Self::PrivateVssShare => super::PRIVATE_VSS_SHARE_PROOF_FAMILY,
            Self::CompactVssShareLinkage => super::COMPACT_VSS_SHARE_LINKAGE_PROOF_FAMILY,
            Self::CompactSameSecretBridge => super::COMPACT_SAME_SECRET_BRIDGE_PROOF_FAMILY,
            Self::TargetDecryptionShare => super::TARGET_DECRYPTION_SHARE_PROOF_FAMILY,
            Self::TrusteeEvaluationKey => super::TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
        }
    }

    pub(crate) fn binding_labels(self) -> &'static [&'static str] {
        match self {
            Self::SameSecretLinkageAnchor => &SAME_SECRET_LINKAGE_ANCHOR_BINDING_LABELS,
            Self::PublicKeyShare => &PUBLIC_KEY_SHARE_SUCCINCT_BINDING_LABELS,
            Self::PrivateVssShare => &PRIVATE_VSS_SHARE_BINDING_LABELS,
            Self::CompactVssShareLinkage => &COMPACT_VSS_SHARE_LINKAGE_BINDING_LABELS,
            Self::CompactSameSecretBridge => &COMPACT_SAME_SECRET_BRIDGE_BINDING_LABELS,
            Self::TargetDecryptionShare => &TARGET_DECRYPTION_SHARE_BINDING_LABELS,
            Self::TrusteeEvaluationKey => &TRUSTEE_EVALUATION_KEY_BINDING_LABELS,
        }
    }
}

fn append_u64(preimage: &mut Vec<u8>, value: u64) {
    preimage.extend_from_slice(&value.to_le_bytes());
}

fn append_usize(preimage: &mut Vec<u8>, value: usize) {
    append_u64(preimage, value as u64);
}

fn append_len_prefixed_str(preimage: &mut Vec<u8>, value: &str) {
    append_usize(preimage, value.len());
    preimage.extend_from_slice(value.as_bytes());
}

pub(crate) fn validate_context_token(field_name: &str, value: &str) -> CanonicalResult<()> {
    if value.is_empty() || value.len() > MAX_CONTEXT_TOKEN_BYTES {
        return Err(invalid_succinct_setup_proof(format!(
            "{field_name} must be a non-empty bounded setup context token",
        )));
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@' | b'+')
    }) {
        return Err(invalid_succinct_setup_proof(format!(
            "{field_name} contains a character outside the setup context token alphabet",
        )));
    }

    Ok(())
}

pub(crate) fn validate_protocol_hash_hex(field_name: &str, value: &str) -> CanonicalResult<()> {
    if value.len() == PROTOCOL_HASH_HEX_LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }

    Err(invalid_succinct_setup_proof(format!(
        "{field_name} must be a lowercase 512-bit protocol hash",
    )))
}

impl SuccinctSetupProofContext {
    fn validate_for_statement(&self, shape: SuccinctSetupProofFamilyShape) -> CanonicalResult<()> {
        validate_context_token("proofFamily", &self.proof_family)?;
        validate_context_token("ceremonyId", &self.ceremony_id)?;
        validate_protocol_hash_hex("manifestHash", &self.manifest_hash)?;
        validate_protocol_hash_hex("rosterHash", &self.roster_hash)?;
        validate_context_token("trusteeIdentity", &self.trustee_identity)?;
        validate_context_token("setupEpoch", &self.setup_epoch)?;
        if self.proof_family != shape.proof_family() {
            return Err(invalid_succinct_setup_proof(
                "statement family does not match its key and linkage shape",
            ));
        }
        let expected_labels = shape.binding_labels();
        if self.binding_roots.len() != expected_labels.len()
            || self
                .binding_roots
                .iter()
                .zip(expected_labels.iter())
                .any(|((label, _), expected)| label != expected)
        {
            return Err(invalid_succinct_setup_proof(
                "statement binding roots do not match the family binding labels",
            ));
        }
        for (binding_label, binding_root) in &self.binding_roots {
            validate_context_token("bindingRootLabel", binding_label)?;
            validate_protocol_hash_hex("bindingRoot", binding_root)?;
        }

        Ok(())
    }
}

impl TrusteeEvaluationKeyStatement {
    pub(in crate::bgv::setup) fn statement_hash(&self) -> [u8; 64] {
        let mut preimage = Vec::new();
        for context_field in [
            self.context.proof_family.as_str(),
            self.context.ceremony_id.as_str(),
            self.context.manifest_hash.as_str(),
            self.context.roster_hash.as_str(),
            self.context.trustee_identity.as_str(),
        ] {
            append_len_prefixed_str(&mut preimage, context_field);
        }
        append_usize(&mut preimage, self.context.binding_roots.len());
        for (binding_label, binding_root) in &self.context.binding_roots {
            for binding_field in [binding_label.as_str(), binding_root.as_str()] {
                append_len_prefixed_str(&mut preimage, binding_field);
            }
        }
        append_u64(&mut preimage, self.context.trustee_roster_position);
        append_len_prefixed_str(&mut preimage, &self.context.setup_epoch);
        preimage.push(0);
        append_usize(&mut preimage, self.ring_degree);
        append_usize(&mut preimage, self.keys.len());
        for key in &self.keys {
            preimage.extend_from_slice(&key.kind.tag_bytes());
            append_usize(&mut preimage, key.level);
            append_len_prefixed_str(&mut preimage, &key.key_switch_domain);
            append_len_prefixed_str(&mut preimage, &key.key_switch_seed_hex);
            for component_b_by_limb in &key.component_b_by_digit {
                for component_b in component_b_by_limb {
                    preimage.extend_from_slice(&coefficient_vector_hash(component_b));
                }
            }
            for aggregate in &key.round_one_aggregate_diagonal {
                preimage.extend_from_slice(&coefficient_vector_hash(aggregate));
            }
        }
        if let Some(linkage) = &self.same_secret_linkage {
            preimage.push(1);
            append_len_prefixed_str(&mut preimage, &linkage.public_matrix_seed_hash);
            append_usize(&mut preimage, linkage.commitments.len());
            for commitment in &linkage.commitments {
                append_usize(&mut preimage, commitment.source_rns_limb_index);
                preimage.extend_from_slice(&commitment.source_message_modulus.to_le_bytes());
                for limb in &commitment.limbs {
                    for row in &limb.rows {
                        preimage.extend_from_slice(&coefficient_vector_hash(row));
                    }
                }
            }
        } else {
            preimage.push(0);
        }
        if let Some(private_vss_share) = &self.private_vss_share {
            preimage.push(1);
            for field in [
                private_vss_share.public_matrix_seed_hash.as_str(),
                private_vss_share.private_envelope_aad_hash.as_str(),
                private_vss_share.source_trustee_identity.as_str(),
                private_vss_share.recipient_identity.as_str(),
                private_vss_share.source_trustee_commitment_root.as_str(),
                private_vss_share.share_values_hash.as_str(),
            ] {
                append_len_prefixed_str(&mut preimage, field);
            }
            preimage.extend_from_slice(
                &private_vss_share
                    .source_trustee_roster_position
                    .to_le_bytes(),
            );
            preimage.extend_from_slice(&private_vss_share.recipient_roster_position.to_le_bytes());
            append_usize(&mut preimage, private_vss_share.source_rns_limb_index);
            preimage.extend_from_slice(&private_vss_share.source_message_modulus.to_le_bytes());
            append_usize(&mut preimage, private_vss_share.share_values.len());
            preimage.extend_from_slice(&coefficient_vector_hash(&private_vss_share.share_values));
            append_usize(
                &mut preimage,
                private_vss_share.coefficient_commitment_roots.len(),
            );
            for root in &private_vss_share.coefficient_commitment_roots {
                append_len_prefixed_str(&mut preimage, root);
            }
            append_usize(
                &mut preimage,
                private_vss_share.coefficient_commitments.len(),
            );
            for commitment in &private_vss_share.coefficient_commitments {
                append_usize(&mut preimage, commitment.source_rns_limb_index);
                preimage.extend_from_slice(&commitment.source_message_modulus.to_le_bytes());
                preimage.extend_from_slice(&commitment.shamir_coefficient_index.to_le_bytes());
                for limb in &commitment.limbs {
                    for row in &limb.rows {
                        preimage.extend_from_slice(&coefficient_vector_hash(row));
                    }
                }
            }
        } else {
            preimage.push(0);
        }
        if let Some(compact_vss_share_linkage) = &self.compact_vss_share_linkage {
            preimage.push(1);
            for field in [
                compact_vss_share_linkage.public_matrix_seed_hash.as_str(),
                compact_vss_share_linkage.source_trustee_identity.as_str(),
                compact_vss_share_linkage.recipient_identity.as_str(),
                compact_vss_share_linkage
                    .source_coefficient_commitment_root
                    .as_str(),
                compact_vss_share_linkage
                    .source_recipient_share_commitment_root
                    .as_str(),
                compact_vss_share_linkage
                    .recipient_share_commitment_root
                    .as_str(),
            ] {
                append_len_prefixed_str(&mut preimage, field);
            }
            preimage.extend_from_slice(
                &compact_vss_share_linkage
                    .source_trustee_roster_position
                    .to_le_bytes(),
            );
            preimage.extend_from_slice(
                &compact_vss_share_linkage
                    .recipient_roster_position
                    .to_le_bytes(),
            );
            append_usize(
                &mut preimage,
                compact_vss_share_linkage.source_rns_limb_index,
            );
            preimage.extend_from_slice(
                &compact_vss_share_linkage
                    .source_message_modulus
                    .to_le_bytes(),
            );
            append_usize(
                &mut preimage,
                compact_vss_share_linkage.coefficient_commitment_roots.len(),
            );
            for root in &compact_vss_share_linkage.coefficient_commitment_roots {
                append_len_prefixed_str(&mut preimage, root);
            }
            append_usize(
                &mut preimage,
                compact_vss_share_linkage.coefficient_commitments.len(),
            );
            for commitment in &compact_vss_share_linkage.coefficient_commitments {
                append_usize(
                    &mut preimage,
                    commitment.coordinates_by_commitment_modulus.len(),
                );
                for coordinates in &commitment.coordinates_by_commitment_modulus {
                    append_usize(&mut preimage, coordinates.len());
                    for coordinate in coordinates {
                        preimage.extend_from_slice(&coordinate.to_le_bytes());
                    }
                }
            }
            append_usize(
                &mut preimage,
                compact_vss_share_linkage
                    .recipient_share_commitment
                    .coordinates_by_commitment_modulus
                    .len(),
            );
            for coordinates in &compact_vss_share_linkage
                .recipient_share_commitment
                .coordinates_by_commitment_modulus
            {
                append_usize(&mut preimage, coordinates.len());
                for coordinate in coordinates {
                    preimage.extend_from_slice(&coordinate.to_le_bytes());
                }
            }
        }
        if let Some(compact_same_secret_bridge) = &self.compact_same_secret_bridge {
            preimage.push(1);
            for field in [
                compact_same_secret_bridge.public_matrix_seed_hash.as_str(),
                compact_same_secret_bridge.source_trustee_identity.as_str(),
                compact_same_secret_bridge.target_basis_hash.as_str(),
            ] {
                append_len_prefixed_str(&mut preimage, field);
            }
            preimage.extend_from_slice(
                &compact_same_secret_bridge
                    .source_trustee_roster_position
                    .to_le_bytes(),
            );
            append_usize(
                &mut preimage,
                compact_same_secret_bridge.target_rns_primes.len(),
            );
            for target_rns_prime in &compact_same_secret_bridge.target_rns_primes {
                preimage.extend_from_slice(&target_rns_prime.to_le_bytes());
            }
            append_usize(
                &mut preimage,
                compact_same_secret_bridge
                    .target_constant_commitment_roots
                    .len(),
            );
            for root in &compact_same_secret_bridge.target_constant_commitment_roots {
                append_len_prefixed_str(&mut preimage, root);
            }
            append_usize(
                &mut preimage,
                compact_same_secret_bridge.target_constant_commitments.len(),
            );
            for commitment in &compact_same_secret_bridge.target_constant_commitments {
                append_usize(
                    &mut preimage,
                    commitment.coordinates_by_commitment_modulus.len(),
                );
                for coordinates in &commitment.coordinates_by_commitment_modulus {
                    append_usize(&mut preimage, coordinates.len());
                    for coordinate in coordinates {
                        preimage.extend_from_slice(&coordinate.to_le_bytes());
                    }
                }
            }
        }
        if let Some(target_decryption_share) = &self.target_decryption_share {
            preimage.push(1);
            for field in [
                target_decryption_share.public_matrix_seed_hash.as_str(),
                target_decryption_share.target_basis_hash.as_str(),
                target_decryption_share.trustee_identity.as_str(),
                target_decryption_share.target_role.as_str(),
                target_decryption_share.aggregate_commitment_root.as_str(),
                target_decryption_share
                    .smudging_commitment_set_root
                    .as_str(),
            ] {
                append_len_prefixed_str(&mut preimage, field);
            }
            preimage.extend_from_slice(
                &target_decryption_share
                    .trustee_roster_position
                    .to_le_bytes(),
            );
            append_usize(&mut preimage, target_decryption_share.target_rns_limb_index);
            preimage.extend_from_slice(&target_decryption_share.target_rns_prime.to_le_bytes());
            preimage.extend_from_slice(&target_decryption_share.interpolation_point.to_le_bytes());
            append_usize(
                &mut preimage,
                target_decryption_share
                    .target_ciphertext_component_one
                    .len(),
            );
            preimage.extend_from_slice(&coefficient_vector_hash(
                &target_decryption_share.target_ciphertext_component_one,
            ));
            append_usize(
                &mut preimage,
                target_decryption_share.released_partial_decryption.len(),
            );
            preimage.extend_from_slice(&coefficient_vector_hash(
                &target_decryption_share.released_partial_decryption,
            ));
            append_usize(
                &mut preimage,
                target_decryption_share
                    .aggregate_commitment
                    .coordinates_by_commitment_modulus
                    .len(),
            );
            for coordinates in &target_decryption_share
                .aggregate_commitment
                .coordinates_by_commitment_modulus
            {
                append_usize(&mut preimage, coordinates.len());
                for coordinate in coordinates {
                    preimage.extend_from_slice(&coordinate.to_le_bytes());
                }
            }
            preimage.extend_from_slice(
                &target_decryption_share
                    .aggregate_message_coefficient_bound
                    .to_le_bytes(),
            );
            append_usize(
                &mut preimage,
                target_decryption_share.smudging_commitment_roots.len(),
            );
            for root in &target_decryption_share.smudging_commitment_roots {
                append_len_prefixed_str(&mut preimage, root);
            }
            append_usize(
                &mut preimage,
                target_decryption_share.smudging_commitments.len(),
            );
            for commitment in &target_decryption_share.smudging_commitments {
                append_usize(
                    &mut preimage,
                    commitment.coordinates_by_commitment_modulus.len(),
                );
                for coordinates in &commitment.coordinates_by_commitment_modulus {
                    append_usize(&mut preimage, coordinates.len());
                    for coordinate in coordinates {
                        preimage.extend_from_slice(&coordinate.to_le_bytes());
                    }
                }
            }
            append_usize(
                &mut preimage,
                target_decryption_share.smudging_polynomial_degree,
            );
            preimage.extend_from_slice(
                &target_decryption_share
                    .smudging_coefficient_bound
                    .to_le_bytes(),
            );
            preimage.extend_from_slice(
                &target_decryption_share
                    .smudging_signed_coefficient_offset
                    .to_le_bytes(),
            );
            preimage.extend_from_slice(
                &target_decryption_share
                    .smudging_message_coefficient_bound
                    .to_le_bytes(),
            );
            preimage.extend_from_slice(&target_decryption_share.plaintext_multiple.to_le_bytes());
        } else {
            preimage.push(0);
        }

        hash512(STATEMENT_HASH_DOMAIN, &[&preimage])
    }

    pub(in crate::bgv::setup) fn family_shape(
        &self,
    ) -> CanonicalResult<SuccinctSetupProofFamilyShape> {
        if self.private_vss_share.is_some() {
            if !self.keys.is_empty()
                || self.same_secret_linkage.is_some()
                || self.compact_vss_share_linkage.is_some()
                || self.compact_same_secret_bridge.is_some()
            {
                return Err(invalid_succinct_setup_proof(
                    "private VSS statement must not include key descriptors or same-secret linkage",
                ));
            }
            return Ok(SuccinctSetupProofFamilyShape::PrivateVssShare);
        }
        if self.compact_vss_share_linkage.is_some() {
            if !self.keys.is_empty()
                || self.same_secret_linkage.is_some()
                || self.compact_same_secret_bridge.is_some()
            {
                return Err(invalid_succinct_setup_proof(
                    "compact VSS share-linkage statement must not include key descriptors or same-secret linkage",
                ));
            }
            return Ok(SuccinctSetupProofFamilyShape::CompactVssShareLinkage);
        }
        if self.compact_same_secret_bridge.is_some() {
            if !self.keys.is_empty()
                || self.same_secret_linkage.is_some()
                || self.private_vss_share.is_some()
                || self.compact_vss_share_linkage.is_some()
                || self.target_decryption_share.is_some()
            {
                return Err(invalid_succinct_setup_proof(
                    "compact same-secret bridge statement must not mix proof families",
                ));
            }
            return Ok(SuccinctSetupProofFamilyShape::CompactSameSecretBridge);
        }
        if self.target_decryption_share.is_some() {
            if !self.keys.is_empty()
                || self.same_secret_linkage.is_some()
                || self.private_vss_share.is_some()
                || self.compact_vss_share_linkage.is_some()
                || self.compact_same_secret_bridge.is_some()
            {
                return Err(invalid_succinct_setup_proof(
                    "target-decryption share statement must not mix proof families",
                ));
            }
            return Ok(SuccinctSetupProofFamilyShape::TargetDecryptionShare);
        }
        let kinds = self.keys.iter().map(|key| key.kind).collect::<Vec<_>>();

        SuccinctSetupProofFamilyShape::from_key_kinds(&kinds)
    }

    pub(in crate::bgv::setup) fn validate_shape(&self) -> CanonicalResult<()> {
        if self.keys.is_empty()
            && self.same_secret_linkage.is_none()
            && self.private_vss_share.is_none()
            && self.compact_vss_share_linkage.is_none()
            && self.compact_same_secret_bridge.is_none()
            && self.target_decryption_share.is_none()
        {
            return Err(invalid_succinct_setup_proof(
                "trustee statement requires key shares or the same-secret linkage anchor",
            ));
        }
        let shape = self.family_shape()?;
        let linkage_commitment_count = self
            .same_secret_linkage
            .as_ref()
            .map(|linkage| linkage.commitments.len());
        match shape {
            SuccinctSetupProofFamilyShape::SameSecretLinkageAnchor => {
                // The anchor proves the whole constant-commitment set, one
                // commitment per Q_share limb, over the setup commitment
                // fields. Subsets leave later families without a canonical
                // anchor target, and supersets sit outside the theorem shape.
                if linkage_commitment_count != Some(DATA_PRIMES.len()) {
                    return Err(invalid_succinct_setup_proof(
                        "the linkage anchor requires exactly one commitment for every Q_share limb",
                    ));
                }
            }
            SuccinctSetupProofFamilyShape::PublicKeyShare => {
                // One constant-commitment opening links the share secret to
                // the anchored secret by congruence over the commitment
                // modulus product plus ternary support.
                if linkage_commitment_count != Some(1) {
                    return Err(invalid_succinct_setup_proof(
                        "the public-key share statement requires exactly one constant-commitment opening",
                    ));
                }
            }
            SuccinctSetupProofFamilyShape::PrivateVssShare => {
                if self.keys.is_empty()
                    && self.same_secret_linkage.is_none()
                    && self.private_vss_share.is_some()
                    && self.compact_vss_share_linkage.is_none()
                    && self.target_decryption_share.is_none()
                {
                    // The detailed statement check below validates the
                    // recipient-private VSS material.
                } else {
                    return Err(invalid_succinct_setup_proof(
                        "private VSS statement must not mix proof families",
                    ));
                }
            }
            SuccinctSetupProofFamilyShape::CompactVssShareLinkage => {
                if !(self.keys.is_empty()
                    && self.same_secret_linkage.is_none()
                    && self.private_vss_share.is_none()
                    && self.compact_vss_share_linkage.is_some()
                    && self.compact_same_secret_bridge.is_none()
                    && self.target_decryption_share.is_none())
                {
                    return Err(invalid_succinct_setup_proof(
                        "compact VSS share-linkage statement must not mix proof families",
                    ));
                }
            }
            SuccinctSetupProofFamilyShape::CompactSameSecretBridge => {
                if !(self.keys.is_empty()
                    && self.same_secret_linkage.is_none()
                    && self.private_vss_share.is_none()
                    && self.compact_vss_share_linkage.is_none()
                    && self.compact_same_secret_bridge.is_some()
                    && self.target_decryption_share.is_none())
                {
                    return Err(invalid_succinct_setup_proof(
                        "compact same-secret bridge statement must not mix proof families",
                    ));
                }
            }
            SuccinctSetupProofFamilyShape::TargetDecryptionShare => {
                if !(self.keys.is_empty()
                    && self.same_secret_linkage.is_none()
                    && self.private_vss_share.is_none()
                    && self.compact_vss_share_linkage.is_none()
                    && self.compact_same_secret_bridge.is_none()
                    && self.target_decryption_share.is_some())
                {
                    return Err(invalid_succinct_setup_proof(
                        "target-decryption share statement must not mix proof families",
                    ));
                }
            }
            SuccinctSetupProofFamilyShape::TrusteeEvaluationKey => {}
        }
        self.context.validate_for_statement(shape)?;
        if !self.ring_degree.is_power_of_two()
            || self.ring_degree < TRACE_SPLIT * MINIMUM_TRACE_SIZE
        {
            return Err(invalid_succinct_setup_proof(
                "ring degree must be a power of two above the minimum trace size",
            ));
        }
        for key in &self.keys {
            key.validate_shape(self.ring_degree)?;
        }
        if let Some(linkage) = &self.same_secret_linkage {
            validate_protocol_hash_hex(
                "sameSecretLinkage.publicMatrixSeedHash",
                &linkage.public_matrix_seed_hash,
            )?;
            if self.limb_count() < SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() {
                return Err(invalid_succinct_setup_proof(
                    "same-secret linkage requires every commitment field to be an active limb",
                ));
            }
            if shape == SuccinctSetupProofFamilyShape::TrusteeEvaluationKey
                && linkage.commitments.len() != self.limb_count()
            {
                return Err(invalid_succinct_setup_proof(format!(
                    "same-secret linkage requires exactly one commitment per active Q_share limb: expected {}, got {}",
                    self.limb_count(),
                    linkage.commitments.len()
                )));
            }
            if linkage.commitments.is_empty() || linkage.commitments.len() > DATA_PRIMES.len() {
                return Err(invalid_succinct_setup_proof(
                    "same-secret linkage requires one commitment per Q_share limb",
                ));
            }
            for (source_limb_index, commitment) in linkage.commitments.iter().enumerate() {
                if commitment.source_rns_limb_index != source_limb_index
                    || commitment.source_message_modulus != DATA_PRIMES[source_limb_index]
                    || commitment.ring_degree != self.ring_degree
                    || commitment.shamir_coefficient_index != 0
                    || commitment.limbs.len() != SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len()
                {
                    return Err(invalid_succinct_setup_proof(
                        "same-secret linkage commitment shape does not match the statement",
                    ));
                }
                for (commitment_field, limb) in commitment.limbs.iter().enumerate() {
                    if limb.commitment_modulus_index != commitment_field
                        || limb.modulus != DATA_PRIMES[commitment_field]
                        || limb.rows.len() != SETUP_COMMITMENT_ROW_COUNT
                        || limb.rows.iter().any(|row| row.len() != self.ring_degree)
                    {
                        return Err(invalid_succinct_setup_proof(
                            "same-secret linkage commitment limb shape does not match the profile",
                        ));
                    }
                }
            }
        }
        if let Some(private_vss_share) = &self.private_vss_share {
            validate_private_vss_share_statement(private_vss_share, self.ring_degree)?;
        }
        if let Some(compact_vss_share_linkage) = &self.compact_vss_share_linkage {
            validate_compact_vss_share_linkage_statement(
                compact_vss_share_linkage,
                self.ring_degree,
            )?;
        }
        if let Some(compact_same_secret_bridge) = &self.compact_same_secret_bridge {
            if compact_same_secret_bridge.source_trustee_identity != self.context.trustee_identity
                || compact_same_secret_bridge.source_trustee_roster_position
                    != self.context.trustee_roster_position
            {
                return Err(invalid_succinct_setup_proof(
                    "compact same-secret bridge source trustee must match the proof context",
                ));
            }
            validate_compact_same_secret_bridge_statement(
                compact_same_secret_bridge,
                self.ring_degree,
            )?;
        }
        if let Some(target_decryption_share) = &self.target_decryption_share {
            if target_decryption_share.trustee_identity != self.context.trustee_identity
                || target_decryption_share.trustee_roster_position
                    != self.context.trustee_roster_position
            {
                return Err(invalid_succinct_setup_proof(
                    "target-decryption share trustee must match the proof context",
                ));
            }
            if self.context.binding_roots[1].1 != target_decryption_share.aggregate_commitment_root
                || self.context.binding_roots[2].1
                    != target_decryption_share.smudging_commitment_set_root
            {
                return Err(invalid_succinct_setup_proof(
                    "target-decryption share context roots must match the statement roots",
                ));
            }
            validate_target_decryption_share_statement(target_decryption_share, self.ring_degree)?;
        }

        Ok(())
    }
}

fn validate_private_vss_share_statement(
    statement: &PrivateVssShareStatement,
    ring_degree: usize,
) -> CanonicalResult<()> {
    validate_protocol_hash_hex(
        "privateVssShare.publicMatrixSeedHash",
        &statement.public_matrix_seed_hash,
    )?;
    validate_protocol_hash_hex(
        "privateVssShare.privateEnvelopeAadHash",
        &statement.private_envelope_aad_hash,
    )?;
    validate_context_token(
        "privateVssShare.sourceTrusteeIdentity",
        &statement.source_trustee_identity,
    )?;
    validate_context_token(
        "privateVssShare.recipientIdentity",
        &statement.recipient_identity,
    )?;
    validate_protocol_hash_hex(
        "privateVssShare.sourceTrusteeCommitmentRoot",
        &statement.source_trustee_commitment_root,
    )?;
    validate_protocol_hash_hex(
        "privateVssShare.shareValuesHash",
        &statement.share_values_hash,
    )?;
    if statement.source_rns_limb_index >= DATA_PRIMES.len()
        || DATA_PRIMES[statement.source_rns_limb_index] != statement.source_message_modulus
    {
        return Err(invalid_succinct_setup_proof(
            "private VSS source limb does not match the selected data basis",
        ));
    }
    if statement.share_values.len() != ring_degree
        || statement
            .share_values
            .iter()
            .any(|value| *value >= statement.source_message_modulus)
    {
        return Err(invalid_succinct_setup_proof(
            "private VSS share values are not canonical for the source limb",
        ));
    }
    if statement.coefficient_commitments.is_empty()
        || statement.coefficient_commitments.len() != statement.coefficient_commitment_roots.len()
    {
        return Err(invalid_succinct_setup_proof(
            "private VSS coefficient commitments and roots must be non-empty and aligned",
        ));
    }
    for commitment_root in &statement.coefficient_commitment_roots {
        validate_protocol_hash_hex("privateVssShare.coefficientCommitmentRoot", commitment_root)?;
    }
    for (coefficient_index, commitment) in statement.coefficient_commitments.iter().enumerate() {
        if commitment.source_rns_limb_index != statement.source_rns_limb_index
            || commitment.source_message_modulus != statement.source_message_modulus
            || commitment.shamir_coefficient_index != coefficient_index as u64
            || commitment.ring_degree != ring_degree
            || commitment.limbs.len() != SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len()
        {
            return Err(invalid_succinct_setup_proof(
                "private VSS coefficient commitment shape does not match the statement",
            ));
        }
        for (commitment_field, limb) in commitment.limbs.iter().enumerate() {
            if limb.commitment_modulus_index != commitment_field
                || limb.modulus != DATA_PRIMES[commitment_field]
                || limb.rows.len() != SETUP_COMMITMENT_ROW_COUNT
                || limb.rows.iter().any(|row| row.len() != ring_degree)
            {
                return Err(invalid_succinct_setup_proof(
                    "private VSS coefficient commitment limb shape does not match the profile",
                ));
            }
        }
    }

    Ok(())
}

fn validate_compact_vss_share_linkage_statement(
    statement: &CompactVssShareLinkageStatement,
    ring_degree: usize,
) -> CanonicalResult<()> {
    validate_protocol_hash_hex(
        "compactVssShareLinkage.publicMatrixSeedHash",
        &statement.public_matrix_seed_hash,
    )?;
    validate_context_token(
        "compactVssShareLinkage.sourceTrusteeIdentity",
        &statement.source_trustee_identity,
    )?;
    validate_context_token(
        "compactVssShareLinkage.recipientIdentity",
        &statement.recipient_identity,
    )?;
    validate_protocol_hash_hex(
        "compactVssShareLinkage.sourceCoefficientCommitmentRoot",
        &statement.source_coefficient_commitment_root,
    )?;
    validate_protocol_hash_hex(
        "compactVssShareLinkage.sourceRecipientShareCommitmentRoot",
        &statement.source_recipient_share_commitment_root,
    )?;
    validate_protocol_hash_hex(
        "compactVssShareLinkage.recipientShareCommitmentRoot",
        &statement.recipient_share_commitment_root,
    )?;
    if statement.source_rns_limb_index >= DATA_PRIMES.len()
        || DATA_PRIMES[statement.source_rns_limb_index] != statement.source_message_modulus
    {
        return Err(invalid_succinct_setup_proof(
            "compact VSS source limb does not match the selected data basis",
        ));
    }
    if statement.coefficient_commitments.is_empty()
        || statement.coefficient_commitments.len() != statement.coefficient_commitment_roots.len()
    {
        return Err(invalid_succinct_setup_proof(
            "compact VSS coefficient commitments and roots must be non-empty and aligned",
        ));
    }
    for commitment_root in &statement.coefficient_commitment_roots {
        validate_protocol_hash_hex(
            "compactVssShareLinkage.coefficientCommitmentRoot",
            commitment_root,
        )?;
    }
    for commitment in statement
        .coefficient_commitments
        .iter()
        .chain(std::iter::once(&statement.recipient_share_commitment))
    {
        if commitment.coordinates_by_commitment_modulus.len()
            != SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len()
            || commitment.coordinates_by_commitment_modulus.iter().any(|coordinates| {
                coordinates.len()
                    != crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_OUTPUT_COORDINATE_COUNT
            })
        {
            return Err(invalid_succinct_setup_proof(
                "compact VSS commitment coordinate count does not match the profile",
            ));
        }
    }
    if ring_degree == 0 {
        return Err(invalid_succinct_setup_proof(
            "compact VSS share-linkage ring degree must be positive",
        ));
    }

    Ok(())
}

fn validate_compact_same_secret_bridge_statement(
    statement: &CompactSameSecretBridgeStatement,
    ring_degree: usize,
) -> CanonicalResult<()> {
    validate_protocol_hash_hex(
        "compactSameSecretBridge.publicMatrixSeedHash",
        &statement.public_matrix_seed_hash,
    )?;
    validate_context_token(
        "compactSameSecretBridge.sourceTrusteeIdentity",
        &statement.source_trustee_identity,
    )?;
    validate_protocol_hash_hex(
        "compactSameSecretBridge.targetBasisHash",
        &statement.target_basis_hash,
    )?;
    if statement.target_rns_primes.is_empty()
        || statement.target_rns_primes.len() > DATA_PRIMES.len()
        || statement.target_rns_primes.len() != statement.target_constant_commitment_roots.len()
        || statement.target_rns_primes.len() != statement.target_constant_commitments.len()
    {
        return Err(invalid_succinct_setup_proof(
            "compact same-secret bridge target commitments and target primes must be non-empty and aligned",
        ));
    }
    for (target_rns_limb_index, target_rns_prime) in statement.target_rns_primes.iter().enumerate()
    {
        if *target_rns_prime != DATA_PRIMES[target_rns_limb_index] {
            return Err(invalid_succinct_setup_proof(
                "compact same-secret bridge target primes must match the canonical target basis",
            ));
        }
        validate_protocol_hash_hex(
            "compactSameSecretBridge.targetConstantCommitmentRoot",
            &statement.target_constant_commitment_roots[target_rns_limb_index],
        )?;
    }
    for commitment in &statement.target_constant_commitments {
        if commitment.coordinates_by_commitment_modulus.len()
            != SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len()
            || commitment.coordinates_by_commitment_modulus.iter().any(|coordinates| {
                coordinates.len()
                    != crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_OUTPUT_COORDINATE_COUNT
            })
        {
            return Err(invalid_succinct_setup_proof(
                "compact same-secret bridge commitment coordinate count does not match the profile",
            ));
        }
    }
    if ring_degree == 0 {
        return Err(invalid_succinct_setup_proof(
            "compact same-secret bridge ring degree must be positive",
        ));
    }

    Ok(())
}

fn validate_target_decryption_share_statement(
    statement: &TargetDecryptionShareStatement,
    ring_degree: usize,
) -> CanonicalResult<()> {
    validate_protocol_hash_hex(
        "targetDecryptionShare.publicMatrixSeedHash",
        &statement.public_matrix_seed_hash,
    )?;
    validate_protocol_hash_hex(
        "targetDecryptionShare.targetBasisHash",
        &statement.target_basis_hash,
    )?;
    validate_context_token(
        "targetDecryptionShare.trusteeIdentity",
        &statement.trustee_identity,
    )?;
    validate_context_token("targetDecryptionShare.targetRole", &statement.target_role)?;
    validate_protocol_hash_hex(
        "targetDecryptionShare.aggregateCommitmentRoot",
        &statement.aggregate_commitment_root,
    )?;
    validate_protocol_hash_hex(
        "targetDecryptionShare.smudgingCommitmentSetRoot",
        &statement.smudging_commitment_set_root,
    )?;
    if statement.target_rns_limb_index >= DATA_PRIMES.len()
        || DATA_PRIMES[statement.target_rns_limb_index] != statement.target_rns_prime
    {
        return Err(invalid_succinct_setup_proof(
            "target-decryption share target limb does not match the selected data basis",
        ));
    }
    if statement.interpolation_point == 0
        || statement.interpolation_point >= statement.target_rns_prime
    {
        return Err(invalid_succinct_setup_proof(
            "target-decryption share interpolation point is outside the target field",
        ));
    }
    if statement.target_ciphertext_component_one.len() != ring_degree
        || statement.released_partial_decryption.len() != ring_degree
        || statement
            .target_ciphertext_component_one
            .iter()
            .chain(statement.released_partial_decryption.iter())
            .any(|value| *value >= statement.target_rns_prime)
    {
        return Err(invalid_succinct_setup_proof(
            "target-decryption share ciphertext and released partial must be canonical target-limb vectors",
        ));
    }
    if statement.smudging_polynomial_degree == 0
        || statement.smudging_commitments.len() != statement.smudging_polynomial_degree
        || statement.smudging_commitment_roots.len() != statement.smudging_polynomial_degree
    {
        return Err(invalid_succinct_setup_proof(
            "target-decryption smudging commitments must cover every nonconstant polynomial degree",
        ));
    }
    if statement.aggregate_message_coefficient_bound < statement.target_rns_prime {
        return Err(invalid_succinct_setup_proof(
            "target-decryption aggregate message coefficient bound must cover the target field",
        ));
    }
    if statement.smudging_coefficient_bound < 0
        || statement.smudging_signed_coefficient_offset != statement.smudging_coefficient_bound
        || statement.smudging_message_coefficient_bound
            != (statement.smudging_coefficient_bound as u64) * 2 + 1
        || statement.plaintext_multiple == 0
        || statement.plaintext_multiple >= statement.target_rns_prime
    {
        return Err(invalid_succinct_setup_proof(
            "target-decryption smudging numeric bounds do not match the statement shape",
        ));
    }
    for commitment_root in &statement.smudging_commitment_roots {
        validate_protocol_hash_hex(
            "targetDecryptionShare.smudgingCommitmentRoot",
            commitment_root,
        )?;
    }
    for commitment in std::iter::once(&statement.aggregate_commitment)
        .chain(statement.smudging_commitments.iter())
    {
        if commitment.coordinates_by_commitment_modulus.len()
            != SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len()
            || commitment.coordinates_by_commitment_modulus.iter().any(|coordinates| {
                coordinates.len()
                    != crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_OUTPUT_COORDINATE_COUNT
            })
        {
            return Err(invalid_succinct_setup_proof(
                "target-decryption compact commitment coordinate count does not match the profile",
            ));
        }
        for (commitment_modulus_index, coordinates) in commitment
            .coordinates_by_commitment_modulus
            .iter()
            .enumerate()
        {
            let commitment_modulus = DATA_PRIMES[commitment_modulus_index];
            if coordinates
                .iter()
                .any(|coordinate| *coordinate >= commitment_modulus)
            {
                return Err(invalid_succinct_setup_proof(
                    "target-decryption compact commitment coordinate is outside its commitment field",
                ));
            }
        }
    }

    Ok(())
}

fn coefficient_vector_hash(coefficients: &[u64]) -> [u8; 64] {
    let mut bytes = Vec::with_capacity(coefficients.len() * 8);
    for value in coefficients {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    hash512(STATEMENT_HASH_DOMAIN, &[&bytes])
}
