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
            Self::TrusteeEvaluationKey => super::TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
        }
    }

    pub(crate) fn binding_labels(self) -> &'static [&'static str] {
        match self {
            Self::SameSecretLinkageAnchor => &SAME_SECRET_LINKAGE_ANCHOR_BINDING_LABELS,
            Self::PublicKeyShare => &PUBLIC_KEY_SHARE_SUCCINCT_BINDING_LABELS,
            Self::PrivateVssShare => &PRIVATE_VSS_SHARE_BINDING_LABELS,
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

        hash512(STATEMENT_HASH_DOMAIN, &[&preimage])
    }

    pub(in crate::bgv::setup) fn family_shape(
        &self,
    ) -> CanonicalResult<SuccinctSetupProofFamilyShape> {
        if self.private_vss_share.is_some() {
            if !self.keys.is_empty() || self.same_secret_linkage.is_some() {
                return Err(invalid_succinct_setup_proof(
                    "private VSS statement must not include key descriptors or same-secret linkage",
                ));
            }
            return Ok(SuccinctSetupProofFamilyShape::PrivateVssShare);
        }
        let kinds = self.keys.iter().map(|key| key.kind).collect::<Vec<_>>();

        SuccinctSetupProofFamilyShape::from_key_kinds(&kinds)
    }

    pub(in crate::bgv::setup) fn validate_shape(&self) -> CanonicalResult<()> {
        if self.keys.is_empty()
            && self.same_secret_linkage.is_none()
            && self.private_vss_share.is_none()
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
                {
                    // The detailed statement check below validates the
                    // recipient-private VSS material.
                } else {
                    return Err(invalid_succinct_setup_proof(
                        "private VSS statement must not mix proof families",
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

fn coefficient_vector_hash(coefficients: &[u64]) -> [u8; 64] {
    let mut bytes = Vec::with_capacity(coefficients.len() * 8);
    for value in coefficients {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    hash512(STATEMENT_HASH_DOMAIN, &[&bytes])
}
