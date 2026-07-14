use super::super::{
    CLAIM_MASK_DIGIT_COUNT, CONSISTENCY_COEFFICIENT_BITS, CONSISTENCY_REPETITIONS,
    MINIMUM_TRACE_SIZE, TARGET_DECRYPTION_AGGREGATE_MESSAGE_CLAIM_MASK_DIGIT_COUNT, TRACE_SPLIT,
    VSS_PUBLIC_CARRY_CLAIM_MASK_DIGIT_COUNT, VSS_PUBLIC_CONSISTENCY_COEFFICIENT_BITS,
    VSS_PUBLIC_CONSISTENCY_REPETITIONS, invalid_succinct_setup_proof,
};
use super::linkage_and_vss_vectors::{
    masked_claim_bounds_for_global_claim, masked_claim_lift_residue_count_for_moduli,
};
use super::statement_types::{
    EvaluationKeyShareKind, PrivateVssShareStatement, SameSecretBridgeStatement,
    SetupProofStatement, SuccinctSetupProofContext, TargetDecryptionShareStatement,
    TrusteeEvaluationKeyStatement, VssShareLinkageStatement,
};
use super::vss_vectors::VssShareLinkageCommitment;
use crate::bgv::parameters::DATA_PRIMES;
use crate::bgv::setup::commitment::{
    SETUP_COMMITMENT_MODULUS_LIMB_INDICES, SETUP_COMMITMENT_ROW_COUNT,
};
use crate::bgv::setup::setup_proof::SetupProofFamily;
use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};
use crate::hashing::hash_framed_parts_512 as hash512;

const STATEMENT_HASH_DOMAIN: &str = "sealed-lattice/setup/trustee-evaluation-key/statement";
const PROTOCOL_HASH_HEX_LENGTH: usize = 128;
const MAX_CONTEXT_TOKEN_BYTES: usize = 512;
const TARGET_DECRYPTION_PROOF_TARGET_ROLES: [&str; 2] = ["targetId", "targetOrder"];

// The request parser maps one public-key share descriptor to the public-key
// share variant and key-switch descriptors to the trustee evaluation-key
// variant. A public-key share descriptor mixed with key-switch descriptors is
// refused before the typed statement is built.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum SuccinctSetupProofFamilyShape {
    PublicKeyShare,
    PrivateVssShare,
    VssShareLinkage,
    SameSecretBridge,
    TargetDecryptionShare,
    TrusteeEvaluationKey,
}

impl SuccinctSetupProofFamilyShape {
    pub(crate) fn from_key_kinds(kinds: &[EvaluationKeyShareKind]) -> CanonicalResult<Self> {
        if kinds.is_empty() {
            return Err(invalid_succinct_setup_proof(
                "key-bearing setup proof statement requires at least one key descriptor",
            ));
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

    pub(crate) const fn setup_proof_family(self) -> SetupProofFamily {
        match self {
            Self::PublicKeyShare => SetupProofFamily::PublicKeyShare,
            Self::PrivateVssShare => SetupProofFamily::PrivateVssShare,
            Self::VssShareLinkage => SetupProofFamily::VssShareLinkage,
            Self::SameSecretBridge => SetupProofFamily::SameSecretBridge,
            Self::TargetDecryptionShare => SetupProofFamily::TargetDecryptionShare,
            Self::TrusteeEvaluationKey => SetupProofFamily::TrusteeEvaluationKey,
        }
    }

    pub(crate) const fn proof_family(self) -> &'static str {
        self.setup_proof_family().wire_label()
    }

    pub(crate) fn binding_labels(self) -> &'static [&'static str] {
        self.setup_proof_family().binding_labels()
    }

    pub(crate) fn claim_mask_digit_count(self) -> usize {
        match self {
            Self::TargetDecryptionShare => {
                TARGET_DECRYPTION_AGGREGATE_MESSAGE_CLAIM_MASK_DIGIT_COUNT
            }
            Self::VssShareLinkage => VSS_PUBLIC_CARRY_CLAIM_MASK_DIGIT_COUNT,
            Self::PublicKeyShare
            | Self::PrivateVssShare
            | Self::SameSecretBridge
            | Self::TrusteeEvaluationKey => CLAIM_MASK_DIGIT_COUNT,
        }
    }

    pub(crate) fn consistency_repetitions(self) -> usize {
        match self {
            Self::VssShareLinkage => VSS_PUBLIC_CONSISTENCY_REPETITIONS,
            Self::PublicKeyShare
            | Self::PrivateVssShare
            | Self::SameSecretBridge
            | Self::TargetDecryptionShare
            | Self::TrusteeEvaluationKey => CONSISTENCY_REPETITIONS,
        }
    }

    pub(crate) fn consistency_coefficient_bits(self) -> u32 {
        match self {
            Self::VssShareLinkage => VSS_PUBLIC_CONSISTENCY_COEFFICIENT_BITS,
            Self::PublicKeyShare
            | Self::PrivateVssShare
            | Self::SameSecretBridge
            | Self::TargetDecryptionShare
            | Self::TrusteeEvaluationKey => CONSISTENCY_COEFFICIENT_BITS,
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

fn append_vss_public_commitment(preimage: &mut Vec<u8>, commitment: &VssShareLinkageCommitment) {
    append_usize(
        preimage,
        commitment.material_roots_by_commitment_field.len(),
    );
    for material_root in &commitment.material_roots_by_commitment_field {
        preimage.extend_from_slice(material_root);
    }
}

// Shape check for a committed-material VSS commitment: exactly one material
// root per setup commitment field. Root bytes are fixed-width digests, so
// there is no residue range to validate; binding is checked by the material
// openings against these roots, not here.
fn validate_vss_committed_material_commitment_shape(
    commitment: &VssShareLinkageCommitment,
    field_name: &str,
) -> CanonicalResult<()> {
    if commitment.material_roots_by_commitment_field.len()
        != SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len()
    {
        return Err(invalid_succinct_setup_proof(format!(
            "{field_name} must carry one material root per setup commitment field",
        )));
    }

    Ok(())
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
        validate_protocol_hash_hex("setupContextHash", &self.setup_context_hash)?;
        validate_context_token("trusteeIdentity", &self.trustee_identity)?;
        let expected_labels = shape.binding_labels();
        if self.binding_roots.len() != expected_labels.len() {
            return Err(invalid_succinct_setup_proof(
                "statement binding roots do not match the proof family",
            ));
        }
        for binding_root in &self.binding_roots {
            validate_protocol_hash_hex("bindingRoot", binding_root)?;
        }

        Ok(())
    }
}

impl TrusteeEvaluationKeyStatement {
    pub(in crate::bgv::setup) fn statement_hash(&self) -> [u8; 64] {
        let mut preimage = Vec::new();
        for context_field in [
            self.family_shape().proof_family(),
            self.context.setup_context_hash.as_str(),
            self.context.trustee_identity.as_str(),
        ] {
            append_len_prefixed_str(&mut preimage, context_field);
        }
        append_usize(&mut preimage, self.context.binding_roots.len());
        for (binding_label, binding_root) in self
            .family_shape()
            .binding_labels()
            .iter()
            .zip(self.context.binding_roots.iter())
        {
            for binding_field in [*binding_label, binding_root.as_str()] {
                append_len_prefixed_str(&mut preimage, binding_field);
            }
        }
        append_u64(&mut preimage, self.context.trustee_roster_position);
        preimage.push(0);
        append_usize(&mut preimage, self.ring_degree);
        append_usize(&mut preimage, self.keys().len());
        for key in self.keys() {
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
        if let Some(linkage) = self.same_secret_linkage() {
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
        if let Some(private_vss_share) = self.private_vss_share() {
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
        if let Some(vss_share_linkage) = self.vss_share_linkage() {
            preimage.push(1);
            preimage.push(u8::from(vss_share_linkage.is_threshold_aggregate));
            for field in [
                vss_share_linkage.public_matrix_seed_hash.as_str(),
                vss_share_linkage.source_trustee_identity.as_str(),
                vss_share_linkage.recipient_identity.as_str(),
                vss_share_linkage
                    .source_coefficient_commitment_root
                    .as_str(),
                vss_share_linkage
                    .source_recipient_share_commitment_root
                    .as_str(),
                vss_share_linkage.recipient_share_commitment_root.as_str(),
            ] {
                append_len_prefixed_str(&mut preimage, field);
            }
            preimage.extend_from_slice(
                &vss_share_linkage
                    .source_trustee_roster_position
                    .to_le_bytes(),
            );
            preimage.extend_from_slice(&vss_share_linkage.recipient_roster_position.to_le_bytes());
            append_usize(&mut preimage, vss_share_linkage.source_rns_limb_index);
            preimage.extend_from_slice(&vss_share_linkage.source_message_modulus.to_le_bytes());
            append_usize(
                &mut preimage,
                vss_share_linkage.coefficient_commitment_roots.len(),
            );
            for root in &vss_share_linkage.coefficient_commitment_roots {
                append_len_prefixed_str(&mut preimage, root);
            }
            append_usize(
                &mut preimage,
                vss_share_linkage.coefficient_commitments.len(),
            );
            for commitment in &vss_share_linkage.coefficient_commitments {
                append_vss_public_commitment(&mut preimage, commitment);
            }
            append_vss_public_commitment(
                &mut preimage,
                &vss_share_linkage.recipient_share_commitment,
            );
            append_usize(
                &mut preimage,
                vss_share_linkage.additional_linkage_items.len(),
            );
            for item in &vss_share_linkage.additional_linkage_items {
                for field in [
                    item.source_trustee_identity.as_str(),
                    item.source_coefficient_commitment_root.as_str(),
                    item.source_recipient_share_commitment_root.as_str(),
                    item.recipient_identity.as_str(),
                    item.recipient_share_commitment_root.as_str(),
                ] {
                    append_len_prefixed_str(&mut preimage, field);
                }
                preimage.extend_from_slice(&item.source_trustee_roster_position.to_le_bytes());
                preimage.extend_from_slice(&item.recipient_roster_position.to_le_bytes());
                append_usize(&mut preimage, item.source_rns_limb_index);
                preimage.extend_from_slice(&item.source_message_modulus.to_le_bytes());
                append_usize(&mut preimage, item.coefficient_commitment_roots.len());
                for root in &item.coefficient_commitment_roots {
                    append_len_prefixed_str(&mut preimage, root);
                }
                append_usize(&mut preimage, item.coefficient_commitments.len());
                for commitment in &item.coefficient_commitments {
                    append_vss_public_commitment(&mut preimage, commitment);
                }
                append_vss_public_commitment(&mut preimage, &item.recipient_share_commitment);
            }
        }
        if let Some(same_secret_bridge) = self.same_secret_bridge() {
            preimage.push(1);
            for field in [
                same_secret_bridge.public_matrix_seed_hash.as_str(),
                same_secret_bridge.source_trustee_identity.as_str(),
            ] {
                append_len_prefixed_str(&mut preimage, field);
            }
            preimage.extend_from_slice(
                &same_secret_bridge
                    .source_trustee_roster_position
                    .to_le_bytes(),
            );
            append_usize(&mut preimage, same_secret_bridge.bridge_rns_primes.len());
            for bridge_rns_prime in &same_secret_bridge.bridge_rns_primes {
                preimage.extend_from_slice(&bridge_rns_prime.to_le_bytes());
            }
            append_usize(
                &mut preimage,
                same_secret_bridge.target_constant_commitment_roots.len(),
            );
            for root in &same_secret_bridge.target_constant_commitment_roots {
                append_len_prefixed_str(&mut preimage, root);
            }
            append_usize(
                &mut preimage,
                same_secret_bridge.target_constant_commitments.len(),
            );
            for commitment in &same_secret_bridge.target_constant_commitments {
                append_vss_public_commitment(&mut preimage, commitment);
            }
        }
        if let Some(target_decryption_share) = self.target_decryption_share() {
            preimage.push(1);
            for field in [
                target_decryption_share.public_matrix_seed_hash.as_str(),
                target_decryption_share.trustee_identity.as_str(),
                target_decryption_share
                    .active_credential_binding_root
                    .as_str(),
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
            preimage.extend_from_slice(&target_decryption_share.interpolation_point.to_le_bytes());
            preimage.extend_from_slice(
                &target_decryption_share
                    .aggregate_message_coefficient_bound
                    .to_le_bytes(),
            );
            append_usize(&mut preimage, target_decryption_share.limb_statements.len());
            for limb_statement in &target_decryption_share.limb_statements {
                append_usize(&mut preimage, limb_statement.target_rns_limb_index);
                preimage.extend_from_slice(&limb_statement.target_rns_prime.to_le_bytes());
                append_len_prefixed_str(&mut preimage, &limb_statement.aggregate_commitment_root);
                append_len_prefixed_str(&mut preimage, &limb_statement.aggregate_opening_root);
                append_vss_public_commitment(&mut preimage, &limb_statement.aggregate_commitment);
                append_usize(&mut preimage, limb_statement.role_statements.len());
                for role_statement in &limb_statement.role_statements {
                    append_len_prefixed_str(&mut preimage, &role_statement.target_role);
                    append_usize(
                        &mut preimage,
                        role_statement.target_ciphertext_component_one.len(),
                    );
                    preimage.extend_from_slice(&coefficient_vector_hash(
                        &role_statement.target_ciphertext_component_one,
                    ));
                    append_usize(
                        &mut preimage,
                        role_statement.released_partial_decryption.len(),
                    );
                    preimage.extend_from_slice(&coefficient_vector_hash(
                        &role_statement.released_partial_decryption,
                    ));
                    append_usize(
                        &mut preimage,
                        role_statement.smudging_commitment_roots.len(),
                    );
                    for root in &role_statement.smudging_commitment_roots {
                        append_len_prefixed_str(&mut preimage, root);
                    }
                    append_usize(&mut preimage, role_statement.smudging_commitments.len());
                    for commitment in &role_statement.smudging_commitments {
                        append_vss_public_commitment(&mut preimage, commitment);
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

    pub(in crate::bgv::setup) const fn family_shape(&self) -> SuccinctSetupProofFamilyShape {
        match &self.proof {
            SetupProofStatement::PublicKeyShare { .. } => {
                SuccinctSetupProofFamilyShape::PublicKeyShare
            }
            SetupProofStatement::PrivateVssShare(_) => {
                SuccinctSetupProofFamilyShape::PrivateVssShare
            }
            SetupProofStatement::VssShareLinkage(_) => {
                SuccinctSetupProofFamilyShape::VssShareLinkage
            }
            SetupProofStatement::SameSecretBridge { .. } => {
                SuccinctSetupProofFamilyShape::SameSecretBridge
            }
            SetupProofStatement::TargetDecryptionShare(_) => {
                SuccinctSetupProofFamilyShape::TargetDecryptionShare
            }
            SetupProofStatement::TrusteeEvaluationKey { .. } => {
                SuccinctSetupProofFamilyShape::TrusteeEvaluationKey
            }
        }
    }

    pub(in crate::bgv::setup) fn validate_shape(&self) -> CanonicalResult<()> {
        if self.ring_degree > crate::bgv::parameters::POLYNOMIAL_DEGREE {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "trustee evaluation-key statement ringDegree exceeds the configured polynomial degree",
            ));
        }
        let shape = self.family_shape();
        if !self.keys().is_empty() {
            let key_kinds = self.keys().iter().map(|key| key.kind).collect::<Vec<_>>();
            if SuccinctSetupProofFamilyShape::from_key_kinds(&key_kinds)? != shape {
                return Err(invalid_succinct_setup_proof(
                    "key descriptors do not match the selected setup proof family",
                ));
            }
        }
        self.context.validate_for_statement(shape)?;
        if !self.ring_degree.is_power_of_two()
            || self.ring_degree < TRACE_SPLIT * MINIMUM_TRACE_SIZE
        {
            return Err(invalid_succinct_setup_proof(
                "ring degree must be a power of two above the minimum trace size",
            ));
        }
        for key in self.keys() {
            key.validate_shape(self.ring_degree)?;
        }
        if let Some(linkage) = self.same_secret_linkage() {
            validate_protocol_hash_hex(
                "sameSecretLinkage.publicMatrixSeedHash",
                &linkage.public_matrix_seed_hash,
            )?;
            let expected_commitment_count = match shape {
                SuccinctSetupProofFamilyShape::SameSecretBridge => DATA_PRIMES.len(),
                SuccinctSetupProofFamilyShape::TrusteeEvaluationKey => 1,
                _ => unreachable!("only linkage-bearing variants expose linkage material"),
            };
            if linkage.commitments.len() != expected_commitment_count {
                return Err(invalid_succinct_setup_proof(
                    "same-secret linkage commitment count does not match the proof family",
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
                            "same-secret linkage commitment limb shape does not match the parameters",
                        ));
                    }
                }
            }
        }
        if let Some(private_vss_share) = self.private_vss_share() {
            validate_private_vss_share_statement(private_vss_share, self.ring_degree)?;
        }
        if let Some(vss_share_linkage) = self.vss_share_linkage() {
            validate_vss_share_linkage_statement(vss_share_linkage, self.ring_degree)?;
        }
        if let Some(same_secret_bridge) = self.same_secret_bridge() {
            if same_secret_bridge.source_trustee_identity != self.context.trustee_identity
                || same_secret_bridge.source_trustee_roster_position
                    != self.context.trustee_roster_position
            {
                return Err(invalid_succinct_setup_proof(
                    "same-secret bridge source trustee must match the proof context",
                ));
            }
            if let Some(same_secret_linkage) = self.same_secret_linkage()
                && same_secret_linkage.public_matrix_seed_hash
                    != same_secret_bridge.public_matrix_seed_hash
            {
                return Err(invalid_succinct_setup_proof(
                    "same-secret bridge and source linkage public matrix seeds must match",
                ));
            }
            validate_same_secret_bridge_statement(same_secret_bridge, self.ring_degree)?;
        }
        if let Some(target_decryption_share) = self.target_decryption_share() {
            if target_decryption_share.trustee_identity != self.context.trustee_identity
                || target_decryption_share.trustee_roster_position
                    != self.context.trustee_roster_position
            {
                return Err(invalid_succinct_setup_proof(
                    "target-decryption share trustee must match the proof context",
                ));
            }
            if self.context.binding_roots[1]
                != target_decryption_share.active_credential_binding_root
                || self.context.binding_roots[2]
                    != target_decryption_share.smudging_commitment_set_root
            {
                return Err(invalid_succinct_setup_proof(
                    "target-decryption share context roots must match the statement roots",
                ));
            }
            validate_target_decryption_share_statement(target_decryption_share, self.ring_degree)?;
        }
        validate_masked_claim_lift_window(self)?;

        Ok(())
    }
}

fn validate_masked_claim_lift_window(
    statement: &TrusteeEvaluationKeyStatement,
) -> CanonicalResult<()> {
    let proof_limb_indices = statement.proof_limb_indices();
    let (lower_bound, upper_bound) = masked_claim_bounds_for_global_claim(statement, 0)?;
    let required_residue_count = masked_claim_lift_residue_count_for_moduli(
        proof_limb_indices
            .iter()
            .map(|limb_index| DATA_PRIMES[*limb_index]),
        &lower_bound,
        &upper_bound,
    );
    if required_residue_count > proof_limb_indices.len() {
        return Err(invalid_succinct_setup_proof(
            "masked consistency claim range requires more active limb fields",
        ));
    }
    if statement.target_decryption_share().is_some()
        && required_residue_count
            > TrusteeEvaluationKeyStatement::TARGET_DECRYPTION_AGGREGATE_MESSAGE_MASKED_CLAIM_FIELD_COUNT
    {
        return Err(invalid_succinct_setup_proof(
            "target-decryption masked consistency claims need more carried limb fields",
        ));
    }
    if let Some(vss_share_linkage) = statement.vss_share_linkage() {
        // The first message-digit consistency vector sits after every item's
        // carry vector, and each vector carries one claim per repetition.
        // Indexing from the item count keeps this window check on a genuine
        // digit claim when additional linkage items are present.
        let first_digit_global_claim_id = (vss_share_linkage.item_count()
            * statement.family_shape().consistency_repetitions())
            as u64;
        let (digit_lower_bound, digit_upper_bound) =
            masked_claim_bounds_for_global_claim(statement, first_digit_global_claim_id)?;
        let required_digit_residue_count = masked_claim_lift_residue_count_for_moduli(
            proof_limb_indices
                .iter()
                .map(|limb_index| DATA_PRIMES[*limb_index]),
            &digit_lower_bound,
            &digit_upper_bound,
        );
        if required_digit_residue_count > proof_limb_indices.len() {
            return Err(invalid_succinct_setup_proof(
                "VSS digit masked consistency claims need more active limb fields",
            ));
        }
    }
    if statement.target_decryption_share().is_some()
        && let Some(first_smudging_global_message_index) =
            statement.target_decryption_smudging_message_global_index()
    {
        let first_smudging_global_claim_id = (first_smudging_global_message_index
            * crate::bgv::setup::vss_commitment::VSS_PUBLIC_MESSAGE_DIGIT_COUNT
            * CONSISTENCY_REPETITIONS) as u64;
        let smudging_limb_indices = statement
            .target_decryption_message_claim_limb_indices(first_smudging_global_message_index);
        let (smudging_lower_bound, smudging_upper_bound) =
            masked_claim_bounds_for_global_claim(statement, first_smudging_global_claim_id)?;
        let required_smudging_residue_count = masked_claim_lift_residue_count_for_moduli(
            smudging_limb_indices
                .iter()
                .map(|limb_index| DATA_PRIMES[*limb_index]),
            &smudging_lower_bound,
            &smudging_upper_bound,
        );
        if required_smudging_residue_count
                > TrusteeEvaluationKeyStatement::TARGET_DECRYPTION_SMUDGING_MESSAGE_MASKED_CLAIM_FIELD_COUNT
            {
                return Err(invalid_succinct_setup_proof(
                    "target-decryption smudging-message masked consistency claims need more carried limb fields",
                ));
            }
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
    validate_context_token(
        "targetDecryptionShare.trusteeIdentity",
        &statement.trustee_identity,
    )?;
    validate_protocol_hash_hex(
        "targetDecryptionShare.activeCredentialBindingRoot",
        &statement.active_credential_binding_root,
    )?;
    validate_protocol_hash_hex(
        "targetDecryptionShare.smudgingCommitmentSetRoot",
        &statement.smudging_commitment_set_root,
    )?;
    if statement.limb_statements.is_empty() {
        return Err(invalid_succinct_setup_proof(
            "target-decryption share statement must include at least one active target limb",
        ));
    }
    if statement.smudging_polynomial_degree == 0 {
        return Err(invalid_succinct_setup_proof(
            "target-decryption smudging polynomial degree must be positive",
        ));
    }
    if statement.smudging_coefficient_bound < 0
        || statement.smudging_signed_coefficient_offset != statement.smudging_coefficient_bound
        || statement.smudging_message_coefficient_bound
            != (statement.smudging_coefficient_bound as u64) * 2 + 1
    {
        return Err(invalid_succinct_setup_proof(
            "target-decryption smudging numeric bounds do not match the statement shape",
        ));
    }
    let mut previous_limb_index = None;
    for limb_statement in &statement.limb_statements {
        validate_protocol_hash_hex(
            "targetDecryptionShare.aggregateCommitmentRoot",
            &limb_statement.aggregate_commitment_root,
        )?;
        validate_protocol_hash_hex(
            "targetDecryptionShare.aggregateOpeningRoot",
            &limb_statement.aggregate_opening_root,
        )?;
        if limb_statement.target_rns_limb_index >= DATA_PRIMES.len()
            || DATA_PRIMES[limb_statement.target_rns_limb_index] != limb_statement.target_rns_prime
        {
            return Err(invalid_succinct_setup_proof(
                "target-decryption share target limb does not match the selected data basis",
            ));
        }
        if previous_limb_index
            .is_some_and(|previous| previous >= limb_statement.target_rns_limb_index)
        {
            return Err(invalid_succinct_setup_proof(
                "target-decryption share target limbs must be strictly increasing",
            ));
        }
        previous_limb_index = Some(limb_statement.target_rns_limb_index);
        if statement.interpolation_point == 0
            || statement.interpolation_point >= limb_statement.target_rns_prime
            || statement.plaintext_multiple == 0
            || statement.plaintext_multiple >= limb_statement.target_rns_prime
            || statement.aggregate_message_coefficient_bound < limb_statement.target_rns_prime
        {
            return Err(invalid_succinct_setup_proof(
                "target-decryption share numeric fields are outside the target field",
            ));
        }
        if limb_statement.role_statements.is_empty() {
            return Err(invalid_succinct_setup_proof(
                "target-decryption share limb statement must include at least one target role",
            ));
        }
        if limb_statement.role_statements.len() != TARGET_DECRYPTION_PROOF_TARGET_ROLES.len() {
            return Err(invalid_succinct_setup_proof(
                "target-decryption share limb statement must cover the canonical target roles",
            ));
        }
        let mut seen_roles = std::collections::BTreeSet::new();
        for (target_role_index, role_statement) in limb_statement.role_statements.iter().enumerate()
        {
            validate_context_token(
                "targetDecryptionShare.targetRole",
                &role_statement.target_role,
            )?;
            if role_statement.target_role != TARGET_DECRYPTION_PROOF_TARGET_ROLES[target_role_index]
            {
                return Err(invalid_succinct_setup_proof(
                    "target-decryption share target roles must be in canonical order",
                ));
            }
            if !seen_roles.insert(role_statement.target_role.as_str()) {
                return Err(invalid_succinct_setup_proof(
                    "target-decryption share statement repeats a target role",
                ));
            }
            if role_statement.target_ciphertext_component_one.len() != ring_degree
                || role_statement.released_partial_decryption.len() != ring_degree
                || role_statement
                    .target_ciphertext_component_one
                    .iter()
                    .chain(role_statement.released_partial_decryption.iter())
                    .any(|value| *value >= limb_statement.target_rns_prime)
            {
                return Err(invalid_succinct_setup_proof(
                    "target-decryption share ciphertext and released partial must be canonical target-limb vectors",
                ));
            }
            if role_statement.smudging_commitments.len() != statement.smudging_polynomial_degree
                || role_statement.smudging_commitment_roots.len()
                    != statement.smudging_polynomial_degree
            {
                return Err(invalid_succinct_setup_proof(
                    "target-decryption smudging commitments must cover every nonconstant polynomial degree",
                ));
            }
            for commitment_root in &role_statement.smudging_commitment_roots {
                validate_protocol_hash_hex(
                    "targetDecryptionShare.smudgingCommitmentRoot",
                    commitment_root,
                )?;
            }
        }
    }
    for commitment in statement.limb_statements.iter().flat_map(|limb_statement| {
        std::iter::once(&limb_statement.aggregate_commitment).chain(
            limb_statement
                .role_statements
                .iter()
                .flat_map(|role_statement| role_statement.smudging_commitments.iter()),
        )
    }) {
        validate_vss_committed_material_commitment_shape(
            commitment,
            "targetDecryptionShare.commitment",
        )?;
    }

    Ok(())
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
                    "private VSS coefficient commitment limb shape does not match the parameters",
                ));
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_vss_share_linkage_item(
    field_prefix: &str,
    recipient_identity: &str,
    source_rns_limb_index: usize,
    source_message_modulus: u64,
    coefficient_commitment_roots: &[String],
    coefficient_commitments: &[VssShareLinkageCommitment],
    recipient_share_commitment_root: &str,
    recipient_share_commitment: &VssShareLinkageCommitment,
) -> CanonicalResult<()> {
    validate_context_token(
        &format!("{field_prefix}.recipientIdentity"),
        recipient_identity,
    )?;
    validate_protocol_hash_hex(
        &format!("{field_prefix}.recipientShareCommitmentRoot"),
        recipient_share_commitment_root,
    )?;
    if source_rns_limb_index >= DATA_PRIMES.len()
        || DATA_PRIMES[source_rns_limb_index] != source_message_modulus
    {
        return Err(invalid_succinct_setup_proof(
            "VSS source limb does not match the selected data basis",
        ));
    }
    if coefficient_commitments.is_empty()
        || coefficient_commitments.len() != coefficient_commitment_roots.len()
    {
        return Err(invalid_succinct_setup_proof(
            "VSS coefficient commitments and roots must be non-empty and aligned",
        ));
    }
    for commitment_root in coefficient_commitment_roots {
        validate_protocol_hash_hex(
            &format!("{field_prefix}.coefficientCommitmentRoot"),
            commitment_root,
        )?;
    }
    for commitment in coefficient_commitments
        .iter()
        .chain(std::iter::once(recipient_share_commitment))
    {
        validate_vss_committed_material_commitment_shape(commitment, "vssShareLinkage.commitment")?;
    }

    Ok(())
}

fn validate_vss_share_linkage_statement(
    statement: &VssShareLinkageStatement,
    ring_degree: usize,
) -> CanonicalResult<()> {
    validate_protocol_hash_hex(
        "vssShareLinkage.publicMatrixSeedHash",
        &statement.public_matrix_seed_hash,
    )?;
    validate_context_token(
        "vssShareLinkage.sourceTrusteeIdentity",
        &statement.source_trustee_identity,
    )?;
    validate_context_token(
        "vssShareLinkage.recipientIdentity",
        &statement.recipient_identity,
    )?;
    validate_protocol_hash_hex(
        "vssShareLinkage.sourceCoefficientCommitmentRoot",
        &statement.source_coefficient_commitment_root,
    )?;
    validate_protocol_hash_hex(
        "vssShareLinkage.sourceRecipientShareCommitmentRoot",
        &statement.source_recipient_share_commitment_root,
    )?;
    validate_vss_share_linkage_item(
        "vssShareLinkage",
        &statement.recipient_identity,
        statement.source_rns_limb_index,
        statement.source_message_modulus,
        &statement.coefficient_commitment_roots,
        &statement.coefficient_commitments,
        &statement.recipient_share_commitment_root,
        &statement.recipient_share_commitment,
    )?;
    for (item_index, item) in statement.additional_linkage_items.iter().enumerate() {
        validate_context_token(
            &format!("vssShareLinkage.additionalLinkageItems.{item_index}.sourceTrusteeIdentity"),
            &item.source_trustee_identity,
        )?;
        validate_protocol_hash_hex(
            &format!(
                "vssShareLinkage.additionalLinkageItems.{item_index}.sourceCoefficientCommitmentRoot"
            ),
            &item.source_coefficient_commitment_root,
        )?;
        validate_protocol_hash_hex(
            &format!(
                "vssShareLinkage.additionalLinkageItems.{item_index}.sourceRecipientShareCommitmentRoot"
            ),
            &item.source_recipient_share_commitment_root,
        )?;
        validate_vss_share_linkage_item(
            &format!("vssShareLinkage.additionalLinkageItems.{item_index}"),
            &item.recipient_identity,
            item.source_rns_limb_index,
            item.source_message_modulus,
            &item.coefficient_commitment_roots,
            &item.coefficient_commitments,
            &item.recipient_share_commitment_root,
            &item.recipient_share_commitment,
        )?;
    }
    let coefficient_slot_indices_by_item = statement.coefficient_witness_slot_indices_by_item();
    let mut commitment_by_coefficient_slot =
        vec![None; statement.unique_coefficient_witness_slot_count()];
    let mut validate_coefficient_slot_bindings =
        |field_prefix: &str,
         coefficient_slot_indices: &[usize],
         coefficient_commitments: &[VssShareLinkageCommitment]|
         -> CanonicalResult<()> {
            if coefficient_slot_indices.len() != coefficient_commitments.len() {
                return Err(invalid_succinct_setup_proof(
                    "VSS coefficient witness slot layout does not match the statement",
                ));
            }
            for (coefficient_index, (coefficient_slot_index, commitment)) in
                coefficient_slot_indices
                    .iter()
                    .zip(coefficient_commitments.iter())
                    .enumerate()
            {
                let slot = commitment_by_coefficient_slot
                    .get_mut(*coefficient_slot_index)
                    .ok_or_else(|| {
                        invalid_succinct_setup_proof(
                            "VSS coefficient witness slot index is outside the layout",
                        )
                    })?;
                if let Some(existing_commitment) = slot {
                    if existing_commitment != commitment {
                        return Err(invalid_succinct_setup_proof(format!(
                            "{field_prefix}.coefficientCommitments.{coefficient_index} reuses a coefficient opening with different commitment coordinates"
                        )));
                    }
                } else {
                    *slot = Some(commitment.clone());
                }
            }

            Ok(())
        };
    validate_coefficient_slot_bindings(
        "vssShareLinkage",
        coefficient_slot_indices_by_item
            .first()
            .map(Vec::as_slice)
            .unwrap_or(&[]),
        &statement.coefficient_commitments,
    )?;
    for (item_index, (item, coefficient_slot_indices)) in statement
        .additional_linkage_items
        .iter()
        .zip(coefficient_slot_indices_by_item.iter().skip(1))
        .enumerate()
    {
        validate_coefficient_slot_bindings(
            &format!("vssShareLinkage.additionalLinkageItems.{item_index}"),
            coefficient_slot_indices,
            &item.coefficient_commitments,
        )?;
    }
    if ring_degree == 0 {
        return Err(invalid_succinct_setup_proof(
            "VSS share-linkage ring degree must be positive",
        ));
    }

    Ok(())
}

fn validate_same_secret_bridge_statement(
    statement: &SameSecretBridgeStatement,
    ring_degree: usize,
) -> CanonicalResult<()> {
    validate_protocol_hash_hex(
        "sameSecretBridge.publicMatrixSeedHash",
        &statement.public_matrix_seed_hash,
    )?;
    validate_context_token(
        "sameSecretBridge.sourceTrusteeIdentity",
        &statement.source_trustee_identity,
    )?;
    if statement.bridge_rns_primes.is_empty()
        || statement.bridge_rns_primes.len() > DATA_PRIMES.len()
        || statement.bridge_rns_primes.len() != statement.target_constant_commitment_roots.len()
        || statement.bridge_rns_primes.len() != statement.target_constant_commitments.len()
    {
        return Err(invalid_succinct_setup_proof(
            "same-secret bridge commitments and primes must be non-empty and aligned",
        ));
    }
    for (bridge_rns_limb_index, bridge_rns_prime) in statement.bridge_rns_primes.iter().enumerate()
    {
        if *bridge_rns_prime != DATA_PRIMES[bridge_rns_limb_index] {
            return Err(invalid_succinct_setup_proof(
                "same-secret bridge primes must be a canonical Q_share prefix",
            ));
        }
        validate_protocol_hash_hex(
            "sameSecretBridge.targetConstantCommitmentRoot",
            &statement.target_constant_commitment_roots[bridge_rns_limb_index],
        )?;
    }
    for commitment in &statement.target_constant_commitments {
        validate_vss_committed_material_commitment_shape(
            commitment,
            "sameSecretBridge.targetConstantCommitment",
        )?;
    }
    if ring_degree == 0 {
        return Err(invalid_succinct_setup_proof(
            "same-secret bridge ring degree must be positive",
        ));
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
