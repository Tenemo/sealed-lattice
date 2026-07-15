use super::super::{
    CLAIM_MASK_DIGIT_COUNT, CONSISTENCY_COEFFICIENT_BITS, CONSISTENCY_REPETITIONS,
    MINIMUM_TRACE_SIZE, TRACE_SPLIT, invalid_succinct_setup_proof,
};
use super::linkage_and_vss_vectors::{
    masked_claim_bounds_for_global_claim, masked_claim_lift_residue_count_for_moduli,
};
use super::statement_types::{
    EvaluationKeyShareKind, PrivateVssShareStatement, SetupProofStatement,
    SuccinctSetupProofContext, TrusteeEvaluationKeyStatement,
};
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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum SuccinctSetupProofFamilyShape {
    PrivateVssShare,
    TrusteeEvaluationKey,
}

impl SuccinctSetupProofFamilyShape {
    pub(crate) fn from_key_kinds(kinds: &[EvaluationKeyShareKind]) -> CanonicalResult<Self> {
        if kinds.is_empty() {
            return Err(invalid_succinct_setup_proof(
                "key-bearing setup proof statement requires at least one key descriptor",
            ));
        }
        Ok(Self::TrusteeEvaluationKey)
    }

    pub(crate) const fn setup_proof_family(self) -> SetupProofFamily {
        match self {
            Self::PrivateVssShare => SetupProofFamily::PrivateVssShare,
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
        CLAIM_MASK_DIGIT_COUNT
    }

    pub(crate) fn consistency_repetitions(self) -> usize {
        CONSISTENCY_REPETITIONS
    }

    pub(crate) fn consistency_coefficient_bits(self) -> u32 {
        CONSISTENCY_COEFFICIENT_BITS
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
        validate_protocol_hash_hex("setupContextHash", &self.setup_context_hash)?;
        validate_context_token("trusteeIdentity", &self.trustee_identity)?;
        if self.binding_roots.len() != shape.binding_labels().len() {
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
            append_len_prefixed_str(&mut preimage, binding_label);
            append_len_prefixed_str(&mut preimage, binding_root);
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
            ] {
                append_len_prefixed_str(&mut preimage, field);
            }
            append_u64(
                &mut preimage,
                private_vss_share.source_trustee_roster_position,
            );
            append_u64(&mut preimage, private_vss_share.recipient_roster_position);
            append_usize(&mut preimage, private_vss_share.source_rns_limb_index);
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
        // Preserve the retained-family statement hash framing that preceded
        // removal of the target-decryption variant.
        preimage.push(0);
        hash512(STATEMENT_HASH_DOMAIN, &[&preimage])
    }

    pub(in crate::bgv::setup) const fn family_shape(&self) -> SuccinctSetupProofFamilyShape {
        match &self.proof {
            SetupProofStatement::PrivateVssShare(_) => {
                SuccinctSetupProofFamilyShape::PrivateVssShare
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
        if !self.keys().is_empty()
            && SuccinctSetupProofFamilyShape::from_key_kinds(
                &self.keys().iter().map(|key| key.kind).collect::<Vec<_>>(),
            )? != shape
        {
            return Err(invalid_succinct_setup_proof(
                "key descriptors do not match the selected setup proof family",
            ));
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
            if linkage.commitments.len() != 1 {
                return Err(invalid_succinct_setup_proof(
                    "trustee evaluation-key linkage requires exactly one constant commitment",
                ));
            }
            validate_setup_commitments(&linkage.commitments, self.ring_degree, true)?;
        }
        if let Some(private_vss_share) = self.private_vss_share() {
            validate_private_vss_share_statement(private_vss_share, self.ring_degree)?;
        }
        validate_masked_claim_lift_window(self)
    }
}

fn validate_setup_commitments(
    commitments: &[crate::bgv::setup::commitment::SetupCommitmentValue],
    ring_degree: usize,
    require_constant_coefficient: bool,
) -> CanonicalResult<()> {
    for (source_limb_index, commitment) in commitments.iter().enumerate() {
        if commitment.source_rns_limb_index != source_limb_index
            || commitment.ring_degree != ring_degree
            || require_constant_coefficient && commitment.shamir_coefficient_index != 0
            || commitment.limbs.len() != SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len()
        {
            return Err(invalid_succinct_setup_proof(
                "setup commitment shape does not match the statement",
            ));
        }
        for (commitment_field, limb) in commitment.limbs.iter().enumerate() {
            if limb.commitment_modulus_index != commitment_field
                || limb.modulus != DATA_PRIMES[commitment_field]
                || limb.rows.len() != SETUP_COMMITMENT_ROW_COUNT
                || limb.rows.iter().any(|row| row.len() != ring_degree)
            {
                return Err(invalid_succinct_setup_proof(
                    "setup commitment limb shape does not match the parameters",
                ));
            }
        }
    }
    Ok(())
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
    let Some(&source_message_modulus) = DATA_PRIMES.get(statement.source_rns_limb_index) else {
        return Err(invalid_succinct_setup_proof(
            "private VSS source limb is outside the selected data basis",
        ));
    };
    if statement.share_values.len() != ring_degree
        || statement
            .share_values
            .iter()
            .any(|value| *value >= source_message_modulus)
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

fn coefficient_vector_hash(coefficients: &[u64]) -> [u8; 64] {
    let mut bytes = Vec::with_capacity(coefficients.len() * 8);
    for coefficient in coefficients {
        bytes.extend_from_slice(&coefficient.to_le_bytes());
    }
    hash512(
        "sealed-lattice/setup/trustee-evaluation-key/coefficient-vector",
        &[&bytes],
    )
}
