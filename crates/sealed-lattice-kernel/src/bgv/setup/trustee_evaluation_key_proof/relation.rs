use super::extension_field::{
    CHALLENGE_EXTENSION_DEGREE, ChallengeExtensionElement, ChallengeExtensionTower,
};
use super::*;
#[cfg(test)]
use crate::bgv::evaluator::key_switch::KEY_SWITCH_ERROR_DOMAIN;
use crate::bgv::{
    evaluator::{
        key_switch::{KEY_SWITCH_SAMPLE_DOMAIN, PLAINTEXT_MODULUS_I64},
        prg::DeterministicSampler,
    },
    profile::DATA_PRIMES,
};
use crate::hashing::hash512;
#[cfg(test)]
use evaluation_domain::negacyclic_ring_product;
use evaluation_domain::negacyclic_transpose_product;
#[cfg(test)]
use num_bigint::BigInt;

#[cfg(test)]
use crate::bgv::setup::commitment::compute_setup_big_signed_lifted_commitment;
use crate::bgv::setup::commitment::{
    SETUP_COMMITMENT_MODULE_RANK, SETUP_COMMITMENT_MODULUS_LIMB_INDICES,
    SETUP_COMMITMENT_RANDOMNESS_WIDTH, SETUP_COMMITMENT_ROW_COUNT, SetupCommitmentValue,
    StructuralMatrixPolynomial, setup_commitment_matrix_coefficients_cached,
    structural_matrix_polynomial_kind,
};
use crate::bgv::setup::sampling::dense_public_residues_with_degree;
use crate::bgv::setup::sharing::canonical_trustee_point;

#[cfg(test)]
const WITNESS_SECRET_DOMAIN: &str = "sealed-lattice/setup/trustee-evaluation-key/witness-secret-v1";
const STATEMENT_HASH_DOMAIN: &str = "sealed-lattice/setup/trustee-evaluation-key/statement-v2";
const PROTOCOL_HASH_HEX_LENGTH: usize = 128;
const MAX_CONTEXT_TOKEN_BYTES: usize = 512;

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
    fn tag_bytes(self) -> [u8; 9] {
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
    pub(super) fn has_diagonal_source(self) -> bool {
        !matches!(self, Self::PublicKeyShare)
    }
}

// Apply the Galois automorphism phi_g coefficient-wise: the monomial X^i maps
// to sign * X^(i*g mod 2N folded into [0, N) with X^N = -1).
#[cfg(test)]
pub(super) fn galois_automorphism_apply(
    values: &[u64],
    galois_element: usize,
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    let degree = values.len();
    let ring_order = 2 * degree;
    if galois_element.is_multiple_of(2) {
        return Err(invalid_succinct_setup_proof("Galois element must be odd"));
    }
    let mut rotated = vec![0_u64; degree];
    for (index, value) in values.iter().enumerate() {
        let target = (index * galois_element) % ring_order;
        if target < degree {
            rotated[target] = *value;
        } else {
            rotated[target - degree] = sub_mod_fast(0, *value, modulus);
        }
    }

    Ok(rotated)
}

// Transpose action of the automorphism matrix on a public vector:
// (M_phi^T u)_i = u[i*g mod 2N] with the negacyclic sign fold, so that
// <u, phi_g(s)> = <M_phi^T u, s>.
pub(super) fn galois_automorphism_transpose_apply(
    vector: &[u64],
    galois_element: usize,
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    let degree = vector.len();
    let ring_order = 2 * degree;
    if galois_element.is_multiple_of(2) {
        return Err(invalid_succinct_setup_proof("Galois element must be odd"));
    }
    let mut transposed = Vec::with_capacity(degree);
    for index in 0..degree {
        // The element acts modulo 2N, so a full-profile schedule value reduces
        // to a valid automorphism on a smaller ring; the target >= N branch is
        // the negacyclic X^N = -1 sign fold.
        let target = (index * galois_element) % ring_order;
        if target < degree {
            transposed.push(vector[target]);
        } else {
            transposed.push(sub_mod_fast(0, vector[target - degree], modulus));
        }
    }

    Ok(transposed)
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

// Ceremony context the proof is bound to: the shared base fields, the proof
// family label, and the family's ordered labeled binding roots. Every field
// enters the statement hash, so a proof transplanted to another ceremony,
// roster position, epoch, family, or binding object fails the transcript
// rebinding. The binding label list is fixed per family: the keyless
// same-secret linkage anchor binds the VSS coefficient commitment material
// root it bridges, and the key-bearing evaluation-key family binds the
// frozen schedule and its same-secret anchor references.
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

fn validate_context_token(field_name: &str, value: &str) -> CanonicalResult<()> {
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

fn validate_protocol_hash_hex(field_name: &str, value: &str) -> CanonicalResult<()> {
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

// A trustee's batched statement: every listed key share is proven against the
// same committed secret, with one trace commitment and one batched FRI
// instance per active limb field covering all listed keys.
pub(crate) struct TrusteeEvaluationKeyStatement {
    pub(crate) context: SuccinctSetupProofContext,
    pub(crate) ring_degree: usize,
    pub(crate) keys: Vec<EvaluationKeyShareDescriptor>,
    pub(crate) same_secret_linkage: Option<SameSecretLinkageStatement>,
    pub(crate) private_vss_share: Option<PrivateVssShareStatement>,
}

pub(crate) struct TrusteeEvaluationKeyWitness {
    pub(crate) secret_coefficients: Vec<i64>,
    // error_coefficients_by_key[key][digit] follows each key's digit count.
    pub(crate) error_coefficients_by_key: Vec<Vec<Vec<i64>>>,
    // Linkage witnesses, present exactly when the statement carries the
    // same-secret linkage: the binary negative-indicator vector and the
    // ternary opening randomness per Q_share limb and column.
    pub(crate) negative_indicator_coefficients: Vec<i64>,
    pub(crate) opening_randomness_by_limb: Vec<Vec<Vec<i64>>>,
    // Private VSS witnesses, present exactly for the recipient-private VSS
    // family. Coefficient messages are canonical non-negative residues stored
    // as signed integers for shared residue conversion.
    pub(crate) private_vss_coefficient_messages_by_shamir_index: Vec<Vec<i64>>,
    pub(crate) private_vss_opening_randomness_by_shamir_index: Vec<Vec<Vec<i64>>>,
    pub(crate) private_vss_carry_witnesses: Vec<i64>,
}

impl EvaluationKeyShareDescriptor {
    // Error vectors carried by this key: one per gadget digit for key-switch
    // kinds, one in total for the public-key share relation.
    pub(super) fn digit_count(&self) -> usize {
        match self.kind {
            EvaluationKeyShareKind::PublicKeyShare => 1,
            _ => self.level + 1,
        }
    }

    // Limb width of every component_b_by_digit row: the key's active limbs.
    fn limb_width(&self) -> usize {
        self.level + 1
    }

    fn validate_shape(&self, ring_degree: usize) -> CanonicalResult<()> {
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
                // order, so frozen profile-scale schedule elements stay valid
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
    pub(super) fn public_sample(
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

    // The diagonal source vector D tested against the secret in limb l, chosen
    // so that <U, source> = <D, s>: U for round one, Neg(A_l)^T U for round
    // two, and M_phi^T U for a Galois rotation. The public-key share relation
    // has no diagonal source.
    pub(super) fn diagonal_source_vector(
        &self,
        limb_index: usize,
        u_powers: &[u64],
        modulus: u64,
    ) -> CanonicalResult<Vec<u64>> {
        match self.kind {
            EvaluationKeyShareKind::RelinearizationRoundOne => Ok(u_powers.to_vec()),
            EvaluationKeyShareKind::RelinearizationRoundTwo => negacyclic_transpose_product(
                &self.round_one_aggregate_diagonal[limb_index],
                u_powers,
                modulus,
            ),
            EvaluationKeyShareKind::GaloisRotation { galois_element } => {
                galois_automorphism_transpose_apply(u_powers, galois_element, modulus)
            }
            EvaluationKeyShareKind::PublicKeyShare => Err(invalid_succinct_setup_proof(
                "the public-key share relation has no diagonal source",
            )),
        }
    }

    // The same diagonal source action on an extension challenge vector: the
    // action is base-linear, so it applies to each extension coordinate.
    pub(super) fn diagonal_source_vector_extension(
        &self,
        limb_index: usize,
        u_powers: &[ChallengeExtensionElement],
        modulus: u64,
    ) -> CanonicalResult<Vec<ChallengeExtensionElement>> {
        let mut result = vec![ChallengeExtensionTower::zero(); u_powers.len()];
        let mut coordinate_vector = vec![0_u64; u_powers.len()];
        for coordinate in 0..CHALLENGE_EXTENSION_DEGREE {
            for (slot, element) in coordinate_vector.iter_mut().zip(u_powers.iter()) {
                *slot = element[coordinate];
            }
            let applied = self.diagonal_source_vector(limb_index, &coordinate_vector, modulus)?;
            for (target, value) in result.iter_mut().zip(applied.iter()) {
                target[coordinate] = *value;
            }
        }

        Ok(result)
    }
}

impl TrusteeEvaluationKeyStatement {
    // The number of active limb fields: one past the highest key level. The
    // keyless same-secret linkage anchor statement is active exactly on the
    // commitment fields, where its opening relations live.
    pub(super) fn limb_count(&self) -> usize {
        if self.private_vss_share.is_some() {
            return SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len();
        }
        self.keys.iter().map(|key| key.level + 1).max().unwrap_or(
            if self.same_secret_linkage.is_some() {
                SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len()
            } else {
                0
            },
        )
    }

    pub(super) fn limb_moduli(&self) -> &'static [u64] {
        &DATA_PRIMES[..self.limb_count()]
    }

    // Indices of the keys whose level reaches the given limb.
    pub(super) fn active_key_indices(&self, limb_index: usize) -> Vec<usize> {
        self.keys
            .iter()
            .enumerate()
            .filter(|(_, key)| key.level >= limb_index)
            .map(|(key_index, _)| key_index)
            .collect()
    }

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

    // Number of linkage opening-randomness logical columns active in a limb:
    // the linkage relations live only in the commitment fields (the first
    // three data primes).
    pub(super) fn linkage_randomness_count(&self, limb_index: usize) -> usize {
        match &self.same_secret_linkage {
            Some(linkage) if limb_index < SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() => {
                linkage.commitments.len() * SETUP_COMMITMENT_RANDOMNESS_WIDTH
            }
            _ => 0,
        }
    }

    pub(super) fn private_vss_randomness_count(&self, limb_index: usize) -> usize {
        match &self.private_vss_share {
            Some(statement) if limb_index < SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() => {
                statement.coefficient_commitments.len() * SETUP_COMMITMENT_RANDOMNESS_WIDTH
            }
            _ => 0,
        }
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

// Deterministic public key-switch sample for one digit and limb, matching the
// production sampler framing exactly.
pub(super) fn public_key_switch_sample(
    key_switch_domain: &str,
    key_switch_seed_hex: &str,
    digit_index: usize,
    modulus: u64,
    ring_degree: usize,
) -> Vec<u64> {
    let digit_bytes = (digit_index as u64).to_le_bytes();
    let modulus_bytes = modulus.to_le_bytes();
    DeterministicSampler::new(
        KEY_SWITCH_SAMPLE_DOMAIN,
        &[
            key_switch_domain.as_bytes(),
            key_switch_seed_hex.as_bytes(),
            &digit_bytes,
            &modulus_bytes,
        ],
    )
    .uniform_residues(modulus, ring_degree)
}

#[cfg(test)]
fn sample_development_errors(
    key_switch_domain: &str,
    key_switch_seed_hex: &str,
    digit_count: usize,
    ring_degree: usize,
) -> Vec<Vec<i64>> {
    (0..digit_count)
        .map(|digit_index| {
            DeterministicSampler::new(
                KEY_SWITCH_ERROR_DOMAIN,
                &[
                    key_switch_domain.as_bytes(),
                    key_switch_seed_hex.as_bytes(),
                    &(digit_index as u64).to_le_bytes(),
                ],
            )
            .centered_binomial_eta2(ring_degree)
        })
        .collect()
}

// Build component material so the relation holds: for digit j, limb l,
//   b = p * e_j - a_{j,l} (*) s + [l == j] * source_j,
// where source_j is the diagonal source residue vector in field q_j.
#[cfg(test)]
fn build_component_material(
    key_switch_domain: &str,
    key_switch_seed_hex: &str,
    level: usize,
    ring_degree: usize,
    secret_coefficients: &[i64],
    error_coefficients_by_digit: &[Vec<i64>],
    diagonal_source_by_digit: &[Vec<u64>],
) -> CanonicalResult<Vec<Vec<Vec<u64>>>> {
    let digit_count = level + 1;
    let mut component_b_by_digit = Vec::with_capacity(digit_count);
    for (digit_index, error_coefficients) in error_coefficients_by_digit.iter().enumerate() {
        let mut component_b_by_limb = Vec::with_capacity(digit_count);
        for (limb_index, modulus) in DATA_PRIMES[..=level].iter().enumerate() {
            let public_sample = public_key_switch_sample(
                key_switch_domain,
                key_switch_seed_hex,
                digit_index,
                *modulus,
                ring_degree,
            );
            let secret_residues = secret_coefficients
                .iter()
                .map(|coefficient| signed_value_residue(*coefficient, *modulus))
                .collect::<Vec<_>>();
            let sample_secret_product =
                negacyclic_ring_product(&public_sample, &secret_residues, *modulus)?;
            let component_b = (0..ring_degree)
                .map(|coefficient_index| {
                    let scaled_error = signed_value_residue(
                        error_coefficients[coefficient_index] * PLAINTEXT_MODULUS_I64,
                        *modulus,
                    );
                    let mut value = sub_mod_fast(
                        scaled_error,
                        sample_secret_product[coefficient_index],
                        *modulus,
                    );
                    if limb_index == digit_index {
                        value = add_mod_fast(
                            value,
                            diagonal_source_by_digit[digit_index][coefficient_index],
                            *modulus,
                        );
                    }
                    value
                })
                .collect::<Vec<_>>();
            component_b_by_limb.push(component_b);
        }
        component_b_by_digit.push(component_b_by_limb);
    }

    Ok(component_b_by_digit)
}

#[cfg(test)]
const ROUND_ONE_AGGREGATE_DOMAIN: &str =
    "sealed-lattice/setup/trustee-evaluation-key/development-round-one-aggregate-v1";

// One development key descriptor plus its errors, for an already-sampled
// shared secret.
#[cfg(test)]
fn generate_development_key(
    kind: EvaluationKeyShareKind,
    key_switch_seed_hex: &str,
    level: usize,
    ring_degree: usize,
    secret_coefficients: &[i64],
) -> CanonicalResult<(EvaluationKeyShareDescriptor, Vec<Vec<i64>>)> {
    let key_switch_domain = match kind {
        EvaluationKeyShareKind::RelinearizationRoundOne => "relinearization-round-one".to_string(),
        EvaluationKeyShareKind::RelinearizationRoundTwo => "relinearization-round-two".to_string(),
        EvaluationKeyShareKind::GaloisRotation { galois_element } => {
            format!("rotation-{galois_element}")
        }
        EvaluationKeyShareKind::PublicKeyShare => {
            return Err(invalid_succinct_setup_proof(
                "the public-key share family uses its own development generator",
            ));
        }
    };
    let digit_count = level + 1;
    let error_coefficients_by_digit = sample_development_errors(
        &key_switch_domain,
        key_switch_seed_hex,
        digit_count,
        ring_degree,
    );
    let mut round_one_aggregate_diagonal = Vec::new();
    let mut diagonal_source_by_digit = Vec::with_capacity(digit_count);
    for (digit_index, modulus) in DATA_PRIMES[..=level].iter().enumerate() {
        let secret_residues = secret_coefficients
            .iter()
            .map(|coefficient| signed_value_residue(*coefficient, *modulus))
            .collect::<Vec<_>>();
        let source = match kind {
            EvaluationKeyShareKind::RelinearizationRoundOne => secret_residues,
            EvaluationKeyShareKind::RelinearizationRoundTwo => {
                let aggregate = DeterministicSampler::new(
                    ROUND_ONE_AGGREGATE_DOMAIN,
                    &[
                        key_switch_seed_hex.as_bytes(),
                        key_switch_domain.as_bytes(),
                        &(digit_index as u64).to_le_bytes(),
                        &modulus.to_le_bytes(),
                    ],
                )
                .uniform_residues(*modulus, ring_degree);
                let source = negacyclic_ring_product(&secret_residues, &aggregate, *modulus)?;
                round_one_aggregate_diagonal.push(aggregate);
                source
            }
            EvaluationKeyShareKind::GaloisRotation { galois_element } => {
                galois_automorphism_apply(&secret_residues, galois_element, *modulus)?
            }
            EvaluationKeyShareKind::PublicKeyShare => {
                // The key_switch_domain match above already returned an error
                // for the public-key share, so this arm is never reached.
                unreachable!("public-key share uses its own development generator");
            }
        };
        diagonal_source_by_digit.push(source);
    }
    let component_b_by_digit = build_component_material(
        &key_switch_domain,
        key_switch_seed_hex,
        level,
        ring_degree,
        secret_coefficients,
        &error_coefficients_by_digit,
        &diagonal_source_by_digit,
    )?;

    Ok((
        EvaluationKeyShareDescriptor {
            kind,
            level,
            key_switch_domain,
            key_switch_seed_hex: key_switch_seed_hex.to_string(),
            component_b_by_digit,
            round_one_aggregate_diagonal,
        },
        error_coefficients_by_digit,
    ))
}

#[cfg(test)]
const LINKAGE_RANDOMNESS_DOMAIN: &str =
    "sealed-lattice/setup/trustee-evaluation-key/linkage-opening-randomness-v1";
#[cfg(test)]
const LINKAGE_MATRIX_SEED_DOMAIN: &str =
    "sealed-lattice/setup/trustee-evaluation-key/linkage-matrix-seed-v1";

// Development instance generator for a whole trustee key schedule: one shared
// ternary secret and a list of key kinds at their levels, all with real
// production-shaped component material. When a Q_share limb count is given,
// the instance also carries the same-secret linkage: real BDLOP constant
// commitments to the lifted secret message per Q_share limb, with fresh
// ternary opening randomness.
#[cfg(test)]
fn development_context(key_switch_seed_hex: &str, keyless: bool) -> SuccinctSetupProofContext {
    let derived = |label: &str| -> String {
        hash512(
            "sealed-lattice/setup/trustee-evaluation-key/development-context-v1",
            &[key_switch_seed_hex.as_bytes(), label.as_bytes()],
        )
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
    };
    let (proof_family, binding_labels): (&str, &[&str]) = if keyless {
        (
            super::SAME_SECRET_LINKAGE_ANCHOR_PROOF_FAMILY,
            &SAME_SECRET_LINKAGE_ANCHOR_BINDING_LABELS,
        )
    } else {
        (
            super::TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
            &TRUSTEE_EVALUATION_KEY_BINDING_LABELS,
        )
    };

    SuccinctSetupProofContext {
        proof_family: proof_family.to_string(),
        ceremony_id: format!("development-ceremony-{key_switch_seed_hex}"),
        manifest_hash: derived("manifest"),
        roster_hash: derived("roster"),
        trustee_identity: format!("development-trustee-{key_switch_seed_hex}"),
        trustee_roster_position: 1,
        setup_epoch: "development-epoch-1".to_string(),
        binding_roots: binding_labels
            .iter()
            .map(|label| ((*label).to_string(), derived(label)))
            .collect(),
    }
}

#[cfg(test)]
pub(crate) fn generate_development_trustee_instance_with_linkage(
    key_switch_seed_hex: &str,
    key_requests: &[(EvaluationKeyShareKind, usize)],
    ring_degree: usize,
    linkage_commitment_count: Option<usize>,
) -> CanonicalResult<(TrusteeEvaluationKeyStatement, TrusteeEvaluationKeyWitness)> {
    let secret_coefficients =
        DeterministicSampler::new(WITNESS_SECRET_DOMAIN, &[key_switch_seed_hex.as_bytes()])
            .ternary(ring_degree);
    let mut keys = Vec::with_capacity(key_requests.len());
    let mut error_coefficients_by_key = Vec::with_capacity(key_requests.len());
    for (request_index, (kind, level)) in key_requests.iter().enumerate() {
        let key_seed = format!("{key_switch_seed_hex}-{request_index}");
        let (descriptor, errors) =
            generate_development_key(*kind, &key_seed, *level, ring_degree, &secret_coefficients)?;
        keys.push(descriptor);
        error_coefficients_by_key.push(errors);
    }
    let mut same_secret_linkage = None;
    let mut negative_indicator_coefficients = Vec::new();
    let mut opening_randomness_by_limb = Vec::new();
    if let Some(commitment_count) = linkage_commitment_count {
        let public_matrix_seed_hash = {
            let digest = hash512(
                LINKAGE_MATRIX_SEED_DOMAIN,
                &[key_switch_seed_hex.as_bytes()],
            );
            digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        negative_indicator_coefficients = secret_coefficients
            .iter()
            .map(|coefficient| i64::from(*coefficient < 0))
            .collect::<Vec<_>>();
        let mut commitments = Vec::with_capacity(commitment_count);
        for (source_limb_index, source_modulus) in
            DATA_PRIMES[..commitment_count].iter().copied().enumerate()
        {
            let randomness = (0..SETUP_COMMITMENT_RANDOMNESS_WIDTH)
                .map(|column| {
                    DeterministicSampler::new(
                        LINKAGE_RANDOMNESS_DOMAIN,
                        &[
                            key_switch_seed_hex.as_bytes(),
                            &(source_limb_index as u64).to_le_bytes(),
                            &(column as u64).to_le_bytes(),
                        ],
                    )
                    .ternary(ring_degree)
                })
                .collect::<Vec<_>>();
            let message = secret_coefficients
                .iter()
                .zip(negative_indicator_coefficients.iter())
                .map(|(secret, indicator)| {
                    BigInt::from(*secret) + BigInt::from(*indicator) * BigInt::from(source_modulus)
                })
                .collect::<Vec<_>>();
            let randomness_i128 = randomness
                .iter()
                .map(|column| column.iter().map(|value| i128::from(*value)).collect())
                .collect::<Vec<Vec<i128>>>();
            commitments.push(compute_setup_big_signed_lifted_commitment(
                &public_matrix_seed_hash,
                source_limb_index,
                source_modulus,
                0,
                &message,
                &randomness_i128,
                ring_degree,
            )?);
            opening_randomness_by_limb.push(randomness);
        }
        same_secret_linkage = Some(SameSecretLinkageStatement {
            public_matrix_seed_hash,
            commitments,
        });
    }

    Ok((
        TrusteeEvaluationKeyStatement {
            context: development_context(key_switch_seed_hex, key_requests.is_empty()),
            ring_degree,
            keys,
            same_secret_linkage,
            private_vss_share: None,
        },
        TrusteeEvaluationKeyWitness {
            secret_coefficients,
            error_coefficients_by_key,
            negative_indicator_coefficients,
            opening_randomness_by_limb,
            private_vss_coefficient_messages_by_shamir_index: Vec::new(),
            private_vss_opening_randomness_by_shamir_index: Vec::new(),
            private_vss_carry_witnesses: Vec::new(),
        },
    ))
}

#[cfg(test)]
pub(crate) fn generate_development_trustee_instance(
    key_switch_seed_hex: &str,
    key_requests: &[(EvaluationKeyShareKind, usize)],
    ring_degree: usize,
) -> CanonicalResult<(TrusteeEvaluationKeyStatement, TrusteeEvaluationKeyWitness)> {
    generate_development_trustee_instance_with_linkage(
        key_switch_seed_hex,
        key_requests,
        ring_degree,
        None,
    )
}

// Development public-key share instance: one ternary secret s and one
// centered-binomial error e produce the published share b_l = p*e - a_l (*) s
// over every Q_share limb against the seed-derived common reference
// polynomial, plus one constant commitment (limb zero) opening s for the
// anchor link.
#[cfg(test)]
pub(crate) fn generate_development_public_key_share_instance(
    seed_hex: &str,
    ring_degree: usize,
) -> CanonicalResult<(TrusteeEvaluationKeyStatement, TrusteeEvaluationKeyWitness)> {
    let secret_coefficients =
        DeterministicSampler::new(WITNESS_SECRET_DOMAIN, &[seed_hex.as_bytes()])
            .ternary(ring_degree);
    let error_coefficients = DeterministicSampler::new(
        KEY_SWITCH_ERROR_DOMAIN,
        &[seed_hex.as_bytes(), b"public-key-share-error"],
    )
    .centered_binomial_eta2(ring_degree);
    let public_matrix_seed_hash = {
        let digest = hash512(LINKAGE_MATRIX_SEED_DOMAIN, &[seed_hex.as_bytes()]);
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    // b_l = p * e - a_l (*) s over every Q_share limb.
    let level = DATA_PRIMES.len() - 1;
    let mut component_b_by_limb = Vec::with_capacity(DATA_PRIMES.len());
    for modulus in DATA_PRIMES.iter().copied() {
        let public_sample = dense_public_residues_with_degree(
            &public_matrix_seed_hash,
            PUBLIC_KEY_SHARE_COMMON_REFERENCE_LABEL,
            modulus,
            ring_degree,
        );
        let secret_residues = secret_coefficients
            .iter()
            .map(|coefficient| signed_value_residue(*coefficient, modulus))
            .collect::<Vec<_>>();
        let sample_secret_product =
            negacyclic_ring_product(&public_sample, &secret_residues, modulus)?;
        let component_b = (0..ring_degree)
            .map(|coefficient_index| {
                let scaled_error = signed_value_residue(
                    error_coefficients[coefficient_index] * PLAINTEXT_MODULUS_I64,
                    modulus,
                );
                sub_mod_fast(
                    scaled_error,
                    sample_secret_product[coefficient_index],
                    modulus,
                )
            })
            .collect::<Vec<_>>();
        component_b_by_limb.push(component_b);
    }
    let descriptor = EvaluationKeyShareDescriptor {
        kind: EvaluationKeyShareKind::PublicKeyShare,
        level,
        key_switch_domain: PUBLIC_KEY_SHARE_COMMON_REFERENCE_LABEL.to_string(),
        key_switch_seed_hex: public_matrix_seed_hash.clone(),
        component_b_by_digit: vec![component_b_by_limb],
        round_one_aggregate_diagonal: Vec::new(),
    };
    // One constant commitment (limb zero) linking s to the anchor.
    let negative_indicator_coefficients = secret_coefficients
        .iter()
        .map(|coefficient| i64::from(*coefficient < 0))
        .collect::<Vec<_>>();
    let source_modulus = DATA_PRIMES[0];
    let randomness = (0..SETUP_COMMITMENT_RANDOMNESS_WIDTH)
        .map(|column| {
            DeterministicSampler::new(
                LINKAGE_RANDOMNESS_DOMAIN,
                &[seed_hex.as_bytes(), &(column as u64).to_le_bytes()],
            )
            .ternary(ring_degree)
        })
        .collect::<Vec<_>>();
    let message = secret_coefficients
        .iter()
        .zip(negative_indicator_coefficients.iter())
        .map(|(secret, indicator)| {
            BigInt::from(*secret) + BigInt::from(*indicator) * BigInt::from(source_modulus)
        })
        .collect::<Vec<_>>();
    let randomness_i128 = randomness
        .iter()
        .map(|column| column.iter().map(|value| i128::from(*value)).collect())
        .collect::<Vec<Vec<i128>>>();
    let commitment = compute_setup_big_signed_lifted_commitment(
        &public_matrix_seed_hash,
        0,
        source_modulus,
        0,
        &message,
        &randomness_i128,
        ring_degree,
    )?;
    let same_secret_linkage = Some(SameSecretLinkageStatement {
        public_matrix_seed_hash,
        commitments: vec![commitment],
    });
    let context = development_public_key_share_context(seed_hex);

    Ok((
        TrusteeEvaluationKeyStatement {
            context,
            ring_degree,
            keys: vec![descriptor],
            same_secret_linkage,
            private_vss_share: None,
        },
        TrusteeEvaluationKeyWitness {
            secret_coefficients,
            error_coefficients_by_key: vec![vec![error_coefficients]],
            negative_indicator_coefficients,
            opening_randomness_by_limb: vec![randomness],
            private_vss_coefficient_messages_by_shamir_index: Vec::new(),
            private_vss_opening_randomness_by_shamir_index: Vec::new(),
            private_vss_carry_witnesses: Vec::new(),
        },
    ))
}

#[cfg(test)]
fn development_public_key_share_context(seed_hex: &str) -> SuccinctSetupProofContext {
    let derived = |label: &str| -> String {
        hash512(
            "sealed-lattice/setup/public-key-share/development-context-v1",
            &[seed_hex.as_bytes(), label.as_bytes()],
        )
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
    };

    SuccinctSetupProofContext {
        proof_family: super::PUBLIC_KEY_SHARE_PROOF_FAMILY.to_string(),
        ceremony_id: format!("development-ceremony-{seed_hex}"),
        manifest_hash: derived("manifest"),
        roster_hash: derived("roster"),
        trustee_identity: format!("development-trustee-{seed_hex}"),
        trustee_roster_position: 1,
        setup_epoch: "development-epoch-1".to_string(),
        binding_roots: PUBLIC_KEY_SHARE_SUCCINCT_BINDING_LABELS
            .iter()
            .map(|label| ((*label).to_string(), derived(label)))
            .collect(),
    }
}

// Per-limb physical column layout. Every logical length-N vector occupies
// TRACE_SPLIT physical columns of length N / TRACE_SPLIT, in half order. The
// layout is: secret halves, then per active key per digit the error halves,
// then the matching error-square halves, then the claim-mask digit halves.
pub(super) struct LimbColumnLayout {
    pub(super) ring_degree: usize,
    pub(super) trace_size: usize,
    pub(super) family_shape: SuccinctSetupProofFamilyShape,
    // (key index, digit count) per active key, in key order.
    pub(super) active_keys: Vec<(usize, usize)>,
    pub(super) total_error_columns: usize,
    pub(super) private_vss_coefficient_columns: usize,
    // Linkage logical columns active in this limb: the binary negative
    // indicator plus the per-commitment opening-randomness columns, or zero
    // outside the commitment fields.
    pub(super) linkage_randomness_columns: usize,
    pub(super) private_vss_randomness_columns: usize,
    pub(super) mask_column_count: usize,
}

impl LimbColumnLayout {
    pub(super) fn new(
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
        if active_keys.is_empty()
            && statement.linkage_randomness_count(limb_index) == 0
            && private_vss_coefficient_columns == 0
        {
            return Err(invalid_succinct_setup_proof(
                "limb layout requires an active key or active linkage relations",
            ));
        }
        let total_error_columns = active_keys.iter().map(|(_, digits)| *digits).sum::<usize>();
        let linkage_randomness_columns = statement.linkage_randomness_count(limb_index);
        let private_vss_randomness_columns = statement.private_vss_randomness_count(limb_index);
        let ring_degree = statement.ring_degree;
        // The mask columns are sized from the number of published consistency
        // claims, so this must mirror consistency_vector_count() exactly. For
        // private VSS the message (Shamir coefficient) columns carry no
        // consistency claim (they are pinned by the opening rows plus the
        // opening-randomness consistency), so the count is the carry plus the
        // opening-randomness columns, not the full logical column count. Sizing
        // the masks from the logical column count instead would commit unused
        // mask columns for claims that are never published.
        let consistency_vector_count = match family_shape {
            SuccinctSetupProofFamilyShape::PrivateVssShare => 1 + private_vss_randomness_columns,
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
            linkage_randomness_columns,
            private_vss_randomness_columns,
            mask_column_count,
        })
    }

    pub(super) fn linkage_active(&self) -> bool {
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

    pub(super) fn private_vss_active(&self) -> bool {
        self.family_shape == SuccinctSetupProofFamilyShape::PrivateVssShare
    }

    // Every private-VSS logical witness column committed in the trace: the
    // message (Shamir coefficient) columns, the carry column, and the
    // opening-randomness columns. This is the trace width and the length of the
    // opening lincheck (`publics.linkage`). It deliberately exceeds
    // consistency_vector_count(), which now claims only the carry and randomness
    // columns; the message columns remain witnesses pinned by the opening rows.
    pub(super) fn private_vss_logical_columns(&self) -> usize {
        if self.private_vss_active() {
            self.private_vss_coefficient_columns + 1 + self.private_vss_randomness_columns
        } else {
            0
        }
    }

    pub(super) fn private_vss_relation_count(&self) -> usize {
        if self.private_vss_active() {
            self.private_vss_coefficient_columns * SETUP_COMMITMENT_ROW_COUNT + 1
        } else {
            0
        }
    }

    // Logical witness vectors carrying cross-limb consistency claims: the
    // shared secret first, then every active key's error vectors in order,
    // then the linkage negative indicator and opening-randomness vectors.
    pub(super) fn consistency_vector_count(&self) -> usize {
        if self.private_vss_active() {
            // The message (Shamir coefficient) columns are intentionally NOT
            // consistency-claimed. They are pinned across the commitment fields
            // by the per-field opening rows plus the ternary opening-randomness
            // consistency: with the randomness fixed to one integer r* across the
            // fields, each opening row forces the message to the residues of the
            // single integer (t - A*r*)_msg, so a masked message consistency
            // claim would only add zero-knowledge leakage with no soundness gain.
            // Only the carry and the opening-randomness columns carry consistency
            // claims. This intentionally diverges from private_vss_logical_columns(),
            // which still counts the message columns because they remain witness
            // columns for the opening and share relations (the opening lincheck).
            1 + self.private_vss_randomness_columns
        } else {
            1 + self.total_error_columns + self.linkage_logical_columns()
        }
    }

    pub(super) fn claim_count(&self) -> usize {
        self.consistency_vector_count() * CONSISTENCY_REPETITIONS
    }

    pub(super) fn physical_secret(&self, half: usize) -> usize {
        debug_assert!(!self.private_vss_active());
        half
    }

    // error_position counts error vectors across active keys in layout order.
    pub(super) fn physical_error(&self, error_position: usize, half: usize) -> usize {
        debug_assert!(!self.private_vss_active());
        TRACE_SPLIT * (1 + error_position) + half
    }

    pub(super) fn physical_error_square(&self, error_position: usize, half: usize) -> usize {
        debug_assert!(!self.private_vss_active());
        TRACE_SPLIT * (1 + self.total_error_columns + error_position) + half
    }

    pub(super) fn physical_negative_indicator(&self, half: usize) -> usize {
        debug_assert!(self.linkage_active());
        debug_assert!(!self.private_vss_active());
        TRACE_SPLIT * (1 + 2 * self.total_error_columns) + half
    }

    pub(super) fn physical_linkage_randomness(
        &self,
        randomness_position: usize,
        half: usize,
    ) -> usize {
        debug_assert!(self.linkage_active());
        debug_assert!(!self.private_vss_active());
        TRACE_SPLIT * (1 + 2 * self.total_error_columns + 1 + randomness_position) + half
    }

    pub(super) fn physical_private_vss_message(
        &self,
        coefficient_index: usize,
        half: usize,
    ) -> usize {
        debug_assert!(self.private_vss_active());
        TRACE_SPLIT * coefficient_index + half
    }

    pub(super) fn physical_private_vss_carry(&self, half: usize) -> usize {
        debug_assert!(self.private_vss_active());
        TRACE_SPLIT * self.private_vss_coefficient_columns + half
    }

    pub(super) fn physical_private_vss_randomness(
        &self,
        randomness_position: usize,
        half: usize,
    ) -> usize {
        debug_assert!(self.private_vss_active());
        TRACE_SPLIT * (self.private_vss_coefficient_columns + 1 + randomness_position) + half
    }

    pub(super) fn physical_mask(&self, mask_column: usize, half: usize) -> usize {
        let logical_prefix = if self.private_vss_active() {
            self.private_vss_logical_columns()
        } else {
            1 + 2 * self.total_error_columns + self.linkage_logical_columns()
        };
        TRACE_SPLIT * (logical_prefix + mask_column) + half
    }

    pub(super) fn phase_one_physical_count(&self) -> usize {
        let logical_prefix = if self.private_vss_active() {
            self.private_vss_logical_columns()
        } else {
            1 + 2 * self.total_error_columns + self.linkage_logical_columns()
        };
        TRACE_SPLIT * (logical_prefix + self.mask_column_count)
    }

    // Row-check constraints are present for restricted witness columns and
    // mask digits. Private VSS message and carry columns are unrestricted
    // field columns; their integer lift is checked by masked consistency.
    pub(super) fn row_check_constraint_count(&self) -> usize {
        if self.private_vss_active() {
            TRACE_SPLIT * (self.private_vss_randomness_columns + self.mask_column_count)
        } else {
            self.phase_one_physical_count()
        }
    }

    // Mask slot of one claim digit: claims are laid out consecutively with
    // CLAIM_MASK_DIGIT_COUNT binary digits each.
    pub(super) fn mask_slot(
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

pub(super) const PHASE_TWO_COLUMN_COUNT: usize = 4;
pub(super) const QUOTIENT_COLUMN_ROW_CHECK_LOW: usize = 0;
pub(super) const QUOTIENT_COLUMN_ROW_CHECK_HIGH: usize = 1;
pub(super) const QUOTIENT_COLUMN_SUMCHECK_VANISHING: usize = 2;
pub(super) const QUOTIENT_COLUMN_SUMCHECK_LINEAR: usize = 3;

// Column value domain for the composition functions: the prover evaluates
// them over base-field committed column values, the verifier re-evaluates the
// same expressions over extension-valued out-of-domain evaluations. One
// generic implementation keeps the constraint enumeration identical on both
// sides; the challenges always live in the extension.
pub(super) trait CompositionColumnDomain {
    type Value: Copy;

    fn tower(&self) -> &ChallengeExtensionTower;
    fn value_mul(&self, left: &Self::Value, right: &Self::Value) -> Self::Value;
    fn value_sub(&self, left: &Self::Value, right: &Self::Value) -> Self::Value;
    fn value_sub_base(&self, left: &Self::Value, right: u64) -> Self::Value;
    // challenge * value, landing in the extension.
    fn challenge_times(
        &self,
        challenge: &ChallengeExtensionElement,
        value: &Self::Value,
    ) -> ChallengeExtensionElement;
}

pub(super) struct BaseColumnDomain {
    pub(super) tower: ChallengeExtensionTower,
}

impl CompositionColumnDomain for BaseColumnDomain {
    type Value = u64;

    fn tower(&self) -> &ChallengeExtensionTower {
        &self.tower
    }

    fn value_mul(&self, left: &u64, right: &u64) -> u64 {
        mul_mod_fast(*left, *right, self.tower.modulus)
    }

    fn value_sub(&self, left: &u64, right: &u64) -> u64 {
        sub_mod_fast(*left, *right, self.tower.modulus)
    }

    fn value_sub_base(&self, left: &u64, right: u64) -> u64 {
        sub_mod_fast(*left, right % self.tower.modulus, self.tower.modulus)
    }

    fn challenge_times(
        &self,
        challenge: &ChallengeExtensionElement,
        value: &u64,
    ) -> ChallengeExtensionElement {
        self.tower.scale_base(challenge, *value)
    }
}

pub(super) struct ExtensionColumnDomain {
    pub(super) tower: ChallengeExtensionTower,
}

impl CompositionColumnDomain for ExtensionColumnDomain {
    type Value = ChallengeExtensionElement;

    fn tower(&self) -> &ChallengeExtensionTower {
        &self.tower
    }

    fn value_mul(
        &self,
        left: &ChallengeExtensionElement,
        right: &ChallengeExtensionElement,
    ) -> ChallengeExtensionElement {
        self.tower.mul(left, right)
    }

    fn value_sub(
        &self,
        left: &ChallengeExtensionElement,
        right: &ChallengeExtensionElement,
    ) -> ChallengeExtensionElement {
        self.tower.sub(left, right)
    }

    fn value_sub_base(
        &self,
        left: &ChallengeExtensionElement,
        right: u64,
    ) -> ChallengeExtensionElement {
        self.tower
            .sub(left, &self.tower.embed_base(right % self.tower.modulus))
    }

    fn challenge_times(
        &self,
        challenge: &ChallengeExtensionElement,
        value: &ChallengeExtensionElement,
    ) -> ChallengeExtensionElement {
        self.tower.mul(challenge, value)
    }
}

// The batched row-check value sum_k beta_k * C_k at one point, given the
// phase-one physical column values at that point in layout order. One
// constraint per physical column:
//   secret halves:        S^3 - S            (ternary support)
//   error halves:         E (E2 - 1)(E2 - 4) (centered binomial support)
//   error-square halves:  E2 - E^2           (helper well-formedness)
//   mask halves:          M^2 - M            (binary digits)
pub(super) fn batched_row_check_value<Domain: CompositionColumnDomain>(
    domain: &Domain,
    column_values: &[Domain::Value],
    beta: &[ChallengeExtensionElement],
    layout: &LimbColumnLayout,
) -> ChallengeExtensionElement {
    debug_assert_eq!(column_values.len(), layout.phase_one_physical_count());
    debug_assert_eq!(beta.len(), layout.row_check_constraint_count());
    let tower = *domain.tower();
    let mut accumulated = ChallengeExtensionTower::zero();
    let mut constraint_index = 0_usize;
    let mut absorb = |value: &Domain::Value, accumulated: &mut ChallengeExtensionElement| {
        *accumulated = tower.add(
            accumulated,
            &domain.challenge_times(&beta[constraint_index], value),
        );
        constraint_index += 1;
    };
    if layout.private_vss_active() {
        for randomness_position in 0..layout.private_vss_randomness_columns {
            for half in 0..TRACE_SPLIT {
                let randomness = column_values
                    [layout.physical_private_vss_randomness(randomness_position, half)];
                let cube =
                    domain.value_mul(&domain.value_mul(&randomness, &randomness), &randomness);
                absorb(&domain.value_sub(&cube, &randomness), &mut accumulated);
            }
        }
        for mask_column in 0..layout.mask_column_count {
            for half in 0..TRACE_SPLIT {
                let mask = column_values[layout.physical_mask(mask_column, half)];
                absorb(
                    &domain.value_sub(&domain.value_mul(&mask, &mask), &mask),
                    &mut accumulated,
                );
            }
        }

        return accumulated;
    }
    for half in 0..TRACE_SPLIT {
        let secret = column_values[layout.physical_secret(half)];
        let cube = domain.value_mul(&domain.value_mul(&secret, &secret), &secret);
        absorb(&domain.value_sub(&cube, &secret), &mut accumulated);
    }
    for error_position in 0..layout.total_error_columns {
        for half in 0..TRACE_SPLIT {
            let error = column_values[layout.physical_error(error_position, half)];
            let error_square = column_values[layout.physical_error_square(error_position, half)];
            let range_polynomial = domain.value_mul(
                &domain.value_sub_base(&error_square, 1),
                &domain.value_sub_base(&error_square, 4),
            );
            absorb(
                &domain.value_mul(&error, &range_polynomial),
                &mut accumulated,
            );
        }
    }
    for error_position in 0..layout.total_error_columns {
        for half in 0..TRACE_SPLIT {
            let error = column_values[layout.physical_error(error_position, half)];
            let error_square = column_values[layout.physical_error_square(error_position, half)];
            absorb(
                &domain.value_sub(&error_square, &domain.value_mul(&error, &error)),
                &mut accumulated,
            );
        }
    }
    if layout.linkage_active() {
        for half in 0..TRACE_SPLIT {
            let indicator = column_values[layout.physical_negative_indicator(half)];
            absorb(
                &domain.value_sub(&domain.value_mul(&indicator, &indicator), &indicator),
                &mut accumulated,
            );
        }
        for randomness_position in 0..layout.linkage_randomness_columns {
            for half in 0..TRACE_SPLIT {
                let randomness =
                    column_values[layout.physical_linkage_randomness(randomness_position, half)];
                let cube =
                    domain.value_mul(&domain.value_mul(&randomness, &randomness), &randomness);
                absorb(&domain.value_sub(&cube, &randomness), &mut accumulated);
            }
        }
    }
    for mask_column in 0..layout.mask_column_count {
        for half in 0..TRACE_SPLIT {
            let mask = column_values[layout.physical_mask(mask_column, half)];
            absorb(
                &domain.value_sub(&domain.value_mul(&mask, &mask), &mask),
                &mut accumulated,
            );
        }
    }

    accumulated
}

// The per-point public evaluations the batched sumcheck integrand consumes:
// for each lincheck repetition the per-half combined secret-factor vector and
// the power vector, for each consistency repetition the per-half coefficient
// vector, and for each mask column the per-half selector combination.
pub(super) struct SumcheckPublicEvaluations<ColumnValue> {
    // [repetition][half]
    pub(super) secret_factor: Vec<[ChallengeExtensionElement; 2]>,
    pub(super) u_power: Vec<[ChallengeExtensionElement; 2]>,
    // [consistency repetition][half]; the consistency vectors are public
    // bounded integers, so their evaluations stay in the column value domain.
    pub(super) consistency: Vec<[ColumnValue; 2]>,
    // [mask column][half]
    pub(super) mask_selector: Vec<[ChallengeExtensionElement; 2]>,
    // Linkage pair vectors in fixed order: the secret-link vector, the
    // negative-indicator vector, then one combined vector per opening
    // randomness column. Empty outside the commitment fields.
    pub(super) linkage: Vec<[ChallengeExtensionElement; 2]>,
}

// Scalar weights for the error contribution of the lincheck: weight of error
// column position p at repetition r is alpha_{key(p), r} * gamma_{key(p)}^j(p).
pub(super) struct SumcheckErrorWeights {
    // [repetition][error position]
    pub(super) weights: Vec<Vec<ChallengeExtensionElement>>,
}

// The batched sumcheck integrand at one point:
//   sum_r [ SecretFactor_r * S - p * U_r * (sum_p weight_{r,p} * E_p) ]
// + sum_{c,t} alpha'_{c,t} * P_t * W_c
// + sum_i CombSel_i * Mask_i
// with every product summed over both halves.
#[allow(clippy::too_many_arguments)]
pub(super) fn batched_sumcheck_value<Domain: CompositionColumnDomain>(
    domain: &Domain,
    column_values: &[Domain::Value],
    publics: &SumcheckPublicEvaluations<Domain::Value>,
    error_weights: &SumcheckErrorWeights,
    consistency_alpha: &[ChallengeExtensionElement],
    layout: &LimbColumnLayout,
) -> ChallengeExtensionElement {
    let tower = *domain.tower();
    let plaintext_modulus = (PLAINTEXT_MODULUS_I64 as u64) % tower.modulus;
    let mut accumulated = ChallengeExtensionTower::zero();
    if layout.private_vss_active() {
        let mut claim_alpha_index = 0_usize;
        for consistency_vector in 0..layout.consistency_vector_count() {
            for repetition in 0..CONSISTENCY_REPETITIONS {
                let alpha_value = &consistency_alpha[claim_alpha_index];
                claim_alpha_index += 1;
                for half in 0..TRACE_SPLIT {
                    // Consistency vectors are [carry, opening-randomness...]; the
                    // message columns carry no consistency claim (see
                    // consistency_vector_count), so index zero is the carry and
                    // the rest are the opening-randomness columns. This order must
                    // match the prover's signed_vectors in global_claim_integers.
                    let witness_value = if consistency_vector == 0 {
                        column_values[layout.physical_private_vss_carry(half)]
                    } else {
                        column_values
                            [layout.physical_private_vss_randomness(consistency_vector - 1, half)]
                    };
                    let consistency_product =
                        domain.value_mul(&publics.consistency[repetition][half], &witness_value);
                    accumulated = tower.add(
                        &accumulated,
                        &domain.challenge_times(alpha_value, &consistency_product),
                    );
                }
            }
        }
        for (mask_column, mask_selector) in publics.mask_selector.iter().enumerate() {
            for half in 0..TRACE_SPLIT {
                accumulated = tower.add(
                    &accumulated,
                    &domain.challenge_times(
                        &mask_selector[half],
                        &column_values[layout.physical_mask(mask_column, half)],
                    ),
                );
            }
        }
        debug_assert_eq!(publics.linkage.len(), layout.private_vss_logical_columns());
        for (column_index, relation_values) in publics.linkage.iter().enumerate() {
            for (half, relation_value) in relation_values.iter().enumerate().take(TRACE_SPLIT) {
                let column_value =
                    private_vss_column_value::<Domain>(column_values, layout, column_index, half);
                accumulated = tower.add(
                    &accumulated,
                    &domain.challenge_times(relation_value, &column_value),
                );
            }
        }

        return accumulated;
    }
    for (repetition, (secret_factor, u_power)) in publics
        .secret_factor
        .iter()
        .zip(publics.u_power.iter())
        .enumerate()
    {
        for half in 0..TRACE_SPLIT {
            let secret = column_values[layout.physical_secret(half)];
            accumulated = tower.add(
                &accumulated,
                &domain.challenge_times(&secret_factor[half], &secret),
            );
            let mut weighted_error = ChallengeExtensionTower::zero();
            for error_position in 0..layout.total_error_columns {
                weighted_error = tower.add(
                    &weighted_error,
                    &domain.challenge_times(
                        &error_weights.weights[repetition][error_position],
                        &column_values[layout.physical_error(error_position, half)],
                    ),
                );
            }
            accumulated = tower.sub(
                &accumulated,
                &tower.scale_base(
                    &tower.mul(&u_power[half], &weighted_error),
                    plaintext_modulus,
                ),
            );
        }
    }
    let mut claim_alpha_index = 0_usize;
    for consistency_vector in 0..layout.consistency_vector_count() {
        for repetition in 0..CONSISTENCY_REPETITIONS {
            let alpha_value = &consistency_alpha[claim_alpha_index];
            claim_alpha_index += 1;
            for half in 0..TRACE_SPLIT {
                let witness_value = if consistency_vector == 0 {
                    column_values[layout.physical_secret(half)]
                } else if consistency_vector <= layout.total_error_columns {
                    column_values[layout.physical_error(consistency_vector - 1, half)]
                } else if consistency_vector == layout.total_error_columns + 1 {
                    column_values[layout.physical_negative_indicator(half)]
                } else {
                    column_values[layout.physical_linkage_randomness(
                        consistency_vector - layout.total_error_columns - 2,
                        half,
                    )]
                };
                let consistency_product =
                    domain.value_mul(&publics.consistency[repetition][half], &witness_value);
                accumulated = tower.add(
                    &accumulated,
                    &domain.challenge_times(alpha_value, &consistency_product),
                );
            }
        }
    }
    for (mask_column, mask_selector) in publics.mask_selector.iter().enumerate() {
        for half in 0..TRACE_SPLIT {
            accumulated = tower.add(
                &accumulated,
                &domain.challenge_times(
                    &mask_selector[half],
                    &column_values[layout.physical_mask(mask_column, half)],
                ),
            );
        }
    }
    if layout.linkage_active() {
        debug_assert_eq!(publics.linkage.len(), 2 + layout.linkage_randomness_columns);
        for (linkage_position, linkage_values) in publics.linkage.iter().enumerate() {
            for half in 0..TRACE_SPLIT {
                let column_value = if linkage_position == 0 {
                    column_values[layout.physical_secret(half)]
                } else if linkage_position == 1 {
                    column_values[layout.physical_negative_indicator(half)]
                } else {
                    column_values[layout.physical_linkage_randomness(linkage_position - 2, half)]
                };
                accumulated = tower.add(
                    &accumulated,
                    &domain.challenge_times(&linkage_values[half], &column_value),
                );
            }
        }
    }

    accumulated
}

fn private_vss_column_value<Domain: CompositionColumnDomain>(
    column_values: &[Domain::Value],
    layout: &LimbColumnLayout,
    vector_index: usize,
    half: usize,
) -> Domain::Value {
    if vector_index < layout.private_vss_coefficient_columns {
        column_values[layout.physical_private_vss_message(vector_index, half)]
    } else if vector_index == layout.private_vss_coefficient_columns {
        column_values[layout.physical_private_vss_carry(half)]
    } else {
        column_values[layout.physical_private_vss_randomness(
            vector_index - layout.private_vss_coefficient_columns - 1,
            half,
        )]
    }
}

// Combined linkage lincheck vectors for one commitment field. For every
// relation (commitment l, row k) and repetition r with Fiat-Shamir weight
// alpha_{l,k,r}, the transposed matrix action of row k lands on each witness
// column; combining across rows and repetitions yields one public vector per
// witness column, in SumcheckPublicEvaluations linkage order (secret link,
// negative indicator, then each opening-randomness column). The returned
// scalar is the alpha-weighted sum of the public commitment-row linchecks,
// which joins the combined sumcheck claim.
pub(super) fn build_linkage_public_vectors(
    linkage: &SameSecretLinkageStatement,
    commitment_field: usize,
    tower: &ChallengeExtensionTower,
    u_power_vectors: &[Vec<ChallengeExtensionElement>],
    linkage_alpha: &[ChallengeExtensionElement],
) -> CanonicalResult<(
    ChallengeExtensionElement,
    Vec<Vec<ChallengeExtensionElement>>,
)> {
    let modulus = tower.modulus;
    let ring_degree = linkage.commitments[0].ring_degree;
    let commitment_count = linkage.commitments.len();
    debug_assert_eq!(
        linkage_alpha.len(),
        commitment_count * SETUP_COMMITMENT_ROW_COUNT * LINCHECK_REPETITIONS
    );
    let mut linkage_claim = ChallengeExtensionTower::zero();
    let extension_zero_vector = || vec![ChallengeExtensionTower::zero(); ring_degree];
    let mut secret_link = extension_zero_vector();
    let mut negative_indicator = extension_zero_vector();
    let mut randomness_vectors =
        vec![extension_zero_vector(); commitment_count * SETUP_COMMITMENT_RANDOMNESS_WIDTH];
    let add_base_scaled = |target: &mut [ChallengeExtensionElement],
                           source: &[ChallengeExtensionElement],
                           scale: u64| {
        for (target_value, source_value) in target.iter_mut().zip(source.iter()) {
            *target_value = tower.add(target_value, &tower.scale_base(source_value, scale));
        }
    };
    for (commitment_index, commitment) in linkage.commitments.iter().enumerate() {
        let source_modulus_residue = commitment.source_message_modulus % modulus;
        let limb = &commitment.limbs[commitment_field];
        for row_index in 0..SETUP_COMMITMENT_ROW_COUNT {
            // Repetition-combined challenge vector for this relation.
            let mut combined_u = extension_zero_vector();
            for (repetition, u_powers) in u_power_vectors.iter().enumerate() {
                let alpha_value = &linkage_alpha[(commitment_index * SETUP_COMMITMENT_ROW_COUNT
                    + row_index)
                    * LINCHECK_REPETITIONS
                    + repetition];
                for (target_value, source_value) in combined_u.iter_mut().zip(u_powers.iter()) {
                    *target_value = tower.add(target_value, &tower.mul(alpha_value, source_value));
                }
            }
            // Public side: alpha-weighted lincheck sums of the commitment row.
            let mut row_sum = ChallengeExtensionTower::zero();
            for (u_value, row_value) in combined_u.iter().zip(limb.rows[row_index].iter()) {
                row_sum = tower.add(&row_sum, &tower.scale_base(u_value, *row_value));
            }
            linkage_claim = tower.add(&linkage_claim, &row_sum);
            // Message row: the lifted secret message s + neg * q_l.
            if row_index == SETUP_COMMITMENT_MODULE_RANK {
                add_base_scaled(&mut secret_link, &combined_u, 1);
                add_base_scaled(&mut negative_indicator, &combined_u, source_modulus_residue);
            }
            for randomness_column in 0..SETUP_COMMITMENT_RANDOMNESS_WIDTH {
                let target = &mut randomness_vectors
                    [commitment_index * SETUP_COMMITMENT_RANDOMNESS_WIDTH + randomness_column];
                match structural_matrix_polynomial_kind(row_index, randomness_column) {
                    Some(StructuralMatrixPolynomial::One) => {
                        add_base_scaled(target, &combined_u, 1);
                    }
                    Some(StructuralMatrixPolynomial::Zero) => {}
                    None => {
                        let matrix_polynomial = setup_commitment_matrix_coefficients_cached(
                            &linkage.public_matrix_seed_hash,
                            commitment.source_rns_limb_index,
                            commitment_field,
                            row_index,
                            randomness_column,
                            ring_degree,
                            modulus,
                        )?;
                        let transposed = negacyclic_transpose_product_extension(
                            &matrix_polynomial,
                            &combined_u,
                            modulus,
                        )?;
                        add_base_scaled(target, &transposed, 1);
                    }
                }
            }
        }
    }
    let mut vectors = Vec::with_capacity(2 + randomness_vectors.len());
    vectors.push(secret_link);
    vectors.push(negative_indicator);
    vectors.extend(randomness_vectors);

    Ok((linkage_claim, vectors))
}

// Combined private VSS lincheck vectors for one commitment field. The vector
// order matches the private VSS logical witness columns: every hidden Shamir
// coefficient message, the hidden carry vector, then every opening-randomness
// column by coefficient and randomness-column index.
pub(super) fn build_private_vss_public_vectors(
    statement: &PrivateVssShareStatement,
    commitment_field: usize,
    tower: &ChallengeExtensionTower,
    u_power_vectors: &[Vec<ChallengeExtensionElement>],
    relation_alpha: &[ChallengeExtensionElement],
) -> CanonicalResult<(
    ChallengeExtensionElement,
    Vec<Vec<ChallengeExtensionElement>>,
)> {
    let modulus = tower.modulus;
    let ring_degree = statement.share_values.len();
    let coefficient_count = statement.coefficient_commitments.len();
    debug_assert_eq!(
        relation_alpha.len(),
        (coefficient_count * SETUP_COMMITMENT_ROW_COUNT + 1) * LINCHECK_REPETITIONS
    );
    let extension_zero_vector = || vec![ChallengeExtensionTower::zero(); ring_degree];
    let mut relation_claim = ChallengeExtensionTower::zero();
    let mut message_vectors = vec![extension_zero_vector(); coefficient_count];
    let mut carry_vector = extension_zero_vector();
    let mut randomness_vectors =
        vec![extension_zero_vector(); coefficient_count * SETUP_COMMITMENT_RANDOMNESS_WIDTH];
    let add_base_scaled = |target: &mut [ChallengeExtensionElement],
                           source: &[ChallengeExtensionElement],
                           scale: u64| {
        for (target_value, source_value) in target.iter_mut().zip(source.iter()) {
            *target_value = tower.add(target_value, &tower.scale_base(source_value, scale));
        }
    };

    for (coefficient_index, commitment) in statement.coefficient_commitments.iter().enumerate() {
        let limb = &commitment.limbs[commitment_field];
        for row_index in 0..SETUP_COMMITMENT_ROW_COUNT {
            let relation_index = coefficient_index * SETUP_COMMITMENT_ROW_COUNT + row_index;
            let mut combined_u = extension_zero_vector();
            for (repetition, u_powers) in u_power_vectors.iter().enumerate() {
                let alpha_value =
                    &relation_alpha[relation_index * LINCHECK_REPETITIONS + repetition];
                for (target_value, source_value) in combined_u.iter_mut().zip(u_powers.iter()) {
                    *target_value = tower.add(target_value, &tower.mul(alpha_value, source_value));
                }
            }
            let mut row_sum = ChallengeExtensionTower::zero();
            for (u_value, row_value) in combined_u.iter().zip(limb.rows[row_index].iter()) {
                row_sum = tower.add(&row_sum, &tower.scale_base(u_value, *row_value));
            }
            relation_claim = tower.add(&relation_claim, &row_sum);
            if row_index == SETUP_COMMITMENT_MODULE_RANK {
                add_base_scaled(&mut message_vectors[coefficient_index], &combined_u, 1);
            }
            for randomness_column in 0..SETUP_COMMITMENT_RANDOMNESS_WIDTH {
                let target = &mut randomness_vectors
                    [coefficient_index * SETUP_COMMITMENT_RANDOMNESS_WIDTH + randomness_column];
                match structural_matrix_polynomial_kind(row_index, randomness_column) {
                    Some(StructuralMatrixPolynomial::One) => {
                        add_base_scaled(target, &combined_u, 1);
                    }
                    Some(StructuralMatrixPolynomial::Zero) => {}
                    None => {
                        let matrix_polynomial = setup_commitment_matrix_coefficients_cached(
                            &statement.public_matrix_seed_hash,
                            statement.source_rns_limb_index,
                            commitment_field,
                            row_index,
                            randomness_column,
                            ring_degree,
                            modulus,
                        )?;
                        let transposed = negacyclic_transpose_product_extension(
                            &matrix_polynomial,
                            &combined_u,
                            modulus,
                        )?;
                        add_base_scaled(target, &transposed, 1);
                    }
                }
            }
        }
    }

    let share_relation_index = coefficient_count * SETUP_COMMITMENT_ROW_COUNT;
    let trustee_point = canonical_trustee_point(
        usize::try_from(statement.recipient_roster_position).map_err(|_| {
            invalid_succinct_setup_proof("private VSS recipient roster position does not fit usize")
        })?,
        statement.source_message_modulus,
    )?;
    let mut trustee_point_powers = Vec::with_capacity(coefficient_count);
    let mut trustee_point_power = 1_u128;
    for _ in 0..coefficient_count {
        trustee_point_powers.push((trustee_point_power % u128::from(modulus)) as u64);
        trustee_point_power = trustee_point_power
            .checked_mul(u128::from(trustee_point))
            .ok_or_else(|| invalid_succinct_setup_proof("private VSS trustee point overflowed"))?;
    }
    let source_modulus_residue = statement.source_message_modulus % modulus;
    let negated_source_modulus = if source_modulus_residue == 0 {
        0
    } else {
        modulus - source_modulus_residue
    };
    for (repetition, u_powers) in u_power_vectors.iter().enumerate() {
        let alpha_value = &relation_alpha[share_relation_index * LINCHECK_REPETITIONS + repetition];
        let mut combined_u = extension_zero_vector();
        for (target_value, source_value) in combined_u.iter_mut().zip(u_powers.iter()) {
            *target_value = tower.add(target_value, &tower.mul(alpha_value, source_value));
        }
        let mut share_sum = ChallengeExtensionTower::zero();
        for (u_value, share_value) in combined_u.iter().zip(statement.share_values.iter()) {
            share_sum = tower.add(
                &share_sum,
                &tower.scale_base(u_value, *share_value % modulus),
            );
        }
        relation_claim = tower.add(&relation_claim, &share_sum);
        for (coefficient_index, power) in trustee_point_powers.iter().enumerate() {
            add_base_scaled(&mut message_vectors[coefficient_index], &combined_u, *power);
        }
        add_base_scaled(&mut carry_vector, &combined_u, negated_source_modulus);
    }

    let mut vectors = Vec::with_capacity(coefficient_count + 1 + randomness_vectors.len());
    vectors.extend(message_vectors);
    vectors.push(carry_vector);
    vectors.extend(randomness_vectors);

    Ok((relation_claim, vectors))
}

// Per-coordinate transpose product: the matrix stays in the base field, so a
// transpose action on an extension vector is the base action on each of the
// four challenge extension coordinates.
pub(super) fn negacyclic_transpose_product_extension(
    matrix_polynomial: &[u64],
    vector: &[ChallengeExtensionElement],
    modulus: u64,
) -> CanonicalResult<Vec<ChallengeExtensionElement>> {
    let mut result = vec![ChallengeExtensionTower::zero(); vector.len()];
    let mut coordinate_vector = vec![0_u64; vector.len()];
    for coordinate in 0..CHALLENGE_EXTENSION_DEGREE {
        for (slot, element) in coordinate_vector.iter_mut().zip(vector.iter()) {
            *slot = element[coordinate];
        }
        let transposed =
            negacyclic_transpose_product(matrix_polynomial, &coordinate_vector, modulus)?;
        for (target, value) in result.iter_mut().zip(transposed.iter()) {
            target[coordinate] = *value;
        }
    }

    Ok(result)
}

// Verifier-side public round-one aggregate diagonals: for digit j, the
// aggregate is the sum of every trustee's accepted round-one component b at
// digit j, limb j, reduced mod q_j. Round-two sources multiply the trustee
// secret by this public aggregate, so each trustee can form its round-two
// share from public material and the verifier rebinds the same values into
// every round-two statement.
#[cfg(test)]
pub(crate) fn round_one_aggregate_diagonal_from_components(
    round_one_components_by_trustee: &[&Vec<Vec<Vec<u64>>>],
    level: usize,
    ring_degree: usize,
) -> CanonicalResult<Vec<Vec<u64>>> {
    let digit_count = level + 1;
    if round_one_components_by_trustee.is_empty() {
        return Err(invalid_succinct_setup_proof(
            "round-one aggregate requires at least one trustee component set",
        ));
    }
    let mut aggregate = Vec::with_capacity(digit_count);
    for (digit_index, modulus) in DATA_PRIMES[..digit_count].iter().copied().enumerate() {
        let mut diagonal = vec![0_u64; ring_degree];
        for components in round_one_components_by_trustee {
            let component = components
                .get(digit_index)
                .and_then(|by_limb| by_limb.get(digit_index))
                .ok_or_else(|| {
                    invalid_succinct_setup_proof(
                        "round-one component material does not cover the aggregate diagonal",
                    )
                })?;
            if component.len() != ring_degree {
                return Err(invalid_succinct_setup_proof(
                    "round-one component diagonal length does not match the ring degree",
                ));
            }
            for (accumulated, value) in diagonal.iter_mut().zip(component.iter()) {
                *accumulated = add_mod_fast(*accumulated, *value, modulus);
            }
        }
        aggregate.push(diagonal);
    }

    Ok(aggregate)
}

// Development multi-trustee ceremony slice: every trustee has its own secret,
// errors, and linkage commitments; round-one components are built per trustee
// with the secret as the diagonal source, the public round-one aggregate is
// recomputed from those components, and every trustee's round-two source is
// its secret times that public aggregate, exactly the multi-party-realizable
// flow the package verifier rebinds.
#[cfg(test)]
pub(crate) fn generate_development_trustee_ceremony_slice(
    ceremony_seed_hex: &str,
    trustee_count: usize,
    level: usize,
    ring_degree: usize,
    linkage_commitment_count: usize,
) -> CanonicalResult<Vec<(TrusteeEvaluationKeyStatement, TrusteeEvaluationKeyWitness)>> {
    let mut round_one_instances = Vec::with_capacity(trustee_count);
    for trustee_index in 0..trustee_count {
        round_one_instances.push(generate_development_trustee_instance_with_linkage(
            &format!("{ceremony_seed_hex}-trustee-{trustee_index}"),
            &[(EvaluationKeyShareKind::RelinearizationRoundOne, level)],
            ring_degree,
            Some(linkage_commitment_count),
        )?);
    }
    let round_one_components = round_one_instances
        .iter()
        .map(|(statement, _)| &statement.keys[0].component_b_by_digit)
        .collect::<Vec<_>>();
    let aggregate_diagonal =
        round_one_aggregate_diagonal_from_components(&round_one_components, level, ring_degree)?;

    let mut instances = Vec::with_capacity(trustee_count);
    for (trustee_index, (mut statement, mut witness)) in round_one_instances.into_iter().enumerate()
    {
        // Round-two share: source = trustee secret (*) public aggregate.
        let key_switch_domain = "relinearization-round-two".to_string();
        let key_switch_seed_hex = format!("{ceremony_seed_hex}-trustee-{trustee_index}-round-two");
        let digit_count = level + 1;
        let error_coefficients_by_digit = sample_development_errors(
            &key_switch_domain,
            &key_switch_seed_hex,
            digit_count,
            ring_degree,
        );
        let mut diagonal_source_by_digit = Vec::with_capacity(digit_count);
        for (digit_index, modulus) in DATA_PRIMES[..=level].iter().enumerate() {
            let secret_residues = witness
                .secret_coefficients
                .iter()
                .map(|coefficient| signed_value_residue(*coefficient, *modulus))
                .collect::<Vec<_>>();
            diagonal_source_by_digit.push(negacyclic_ring_product(
                &secret_residues,
                &aggregate_diagonal[digit_index],
                *modulus,
            )?);
        }
        let component_b_by_digit = build_component_material(
            &key_switch_domain,
            &key_switch_seed_hex,
            level,
            ring_degree,
            &witness.secret_coefficients,
            &error_coefficients_by_digit,
            &diagonal_source_by_digit,
        )?;
        statement.keys.push(EvaluationKeyShareDescriptor {
            kind: EvaluationKeyShareKind::RelinearizationRoundTwo,
            level,
            key_switch_domain,
            key_switch_seed_hex,
            component_b_by_digit,
            round_one_aggregate_diagonal: aggregate_diagonal.clone(),
        });
        witness
            .error_coefficients_by_key
            .push(error_coefficients_by_digit);
        instances.push((statement, witness));
    }

    Ok(instances)
}

// Centered bound for a published masked consistency claim: the clear sum is
// bounded by max witness magnitude * ring degree * (2^bits - 1), and the
// smudging mask lies in [0, 2^CLAIM_MASK_DIGIT_COUNT).
// Family-aware clear bound: the private-VSS family masks only the carry and the
// ternary opening-randomness columns (its message columns carry no consistency
// claim; see consistency_vector_count), so its witness bound is the lifted carry
// bound (about 2^11); every other family uses 2 (centered-binomial magnitude).
// The mask is one-sided in [0, 2^CLAIM_MASK_DIGIT_COUNT), so the centered claim
// lies in [-clear_bound, mask_bound + clear_bound]. The disclosed smudging
// figure in accounting.rs recomputes from this same carry-driven family bound,
// so the relation bound and the disclosed leakage figure agree by construction.
pub(super) fn masked_claim_bounds(
    statement: &TrusteeEvaluationKeyStatement,
) -> CanonicalResult<(i128, i128)> {
    let ring_degree = statement.ring_degree;
    let coefficient_bound = (1_i128 << CONSISTENCY_COEFFICIENT_BITS) - 1;
    let witness_bound = match &statement.private_vss_share {
        Some(private_vss_share) => {
            // The message (Shamir coefficient) columns no longer carry a masked
            // consistency claim: they are pinned by the opening rows plus the
            // opening-randomness consistency (see consistency_vector_count), so
            // the published masked claims range only over the carry and the
            // ternary opening-randomness columns. The lifted carry bound
            // dominates the magnitude-one randomness, so it is the witness bound.
            let carry_bound = private_vss_share_lifted_carry_bound(
                private_vss_share.recipient_roster_position,
                private_vss_share.coefficient_commitments.len(),
            )?;
            carry_bound.max(1)
        }
        None => 2,
    };
    let clear_bound = witness_bound
        .checked_mul(coefficient_bound)
        .and_then(|bound| bound.checked_mul(ring_degree as i128))
        .ok_or_else(|| invalid_succinct_setup_proof("masked claim bound overflowed"))?;
    let mask_bound = 1_i128 << CLAIM_MASK_DIGIT_COUNT;

    Ok((-clear_bound, mask_bound + clear_bound))
}

pub(super) fn private_vss_share_lifted_carry_bound(
    recipient_roster_position: u64,
    coefficient_count: usize,
) -> CanonicalResult<i128> {
    let trustee_point = recipient_roster_position
        .checked_add(1)
        .ok_or_else(|| invalid_succinct_setup_proof("private VSS trustee point overflowed"))?;
    let mut power = 1_i128;
    let mut bound = 0_i128;
    for _ in 0..coefficient_count {
        bound = bound
            .checked_add(power)
            .ok_or_else(|| invalid_succinct_setup_proof("private VSS carry bound overflowed"))?;
        power = power
            .checked_mul(i128::from(trustee_point))
            .ok_or_else(|| invalid_succinct_setup_proof("private VSS carry bound overflowed"))?;
    }

    Ok(bound)
}
