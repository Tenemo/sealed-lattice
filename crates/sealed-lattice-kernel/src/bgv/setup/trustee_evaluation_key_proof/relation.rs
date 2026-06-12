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

use crate::bgv::setup::commitment::{
    SETUP_COMMITMENT_MODULUS_LIMB_INDICES, SETUP_COMMITMENT_MODULE_RANK,
    SETUP_COMMITMENT_RANDOMNESS_WIDTH, SETUP_COMMITMENT_ROW_COUNT, SetupCommitmentValue,
    StructuralMatrixPolynomial, setup_commitment_matrix_coefficients_cached,
    structural_matrix_polynomial_kind,
};
#[cfg(test)]
use crate::bgv::setup::commitment::compute_setup_big_signed_lifted_commitment;

#[cfg(test)]
const WITNESS_SECRET_DOMAIN: &str =
    "sealed-lattice/setup/trustee-evaluation-key/witness-secret-v1";
const STATEMENT_HASH_DOMAIN: &str =
    "sealed-lattice/setup/trustee-evaluation-key/statement-v2";

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
        }

        bytes
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
        return Err(invalid_succinct_setup_proof(
            "Galois element must be odd",
        ));
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
        return Err(invalid_succinct_setup_proof(
            "Galois element must be odd",
        ));
    }
    let mut transposed = Vec::with_capacity(degree);
    for index in 0..degree {
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

// Ceremony context the proof is bound to: every field enters the statement
// hash, so a proof transplanted to another ceremony, roster position, epoch,
// schedule, or same-secret anchor fails the transcript rebinding.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct TrusteeEvaluationKeyContext {
    pub(crate) ceremony_id: String,
    pub(crate) manifest_hash: String,
    pub(crate) roster_hash: String,
    pub(crate) trustee_identity: String,
    pub(crate) trustee_roster_position: u64,
    pub(crate) setup_epoch: String,
    pub(crate) required_galois_set_hash: String,
    pub(crate) evaluator_key_schedule_root: String,
    pub(crate) key_switch_decomposition_hash: String,
    pub(crate) same_secret_statement_root: String,
    pub(crate) same_secret_proof_root: String,
}

// A trustee's batched statement: every listed key share is proven against the
// same committed secret, with one trace commitment and one batched FRI
// instance per active limb field covering all listed keys.
pub(crate) struct TrusteeEvaluationKeyStatement {
    pub(crate) context: TrusteeEvaluationKeyContext,
    pub(crate) ring_degree: usize,
    pub(crate) keys: Vec<EvaluationKeyShareDescriptor>,
    pub(crate) same_secret_linkage: Option<SameSecretLinkageStatement>,
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
}

impl EvaluationKeyShareDescriptor {
    pub(super) fn digit_count(&self) -> usize {
        self.level + 1
    }

    fn validate_shape(&self, ring_degree: usize) -> CanonicalResult<()> {
        if self.level + 1 > DATA_PRIMES.len() {
            return Err(invalid_succinct_setup_proof(
                "key level is outside the selected data basis",
            ));
        }
        if self.component_b_by_digit.len() != self.digit_count()
            || self.component_b_by_digit.iter().any(|by_limb| {
                by_limb.len() != self.digit_count()
                    || by_limb
                        .iter()
                        .any(|component| component.len() != ring_degree)
            })
        {
            return Err(invalid_succinct_setup_proof(
                "key component material shape does not match its level and ring degree",
            ));
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
        }

        Ok(())
    }

    // The diagonal source vector D tested against the secret in limb l, chosen
    // so that <U, source> = <D, s>: U for round one, Neg(A_l)^T U for round
    // two, and M_phi^T U for a Galois rotation.
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
        }
    }
}

impl TrusteeEvaluationKeyStatement {
    // The number of active limb fields: one past the highest key level.
    pub(super) fn limb_count(&self) -> usize {
        self.keys
            .iter()
            .map(|key| key.level + 1)
            .max()
            .unwrap_or(0)
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
            self.context.ceremony_id.as_str(),
            self.context.manifest_hash.as_str(),
            self.context.roster_hash.as_str(),
            self.context.trustee_identity.as_str(),
            self.context.required_galois_set_hash.as_str(),
            self.context.evaluator_key_schedule_root.as_str(),
            self.context.key_switch_decomposition_hash.as_str(),
            self.context.same_secret_statement_root.as_str(),
            self.context.same_secret_proof_root.as_str(),
        ] {
            preimage.extend_from_slice(&(context_field.len() as u64).to_le_bytes());
            preimage.extend_from_slice(context_field.as_bytes());
        }
        preimage.extend_from_slice(&self.context.trustee_roster_position.to_le_bytes());
        preimage.extend_from_slice(self.context.setup_epoch.as_bytes());
        preimage.push(0);
        preimage.extend_from_slice(&(self.ring_degree as u64).to_le_bytes());
        preimage.extend_from_slice(&(self.keys.len() as u64).to_le_bytes());
        for key in &self.keys {
            preimage.extend_from_slice(&key.kind.tag_bytes());
            preimage.extend_from_slice(&(key.level as u64).to_le_bytes());
            preimage.extend_from_slice(&(key.key_switch_domain.len() as u64).to_le_bytes());
            preimage.extend_from_slice(key.key_switch_domain.as_bytes());
            preimage.extend_from_slice(&(key.key_switch_seed_hex.len() as u64).to_le_bytes());
            preimage.extend_from_slice(key.key_switch_seed_hex.as_bytes());
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
            preimage.extend_from_slice(linkage.public_matrix_seed_hash.as_bytes());
            preimage.extend_from_slice(&(linkage.commitments.len() as u64).to_le_bytes());
            for commitment in &linkage.commitments {
                preimage.extend_from_slice(
                    &(commitment.source_rns_limb_index as u64).to_le_bytes(),
                );
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

        hash512(STATEMENT_HASH_DOMAIN, &[&preimage])
    }

    pub(in crate::bgv::setup) fn validate_shape(&self) -> CanonicalResult<()> {
        if self.keys.is_empty() {
            return Err(invalid_succinct_setup_proof(
                "trustee statement requires at least one key share",
            ));
        }
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
            if self.limb_count() < SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() {
                return Err(invalid_succinct_setup_proof(
                    "same-secret linkage requires every commitment field to be an active limb",
                ));
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
                        || limb
                            .rows
                            .iter()
                            .any(|row| row.len() != self.ring_degree)
                    {
                        return Err(invalid_succinct_setup_proof(
                            "same-secret linkage commitment limb shape does not match the profile",
                        ));
                    }
                }
            }
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
                let source =
                    negacyclic_ring_product(&secret_residues, &aggregate, *modulus)?;
                round_one_aggregate_diagonal.push(aggregate);
                source
            }
            EvaluationKeyShareKind::GaloisRotation { galois_element } => {
                galois_automorphism_apply(&secret_residues, galois_element, *modulus)?
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
fn development_context(key_switch_seed_hex: &str) -> TrusteeEvaluationKeyContext {
    let derived = |label: &str| -> String {
        hash512(
            "sealed-lattice/setup/trustee-evaluation-key/development-context-v1",
            &[key_switch_seed_hex.as_bytes(), label.as_bytes()],
        )
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
    };

    TrusteeEvaluationKeyContext {
        ceremony_id: format!("development-ceremony-{key_switch_seed_hex}"),
        manifest_hash: derived("manifest"),
        roster_hash: derived("roster"),
        trustee_identity: format!("development-trustee-{key_switch_seed_hex}"),
        trustee_roster_position: 1,
        setup_epoch: "development-epoch-1".to_string(),
        required_galois_set_hash: derived("required-galois-set"),
        evaluator_key_schedule_root: derived("evaluator-key-schedule"),
        key_switch_decomposition_hash: derived("key-switch-decomposition"),
        same_secret_statement_root: derived("same-secret-statement"),
        same_secret_proof_root: derived("same-secret-proof"),
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
            digest.iter().map(|byte| format!("{byte:02x}")).collect::<String>()
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
            context: development_context(key_switch_seed_hex),
            ring_degree,
            keys,
            same_secret_linkage,
        },
        TrusteeEvaluationKeyWitness {
            secret_coefficients,
            error_coefficients_by_key,
            negative_indicator_coefficients,
            opening_randomness_by_limb,
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

// Per-limb physical column layout. Every logical length-N vector occupies
// TRACE_SPLIT physical columns of length N / TRACE_SPLIT, in half order. The
// layout is: secret halves, then per active key per digit the error halves,
// then the matching error-square halves, then the claim-mask digit halves.
pub(super) struct LimbColumnLayout {
    pub(super) ring_degree: usize,
    pub(super) trace_size: usize,
    // (key index, digit count) per active key, in key order.
    pub(super) active_keys: Vec<(usize, usize)>,
    pub(super) total_error_columns: usize,
    // Linkage logical columns active in this limb: the binary negative
    // indicator plus the per-commitment opening-randomness columns, or zero
    // outside the commitment fields.
    pub(super) linkage_randomness_columns: usize,
    pub(super) mask_column_count: usize,
}

impl LimbColumnLayout {
    pub(super) fn new(
        statement: &TrusteeEvaluationKeyStatement,
        limb_index: usize,
    ) -> CanonicalResult<Self> {
        let active_keys = statement
            .active_key_indices(limb_index)
            .into_iter()
            .map(|key_index| (key_index, statement.keys[key_index].digit_count()))
            .collect::<Vec<_>>();
        if active_keys.is_empty() {
            return Err(invalid_succinct_setup_proof(
                "limb layout requires at least one active key",
            ));
        }
        let total_error_columns = active_keys.iter().map(|(_, digits)| *digits).sum::<usize>();
        let linkage_randomness_columns = statement.linkage_randomness_count(limb_index);
        let ring_degree = statement.ring_degree;
        let consistency_vector_count = 1
            + total_error_columns
            + if linkage_randomness_columns > 0 {
                1 + linkage_randomness_columns
            } else {
                0
            };
        let claim_count = consistency_vector_count * CONSISTENCY_REPETITIONS;
        let mask_slot_count = claim_count * CLAIM_MASK_DIGIT_COUNT;
        let mask_column_count = mask_slot_count.div_ceil(ring_degree);

        Ok(Self {
            ring_degree,
            trace_size: ring_degree / TRACE_SPLIT,
            active_keys,
            total_error_columns,
            linkage_randomness_columns,
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

    // Logical witness vectors carrying cross-limb consistency claims: the
    // shared secret first, then every active key's error vectors in order,
    // then the linkage negative indicator and opening-randomness vectors.
    pub(super) fn consistency_vector_count(&self) -> usize {
        1 + self.total_error_columns + self.linkage_logical_columns()
    }

    pub(super) fn claim_count(&self) -> usize {
        self.consistency_vector_count() * CONSISTENCY_REPETITIONS
    }

    pub(super) fn physical_secret(&self, half: usize) -> usize {
        half
    }

    // error_position counts error vectors across active keys in layout order.
    pub(super) fn physical_error(&self, error_position: usize, half: usize) -> usize {
        TRACE_SPLIT * (1 + error_position) + half
    }

    pub(super) fn physical_error_square(&self, error_position: usize, half: usize) -> usize {
        TRACE_SPLIT * (1 + self.total_error_columns + error_position) + half
    }

    pub(super) fn physical_negative_indicator(&self, half: usize) -> usize {
        debug_assert!(self.linkage_active());
        TRACE_SPLIT * (1 + 2 * self.total_error_columns) + half
    }

    pub(super) fn physical_linkage_randomness(
        &self,
        randomness_position: usize,
        half: usize,
    ) -> usize {
        debug_assert!(self.linkage_active());
        TRACE_SPLIT * (1 + 2 * self.total_error_columns + 1 + randomness_position) + half
    }

    pub(super) fn physical_mask(&self, mask_column: usize, half: usize) -> usize {
        TRACE_SPLIT
            * (1 + 2 * self.total_error_columns + self.linkage_logical_columns() + mask_column)
            + half
    }

    pub(super) fn phase_one_physical_count(&self) -> usize {
        TRACE_SPLIT
            * (1
                + 2 * self.total_error_columns
                + self.linkage_logical_columns()
                + self.mask_column_count)
    }

    // One row-check constraint per physical column.
    pub(super) fn row_check_constraint_count(&self) -> usize {
        self.phase_one_physical_count()
    }

    // Mask slot of one claim digit: claims are laid out consecutively with
    // CLAIM_MASK_DIGIT_COUNT binary digits each.
    pub(super) fn mask_slot(&self, claim_index: usize, digit_index: usize) -> (usize, usize, usize) {
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

// The batched row-check value sum_k beta_k * C_k at one point, given the
// phase-one physical column values at that point in layout order. One
// constraint per physical column:
//   secret halves:        S^3 - S            (ternary support)
//   error halves:         E (E2 - 1)(E2 - 4) (centered binomial support)
//   error-square halves:  E2 - E^2           (helper well-formedness)
//   mask halves:          M^2 - M            (binary digits)
pub(super) fn batched_row_check_value(
    column_values: &[u64],
    beta: &[u64],
    layout: &LimbColumnLayout,
    modulus: u64,
) -> u64 {
    debug_assert_eq!(column_values.len(), layout.phase_one_physical_count());
    debug_assert_eq!(beta.len(), layout.row_check_constraint_count());
    let four = 4 % modulus;
    let one = 1 % modulus;
    let mut accumulated = 0_u64;
    let mut constraint_index = 0_usize;
    let mut absorb = |value: u64, accumulated: &mut u64| {
        *accumulated = add_mod_fast(
            *accumulated,
            mul_mod_fast(beta[constraint_index], value, modulus),
            modulus,
        );
        constraint_index += 1;
    };
    for half in 0..TRACE_SPLIT {
        let secret = column_values[layout.physical_secret(half)];
        let cube = mul_mod_fast(mul_mod_fast(secret, secret, modulus), secret, modulus);
        absorb(sub_mod_fast(cube, secret, modulus), &mut accumulated);
    }
    for error_position in 0..layout.total_error_columns {
        for half in 0..TRACE_SPLIT {
            let error = column_values[layout.physical_error(error_position, half)];
            let error_square = column_values[layout.physical_error_square(error_position, half)];
            let range_polynomial = mul_mod_fast(
                sub_mod_fast(error_square, one, modulus),
                sub_mod_fast(error_square, four, modulus),
                modulus,
            );
            absorb(
                mul_mod_fast(error, range_polynomial, modulus),
                &mut accumulated,
            );
        }
    }
    for error_position in 0..layout.total_error_columns {
        for half in 0..TRACE_SPLIT {
            let error = column_values[layout.physical_error(error_position, half)];
            let error_square = column_values[layout.physical_error_square(error_position, half)];
            absorb(
                sub_mod_fast(error_square, mul_mod_fast(error, error, modulus), modulus),
                &mut accumulated,
            );
        }
    }
    if layout.linkage_active() {
        for half in 0..TRACE_SPLIT {
            let indicator = column_values[layout.physical_negative_indicator(half)];
            absorb(
                sub_mod_fast(
                    mul_mod_fast(indicator, indicator, modulus),
                    indicator,
                    modulus,
                ),
                &mut accumulated,
            );
        }
        for randomness_position in 0..layout.linkage_randomness_columns {
            for half in 0..TRACE_SPLIT {
                let randomness =
                    column_values[layout.physical_linkage_randomness(randomness_position, half)];
                let cube = mul_mod_fast(
                    mul_mod_fast(randomness, randomness, modulus),
                    randomness,
                    modulus,
                );
                absorb(sub_mod_fast(cube, randomness, modulus), &mut accumulated);
            }
        }
    }
    for mask_column in 0..layout.mask_column_count {
        for half in 0..TRACE_SPLIT {
            let mask = column_values[layout.physical_mask(mask_column, half)];
            absorb(
                sub_mod_fast(mul_mod_fast(mask, mask, modulus), mask, modulus),
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
pub(super) struct SumcheckPublicEvaluations {
    // [repetition][half]
    pub(super) secret_factor: Vec<[u64; 2]>,
    pub(super) u_power: Vec<[u64; 2]>,
    // [consistency repetition][half]
    pub(super) consistency: Vec<[u64; 2]>,
    // [mask column][half]
    pub(super) mask_selector: Vec<[u64; 2]>,
    // Linkage pair vectors in fixed order: the secret-link vector, the
    // negative-indicator vector, then one combined vector per opening
    // randomness column. Empty outside the commitment fields.
    pub(super) linkage: Vec<[u64; 2]>,
}

// Scalar weights for the error contribution of the lincheck: weight of error
// column position p at repetition r is alpha_{key(p), r} * gamma_{key(p)}^j(p).
pub(super) struct SumcheckErrorWeights {
    // [repetition][error position]
    pub(super) weights: Vec<Vec<u64>>,
}

// The batched sumcheck integrand at one point:
//   sum_r [ SecretFactor_r * S - p * U_r * (sum_p weight_{r,p} * E_p) ]
// + sum_{c,t} alpha'_{c,t} * P_t * W_c
// + sum_i CombSel_i * Mask_i
// with every product summed over both halves.
#[allow(clippy::too_many_arguments)]
pub(super) fn batched_sumcheck_value(
    column_values: &[u64],
    publics: &SumcheckPublicEvaluations,
    error_weights: &SumcheckErrorWeights,
    consistency_alpha: &[u64],
    layout: &LimbColumnLayout,
    modulus: u64,
) -> u64 {
    let plaintext_modulus = (PLAINTEXT_MODULUS_I64 as u64) % modulus;
    let mut accumulated = 0_u64;
    for (repetition, (secret_factor, u_power)) in publics
        .secret_factor
        .iter()
        .zip(publics.u_power.iter())
        .enumerate()
    {
        for half in 0..TRACE_SPLIT {
            let secret = column_values[layout.physical_secret(half)];
            accumulated = add_mod_fast(
                accumulated,
                mul_mod_fast(secret_factor[half], secret, modulus),
                modulus,
            );
            let mut weighted_error = 0_u64;
            for error_position in 0..layout.total_error_columns {
                weighted_error = add_mod_fast(
                    weighted_error,
                    mul_mod_fast(
                        error_weights.weights[repetition][error_position],
                        column_values[layout.physical_error(error_position, half)],
                        modulus,
                    ),
                    modulus,
                );
            }
            accumulated = sub_mod_fast(
                accumulated,
                mul_mod_fast(
                    plaintext_modulus,
                    mul_mod_fast(u_power[half], weighted_error, modulus),
                    modulus,
                ),
                modulus,
            );
        }
    }
    let mut claim_alpha_index = 0_usize;
    for consistency_vector in 0..layout.consistency_vector_count() {
        for repetition in 0..CONSISTENCY_REPETITIONS {
            let alpha_value = consistency_alpha[claim_alpha_index];
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
                accumulated = add_mod_fast(
                    accumulated,
                    mul_mod_fast(
                        alpha_value,
                        mul_mod_fast(publics.consistency[repetition][half], witness_value, modulus),
                        modulus,
                    ),
                    modulus,
                );
            }
        }
    }
    for (mask_column, mask_selector) in publics.mask_selector.iter().enumerate() {
        for half in 0..TRACE_SPLIT {
            accumulated = add_mod_fast(
                accumulated,
                mul_mod_fast(
                    mask_selector[half],
                    column_values[layout.physical_mask(mask_column, half)],
                    modulus,
                ),
                modulus,
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
                accumulated = add_mod_fast(
                    accumulated,
                    mul_mod_fast(linkage_values[half], column_value, modulus),
                    modulus,
                );
            }
        }
    }

    accumulated
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
    modulus: u64,
    u_power_vectors: &[Vec<u64>],
    linkage_alpha: &[u64],
) -> CanonicalResult<(u64, Vec<Vec<u64>>)> {
    let ring_degree = linkage.commitments[0].ring_degree;
    let commitment_count = linkage.commitments.len();
    debug_assert_eq!(
        linkage_alpha.len(),
        commitment_count * SETUP_COMMITMENT_ROW_COUNT * LINCHECK_REPETITIONS
    );
    let mut linkage_claim = 0_u64;
    let mut secret_link = vec![0_u64; ring_degree];
    let mut negative_indicator = vec![0_u64; ring_degree];
    let mut randomness_vectors =
        vec![vec![0_u64; ring_degree]; commitment_count * SETUP_COMMITMENT_RANDOMNESS_WIDTH];
    let add_scaled = |target: &mut [u64], source: &[u64], scale: u64, modulus: u64| {
        for (target_value, source_value) in target.iter_mut().zip(source.iter()) {
            *target_value = add_mod_fast(
                *target_value,
                mul_mod_fast(scale, *source_value, modulus),
                modulus,
            );
        }
    };
    for (commitment_index, commitment) in linkage.commitments.iter().enumerate() {
        let source_modulus_residue = commitment.source_message_modulus % modulus;
        let limb = &commitment.limbs[commitment_field];
        for row_index in 0..SETUP_COMMITMENT_ROW_COUNT {
            // Repetition-combined challenge vector for this relation.
            let mut combined_u = vec![0_u64; ring_degree];
            for (repetition, u_powers) in u_power_vectors.iter().enumerate() {
                let alpha_value = linkage_alpha[(commitment_index * SETUP_COMMITMENT_ROW_COUNT
                    + row_index)
                    * LINCHECK_REPETITIONS
                    + repetition];
                add_scaled(&mut combined_u, u_powers, alpha_value, modulus);
            }
            // Public side: alpha-weighted lincheck sums of the commitment row.
            let mut row_sum = 0_u64;
            for (u_value, row_value) in combined_u.iter().zip(limb.rows[row_index].iter()) {
                row_sum = add_mod_fast(
                    row_sum,
                    mul_mod_fast(*u_value, *row_value, modulus),
                    modulus,
                );
            }
            linkage_claim = add_mod_fast(linkage_claim, row_sum, modulus);
            // Message row: the lifted secret message s + neg * q_l.
            if row_index == SETUP_COMMITMENT_MODULE_RANK {
                add_scaled(&mut secret_link, &combined_u, 1, modulus);
                add_scaled(
                    &mut negative_indicator,
                    &combined_u,
                    source_modulus_residue,
                    modulus,
                );
            }
            for randomness_column in 0..SETUP_COMMITMENT_RANDOMNESS_WIDTH {
                let target =
                    &mut randomness_vectors
                        [commitment_index * SETUP_COMMITMENT_RANDOMNESS_WIDTH + randomness_column];
                match structural_matrix_polynomial_kind(row_index, randomness_column) {
                    Some(StructuralMatrixPolynomial::One) => {
                        add_scaled(target, &combined_u, 1, modulus);
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
                        let transposed = negacyclic_transpose_product(
                            &matrix_polynomial,
                            &combined_u,
                            modulus,
                        )?;
                        add_scaled(target, &transposed, 1, modulus);
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
    for (trustee_index, (mut statement, mut witness)) in
        round_one_instances.into_iter().enumerate()
    {
        // Round-two share: source = trustee secret (*) public aggregate.
        let key_switch_domain = "relinearization-round-two".to_string();
        let key_switch_seed_hex =
            format!("{ceremony_seed_hex}-trustee-{trustee_index}-round-two");
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
pub(super) fn masked_claim_bounds(ring_degree: usize) -> (i128, i128) {
    let coefficient_bound = (1_i128 << CONSISTENCY_COEFFICIENT_BITS) - 1;
    let clear_bound = 2 * coefficient_bound * ring_degree as i128;
    let mask_bound = 1_i128 << CLAIM_MASK_DIGIT_COUNT;

    (-clear_bound, mask_bound + clear_bound)
}
