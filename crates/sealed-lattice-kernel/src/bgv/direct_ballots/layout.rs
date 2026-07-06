//! Direct encrypted ballot layout and batch-encoder identity freeze.
//!
//! SL3 Phase A: the accepted ballot-validity relation binds the encoded
//! plaintext to a fixed public batch encoder and a reserved-slot rule. This
//! module recomputes, from the kernel's own constants, the batch-encoder
//! identity (a hash over the twenty encoder basis vectors - the
//! plaintext-coefficient images of the per-option unit score slots under the
//! fixed encoder) and the encrypted-ballot layout identity, and enforces the
//! reserved-slot rule. The ballot statement binds these identities so a ballot
//! proven under a different encoder or layout, or with a nonzero reserved slot,
//! is refused. The functions are frozen here ahead of the statement/package
//! schema (SL3 Phase A item 4) that consumes them.

use serde_json::json;

use super::{MAXIMUM_SCORE, MINIMUM_SCORE, OPTION_COUNT, SCORE_BUCKET_COUNT};
use crate::bgv::evaluator::engine::encode_slots_to_coefficients;
use crate::bgv::parameters::{PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE};
use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};
use crate::hashing::{canonical_json, hash512_hex};

const BATCH_ENCODER_IDENTITY_DOMAIN: &str =
    "sealed-lattice/direct-ballot/batch-encoder-identity-v1";
const ENCRYPTED_BALLOT_LAYOUT_DOMAIN: &str =
    "sealed-lattice/direct-ballot/encrypted-ballot-layout-v1";

fn invalid_ballot_layout(message: &str) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

// The batch encoder is the fixed public linear map from score slots to
// plaintext coefficients (inverse negacyclic NTT over the plaintext field). Its
// twenty basis vectors are the images of the per-option unit score slots:
// `basis[a] = Encode_p(e_a)`, where `e_a` places the value one at option `a`'s
// slot and zero elsewhere. Because the map is linear, a ballot's encoded
// plaintext is `sum_a score[a] * basis[a]`, so binding these vectors binds the
// encoder exactly.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn batch_encoder_basis_vectors() -> CanonicalResult<Vec<Vec<u64>>> {
    (0..OPTION_COUNT)
        .map(|option_index| {
            let mut unit_slots = vec![0_u64; OPTION_COUNT];
            unit_slots[option_index] = 1;
            encode_slots_to_coefficients(&unit_slots)
        })
        .collect()
}

// The batch-encoder identity: a canonical hash over the twenty basis vectors
// together with the encoder's fixed shape. The statement binds this hash so a
// ballot encoded under any other linear map is refused.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn batch_encoder_hash() -> CanonicalResult<String> {
    let basis_vectors = batch_encoder_basis_vectors()?;
    let mut header = Vec::with_capacity(24);
    header.extend_from_slice(&(OPTION_COUNT as u64).to_le_bytes());
    header.extend_from_slice(&(POLYNOMIAL_DEGREE as u64).to_le_bytes());
    header.extend_from_slice(&PLAINTEXT_MODULUS.to_le_bytes());
    let mut vector_bytes: Vec<Vec<u8>> = Vec::with_capacity(basis_vectors.len());
    for vector in &basis_vectors {
        let mut bytes = Vec::with_capacity(vector.len() * 8);
        for coefficient in vector {
            bytes.extend_from_slice(&coefficient.to_le_bytes());
        }
        vector_bytes.push(bytes);
    }
    let mut parts: Vec<&[u8]> = Vec::with_capacity(vector_bytes.len() + 1);
    parts.push(header.as_slice());
    parts.extend(vector_bytes.iter().map(Vec::as_slice));
    Ok(hash512_hex(BATCH_ENCODER_IDENTITY_DOMAIN, &parts))
}

// The encrypted-ballot layout identity: the score domain, the reserved-slot
// rule, and the batch-encoder identity bound together. A ciphertext rebound to a
// different layout carries a different hash and is refused.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn encrypted_ballot_layout_hash() -> CanonicalResult<String> {
    let batch_encoder_hash = batch_encoder_hash()?;
    let layout = json!({
        "optionCount": OPTION_COUNT,
        "scoreBucketCount": SCORE_BUCKET_COUNT,
        "minimumScore": MINIMUM_SCORE,
        "maximumScore": MAXIMUM_SCORE,
        "polynomialDegree": POLYNOMIAL_DEGREE,
        "plaintextModulus": PLAINTEXT_MODULUS,
        "reservedSlotRule": "plaintext coefficients at slot index >= optionCount are zero",
        "batchEncoderHash": batch_encoder_hash,
    });
    Ok(hash512_hex(
        ENCRYPTED_BALLOT_LAYOUT_DOMAIN,
        &[canonical_json(&layout)?.as_bytes()],
    ))
}

// The reserved-slot rule: every plaintext slot at or beyond the option count is
// zero. The statement binds this so a ballot that hides a value in a reserved
// slot is refused.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn validate_reserved_slots(slots: &[u64]) -> CanonicalResult<()> {
    if slots.len() != POLYNOMIAL_DEGREE {
        return Err(invalid_ballot_layout(
            "direct encrypted ballot slot vector must match the polynomial degree",
        ));
    }
    if slots[OPTION_COUNT..].iter().any(|slot| *slot != 0) {
        return Err(invalid_ballot_layout(
            "direct encrypted ballot reserved slots must be zero",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::modular_arithmetic::add_mod;

    fn multiply_modulo_plaintext(left: u64, right: u64) -> u64 {
        ((u128::from(left) * u128::from(right)) % u128::from(PLAINTEXT_MODULUS)) as u64
    }

    #[test]
    fn basis_vectors_are_the_batch_encoder_columns() {
        // The freeze is only meaningful if the committed basis vectors really
        // are the encoder: a linear reconstruction from them must equal the
        // fixed encoder on an arbitrary score vector.
        let basis = batch_encoder_basis_vectors().expect("basis vectors");
        assert_eq!(basis.len(), OPTION_COUNT);
        assert!(
            basis.iter().all(|vector| vector.len() == POLYNOMIAL_DEGREE),
            "each basis vector spans the polynomial degree"
        );

        let scores: Vec<u64> = (0..OPTION_COUNT)
            .map(|option_index| ((option_index as u64) % MAXIMUM_SCORE) + MINIMUM_SCORE)
            .collect();
        let direct = encode_slots_to_coefficients(&scores).expect("direct encode");

        let mut reconstructed = vec![0_u64; POLYNOMIAL_DEGREE];
        for (option_index, score) in scores.iter().enumerate() {
            for (coefficient, basis_value) in
                reconstructed.iter_mut().zip(basis[option_index].iter())
            {
                *coefficient = add_mod(
                    *coefficient,
                    multiply_modulo_plaintext(*score, *basis_value),
                    PLAINTEXT_MODULUS,
                )
                .expect("plaintext-field modular add");
            }
        }
        assert_eq!(
            direct, reconstructed,
            "the basis vectors must reconstruct the fixed batch encoder"
        );
    }

    #[test]
    fn batch_encoder_hash_is_deterministic_and_binds_the_basis() {
        let first = batch_encoder_hash().expect("encoder hash");
        let second = batch_encoder_hash().expect("encoder hash");
        assert_eq!(first, second, "the encoder identity is deterministic");

        // A ballot encoded under any other linear map has different basis
        // vectors, so its identity differs: perturbing one basis coefficient
        // must change the hash.
        let mut basis = batch_encoder_basis_vectors().expect("basis vectors");
        basis[0][0] = add_mod(basis[0][0], 1, PLAINTEXT_MODULUS)
            .expect("plaintext-field modular add");
        let mut header = Vec::with_capacity(24);
        header.extend_from_slice(&(OPTION_COUNT as u64).to_le_bytes());
        header.extend_from_slice(&(POLYNOMIAL_DEGREE as u64).to_le_bytes());
        header.extend_from_slice(&PLAINTEXT_MODULUS.to_le_bytes());
        let mut vector_bytes: Vec<Vec<u8>> = Vec::with_capacity(basis.len());
        for vector in &basis {
            let mut bytes = Vec::with_capacity(vector.len() * 8);
            for coefficient in vector {
                bytes.extend_from_slice(&coefficient.to_le_bytes());
            }
            vector_bytes.push(bytes);
        }
        let mut parts: Vec<&[u8]> = Vec::with_capacity(vector_bytes.len() + 1);
        parts.push(header.as_slice());
        parts.extend(vector_bytes.iter().map(Vec::as_slice));
        let perturbed = hash512_hex(BATCH_ENCODER_IDENTITY_DOMAIN, &parts);
        assert_ne!(
            first, perturbed,
            "a different encoder matrix must yield a different identity"
        );
    }

    #[test]
    fn layout_hash_is_deterministic_and_binds_the_encoder() {
        let first = encrypted_ballot_layout_hash().expect("layout hash");
        let second = encrypted_ballot_layout_hash().expect("layout hash");
        assert_eq!(first, second, "the layout identity is deterministic");
        // The layout hash folds in the encoder identity, so it is distinct from
        // the bare encoder hash.
        assert_ne!(
            first,
            batch_encoder_hash().expect("encoder hash"),
            "the layout hash must be domain-separated from the encoder hash"
        );
    }

    #[test]
    fn reserved_slot_rule_accepts_zero_and_rejects_nonzero_and_wrong_length() {
        let mut slots = vec![0_u64; POLYNOMIAL_DEGREE];
        for (option_index, slot) in slots.iter_mut().take(OPTION_COUNT).enumerate() {
            *slot = ((option_index as u64) % MAXIMUM_SCORE) + MINIMUM_SCORE;
        }
        validate_reserved_slots(&slots).expect("zero reserved slots accepted");

        let mut hidden_value = slots.clone();
        hidden_value[OPTION_COUNT] = 1;
        assert!(
            validate_reserved_slots(&hidden_value).is_err(),
            "a nonzero reserved slot must be refused"
        );

        assert!(
            validate_reserved_slots(&slots[..POLYNOMIAL_DEGREE - 1]).is_err(),
            "a slot vector of the wrong length must be refused"
        );
    }
}
