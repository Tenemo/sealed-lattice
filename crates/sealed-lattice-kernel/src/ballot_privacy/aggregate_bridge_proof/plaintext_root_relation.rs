use super::{plaintext_binding, *};
use num_bigint::BigInt;

pub(super) struct PlaintextRootRelationPublicInputs<'a> {
    pub(super) plaintext_root: &'a str,
    pub(super) plaintext_coefficient_binding_commitment: &'a Value,
    pub(super) plaintext_coefficient_binding_commitment_hash: &'a str,
}

pub(super) struct PlaintextRootRelationWitness<'a> {
    pub(super) plaintext_coefficients: &'a [u64],
    pub(super) plaintext_binding_opening_witness: &'a [BigInt],
}

pub(super) struct PlaintextRootRelationCheck {
    pub(super) canonical_plaintext_byte_length: usize,
}

pub(super) fn check_plaintext_root_relation(
    public_inputs: PlaintextRootRelationPublicInputs<'_>,
    witness: PlaintextRootRelationWitness<'_>,
) -> CanonicalResult<PlaintextRootRelationCheck> {
    if !is_protocol_hash(public_inputs.plaintext_root) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "encrypted aggregate bridge plaintext root relation requires a nonzero lowercase PlaintextRoot",
        ));
    }
    if !is_protocol_hash(public_inputs.plaintext_coefficient_binding_commitment_hash) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "encrypted aggregate bridge plaintext root relation requires a nonzero lowercase plaintext coefficient commitment hash",
        ));
    }
    let (computed_plaintext_root, canonical_plaintext_byte_length) =
        crate::bgv::commands::canonical_plaintext_root_from_coefficients(
            witness.plaintext_coefficients,
        )?;
    if computed_plaintext_root != public_inputs.plaintext_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted aggregate bridge plaintext root relation does not match the hidden canonical plaintext coefficients",
        ));
    }
    let computed_commitment_hash =
        plaintext_binding::plaintext_coefficient_binding_commitment_hash(
            public_inputs.plaintext_coefficient_binding_commitment,
        )?;
    if computed_commitment_hash != public_inputs.plaintext_coefficient_binding_commitment_hash {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted aggregate bridge plaintext root relation commitment hash does not match the public commitment object",
        ));
    }
    let public_commitment_chunks = plaintext_binding::read_plaintext_binding_commitment_chunks(
        public_inputs.plaintext_coefficient_binding_commitment,
    )?;
    let witness_commitment_chunks = plaintext_binding::plaintext_binding_commitment_chunks(
        witness.plaintext_coefficients,
        witness.plaintext_binding_opening_witness,
    )?;
    if witness_commitment_chunks != public_commitment_chunks {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted aggregate bridge plaintext root relation commitment does not open to the same hidden plaintext coefficients",
        ));
    }

    Ok(PlaintextRootRelationCheck {
        canonical_plaintext_byte_length,
    })
}
