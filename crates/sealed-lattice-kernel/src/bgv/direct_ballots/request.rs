use super::*;

pub(super) fn direct_ballot_proof_randomness_seed(
    private_setup_seed: &str,
    ballot: &DirectEncryptedBallot,
) -> String {
    hash512_hex(
        "sealed-lattice/direct-encrypted-ballot/proof-randomness-seed",
        &[
            private_setup_seed.as_bytes(),
            ballot.ciphertext_root.as_bytes(),
            ballot.input.voter_identity.as_bytes(),
            ballot.input.action_context_hash.as_bytes(),
        ],
    )
}

pub(super) fn direct_ballot_slots(scores: &[u64]) -> Vec<u64> {
    let mut slots = vec![0_u64; POLYNOMIAL_DEGREE];
    slots[..OPTION_COUNT].copy_from_slice(scores);
    slots
}

pub(super) fn setup_package_hash(setup_package: &Value) -> CanonicalResult<String> {
    setup_package
        .get("setupPackageHash")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupPackage.setupPackageHash must be present",
            )
        })
}
