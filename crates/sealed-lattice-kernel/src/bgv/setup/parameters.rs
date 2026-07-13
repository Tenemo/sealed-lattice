use super::*;
use crate::hashing::derive_canonical_object_hash;

// Target-decryption parameter identity binds the BGV parameter hash and
// secret-share domain.
pub(super) fn target_decryption_parameters(bgv_parameters_hash: &str) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "TargetDecryptionParameters",
        "bgvParametersHash": bgv_parameters_hash,
        "secretShareDomain": SECRET_SHARE_DOMAIN,
    }))
}

pub(super) fn public_common_random_polynomial_root(
    input: &PassiveSetupInput,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "BgvPublicCommonRandomPolynomial",
        "ceremonyId": input.ceremony_id,
        "rosterHash": input.roster_hash,
        "setupSeedHash": input.setup_seed_hash,
        "level": DATA_PRIMES.len() - 1,
        "coefficientCount": POLYNOMIAL_DEGREE,
        "sampledResidues": sample_public_residues(
            &input.setup_seed_hash,
            "public-common-random-polynomial",
            DATA_PRIMES[0],
        )?,
    }))
}
