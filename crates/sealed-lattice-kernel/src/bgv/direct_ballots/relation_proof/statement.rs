use super::*;

pub(super) fn direct_ballot_relation_statement_hash(
    setup_package: &Value,
    public_key: &BgvPublicKey,
    ballot: &DirectEncryptedBallot,
) -> CanonicalResult<[u8; 64]> {
    direct_ballot_validity_statement_hash(setup_package, public_key, ballot)
}
