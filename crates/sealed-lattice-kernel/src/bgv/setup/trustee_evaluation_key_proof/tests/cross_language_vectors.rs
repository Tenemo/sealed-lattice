use super::*;

#[test]
fn succinct_setup_statement_hash_vectors_cover_current_families() {
    let same_secret = super::generate_trustee_evaluation_key_proof_from_request(
        &same_secret_statement_hash_vector_request(),
    )
    .expect("same-secret statement vector");
    let public_key = super::generate_trustee_evaluation_key_proof_from_request(
        &public_key_share_statement_hash_vector_request(),
    )
    .expect("public-key statement vector");
    let private_vss =
        crate::bgv::setup::private_vss::generate_private_vss_share_proof_from_request(
            &private_vss_statement_hash_vector_request(),
        )
        .expect("private VSS statement vector");
    let trustee_evaluation_key = super::generate_trustee_evaluation_key_proof_from_request(
        &trustee_evaluation_key_statement_hash_vector_request(),
    )
    .expect("trustee evaluation-key statement vector");

    println!(
        "statement hash vectors: same-secret={}, public-key-share={}, private-vss-share={}, trustee-evaluation-key={}",
        same_secret["statementHash"]
            .as_str()
            .expect("same-secret hash"),
        public_key["statementHash"]
            .as_str()
            .expect("public-key hash"),
        private_vss["privateVssShareProof"]["statementHash"]
            .as_str()
            .expect("private VSS hash"),
        trustee_evaluation_key["statementHash"]
            .as_str()
            .expect("trustee evaluation-key hash"),
    );
    let expected_statement_hashes = expected_statement_hash_vectors();
    assert_eq!(same_secret["proofFamily"], "same-secret-linkage-anchor");
    assert_eq!(
        same_secret["statementHash"],
        expected_statement_hashes["sameSecret"]
    );
    assert_eq!(public_key["proofFamily"], "public-key-share");
    assert_eq!(
        public_key["statementHash"],
        expected_statement_hashes["publicKeyShare"]
    );
    assert_eq!(
        private_vss["privateVssShareProof"]["proofFamily"],
        "vss-opening-carry"
    );
    assert_eq!(
        private_vss["privateVssShareProof"]["statementHash"],
        expected_statement_hashes["privateVssShare"]
    );
    assert_eq!(
        trustee_evaluation_key["proofFamily"],
        "trustee-evaluation-key"
    );
    assert_eq!(
        trustee_evaluation_key["statementHash"],
        expected_statement_hashes["trusteeEvaluationKey"]
    );
}
