use supported_profile::{
    Profile,
    relation::{ballot_relation, release_relation, setup_relation},
};

// The verifier's own statement context equals the prover's for every
// relation of every profile.
#[test]
fn verifier_and_prover_bind_the_same_statement_context() {
    let mut relations = Vec::new();
    for profile in Profile::all() {
        relations.extend([
            setup_relation(profile),
            ballot_relation(profile),
            release_relation(profile),
        ]);
    }
    for relation in relations {
        assert_eq!(
            super::engine::context(&relation, b"context-test", &[7; 64]),
            word_proof::transcript::context(&relation, b"context-test", &[7; 64])
        );
    }
}
