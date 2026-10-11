use supported_profile::{
    Profile,
    relation::{ballot_relation, release_relation, setup_relation},
};

// The verifier's own context parameters equal the prover's for every
// relation of every profile.
#[test]
fn verifier_and_prover_bind_the_same_relation_parameters() {
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
            super::engine::context_parameters(&relation),
            word_proof::transcript::parameters(&relation)
        );
    }
}
