use super::*;
use crate::{
    CHUNK_LIMIT, HEADER_LENGTH, parameters::ballot_relation, statement::tests::synthetic_ballot,
    verifier,
};
use supported_profile::Profile;

fn verify(profile: Profile, role: &[u8], statement: &PublicStatement, proof: &[u8]) -> bool {
    let Ok(mut verifier) = verifier(profile, role, statement.digest(), &proof[..HEADER_LENGTH])
    else {
        return false;
    };
    for part in std::iter::once(&statement.header).chain(&statement.polynomials) {
        for chunk in part.chunks(CHUNK_LIMIT) {
            if verifier.push_statement(chunk).is_err() {
                return false;
            }
        }
    }
    if verifier.finish_statement().is_err() {
        return false;
    }
    for chunk in proof[HEADER_LENGTH..].chunks(CHUNK_LIMIT) {
        if verifier.push_proof(chunk).is_err() {
            return false;
        }
    }
    verifier.finish()
}

#[test]
fn ballot_proofs_verify_only_for_their_role_profile_and_true_ciphertext() {
    let profile = Profile::new(3, 2).unwrap();
    let role = b"ballot-proof-test";
    let (statement, columns) = synthetic_ballot(profile);
    let relation = ballot_relation(profile);
    let witness = Witness::from_columns(&relation, statement.digest(), columns).unwrap();
    let proof = prove(role, &statement, witness, false);
    let mut bytes = Vec::new();
    proof.write(&mut bytes);
    drop(proof);
    assert!(bytes.len() <= relation.maximum_proof_bytes());
    assert!(verify(profile, role, &statement, &bytes));
    assert!(!verify(profile, b"another-role", &statement, &bytes));
    // The same bytes are a statement of another option count only by
    // header, which that profile's verifier refuses.
    assert!(!verify(
        Profile::new(3, 3).unwrap(),
        role,
        &statement,
        &bytes
    ));
    // A proof for a ciphertext coefficient changed by one cannot meet
    // the affine relation. The coefficient is uniform, so its magnitude
    // stays nonzero and below half the modulus.
    let (mut statement, columns) = synthetic_ballot(profile);
    statement.polynomials[2][1] ^= 1;
    let witness = Witness::from_columns(&relation, statement.digest(), columns).unwrap();
    let proof = prove(role, &statement, witness, true);
    let mut bytes = Vec::new();
    proof.write(&mut bytes);
    assert!(!verify(profile, role, &statement, &bytes));
}

// Statistical zero knowledge allows one published proof for each mask
// draw. A proof replayed from the same draw, as an operation's retained
// seed replays it, repeats its bytes, and another draw gives another
// proof.
#[test]
fn a_replayed_mask_draw_repeats_its_proof() {
    let profile = Profile::new(3, 2).unwrap();
    let role = b"ballot-proof-test";
    let (statement, columns) = synthetic_ballot(profile);
    let relation = ballot_relation(profile);
    let prove = |seed| {
        word_proof::random::REPLAYED.with(|replayed| replayed.set(Some(seed)));
        let witness =
            Witness::from_columns(&relation, statement.digest(), columns.clone()).unwrap();
        let mut bytes = Vec::new();
        prove(role, &statement, witness, false).write(&mut bytes);
        bytes
    };
    let first = prove(1);
    assert!(verify(profile, role, &statement, &first));
    assert_eq!(prove(1), first);
    assert_ne!(prove(2), first);
}
