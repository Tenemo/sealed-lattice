use super::*;
use crate::{CHUNK_LIMIT, HEADER_LENGTH, statement::tests::synthetic_ballot, verifier};
use parallel_work::random::{self, Purpose};
use std::cell::Cell;
use supported_profile::{Profile, relation::ballot_relation};

thread_local! {
    // The state of the SplitMix64 stream that serves the proof's draws, as
    // an operation's retained seed serves them.
    static PROOF_STREAM: Cell<u64> = const { Cell::new(0) };
}

fn serve(purpose: Purpose, bytes: &mut [u8]) -> bool {
    if purpose != Purpose::Proof {
        return false;
    }
    PROOF_STREAM.with(|stream| {
        let mut state = stream.get();
        for chunk in bytes.chunks_mut(8) {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut word = state;
            word = (word ^ (word >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            word = (word ^ (word >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            word ^= word >> 31;
            chunk.copy_from_slice(&word.to_le_bytes()[..chunk.len()]);
        }
        stream.set(state);
    });
    true
}

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
        PROOF_STREAM.with(|stream| stream.set(seed));
        random::install(serve);
        let witness =
            Witness::from_columns(&relation, statement.digest(), columns.clone()).unwrap();
        let mut bytes = Vec::new();
        prove(role, &statement, witness, false).write(&mut bytes);
        random::release();
        bytes
    };
    let first = prove(1);
    assert!(verify(profile, role, &statement, &first));
    assert_eq!(prove(1), first);
    assert_ne!(prove(2), first);
}
